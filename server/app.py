import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO
from functools import wraps
from datetime import datetime
import sqlite3
import os
import time as _time

from ai_model import SecurityAIModel

# Config ──────
SECRET_KEY    = "change-this-secret-key-in-production"
ADMIN_USER    = "admin"
ADMIN_PASS    = "admin123"
ESP32_API_KEY = "esp32-secret-key-2026"
DB_PATH       = os.path.join(os.path.dirname(__file__), "server_room.db")
WORK_HOURS    = (8, 18)   # From 08:00am – 18:00pm

DAYS = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]

# Known people (UID → name) 
UID_PERSONS = {
    "1BDD3A06":       "Admin Card",
    "5DE95006":       "Staff Tag",
    "FF0F9806120100": "Visitor Sticker"
}

app            = Flask(__name__)
app.secret_key = SECRET_KEY
socketio       = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# NFC scan tracker (server-side dedup) ─────
_last_nfc = {"uid": "", "ts": 0.0}   # last logged NFC scan

# AI model ─────
ai = SecurityAIModel()
if not ai.load():
    ai.train()

# Database ────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS readings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT,
                day          TEXT,
                temp_s       REAL, temp_r REAL, hum REAL, co2 INTEGER,
                door         INTEGER, motion INTEGER,
                nfc_uid      TEXT, nfc_valid INTEGER, person_name TEXT,
                alert        INTEGER, alert_type TEXT,
                after_hours  INTEGER,
                risk_score   INTEGER, risk_status TEXT, risk_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS access_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT,
                day          TEXT,
                nfc_uid      TEXT,
                person_name  TEXT,
                nfc_valid    INTEGER,
                door_open    INTEGER,
                after_hours  INTEGER
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT,
                day          TEXT,
                type         TEXT,
                message      TEXT,
                person_name  TEXT,
                risk_score   INTEGER,
                read         INTEGER DEFAULT 0
            );
        """)

init_db()

# Auth ─────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("X-API-Key") != ESP32_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# Helper: build notification message ──────
def build_notification(alert_type, person_name, risk_score, after_hours):
    messages = []
    types = alert_type.split(",") if alert_type else []

    for t in types:
        t = t.strip()
        if t == "unauthorized_access":
            messages.append(f"🚨 Unauthorized door access detected" +
                          (f" — {person_name}" if person_name and person_name != "Unknown" else ""))
        elif t == "motion_no_auth":
            messages.append("🚨 Motion detected without authorization")
        elif t == "server_overheat":
            messages.append("🔥 Server temperature critical")
        elif t == "room_overheat":
            messages.append("🌡️ Room temperature too high")
        elif t == "high_humidity":
            messages.append("💧 Humidity level critical")
        elif t == "high_co2":
            messages.append("☁️ CO₂ level dangerous")

    if after_hours and ("unauthorized_access" in types or "motion_no_auth" in types):
        messages.append("🌙 After-hours activity detected")

    return " | ".join(messages) if messages else "Alert triggered"

# ESP32 data ingestion ──────
@app.route("/api/data", methods=["POST"])
@require_api_key
def receive_data():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    now         = datetime.now()
    timestamp   = now.strftime("%Y-%m-%d %H:%M:%S")
    day         = DAYS[now.weekday()]
    after_hours = 0 if WORK_HOURS[0] <= now.hour < WORK_HOURS[1] else 1

    # Support both short keys (LoRa) and long keys (direct POST)
    nfc_uid     = data.get("uid",  data.get("nfc_uid",     ""))
    person_name = data.get("n",    data.get("person_name", ""))
    temp_s      = float(data.get("ts", data.get("temp_s",  25)))
    temp_r      = float(data.get("tr", data.get("temp_r",  25)))
    hum         = float(data.get("h",  data.get("hum",     50)))
    co2         = int  (data.get("c",  data.get("co2",    400)))
    door        = int  (data.get("d",  data.get("door",     0)))
    motion      = int  (data.get("m",  data.get("motion",   0)))
    nfc_valid   = int  (data.get("v",  data.get("nfc_valid",0)))
    alert       = int  (data.get("a",  data.get("alert",    0)))
    alert_type  =       data.get("at", data.get("alert_type",""))
    # ns=1 means that the transmitter just detected a fresh physical scan
    ns_flag  = int(data.get("ns", 0))
    _now     = _time.time()
    new_scan = bool(nfc_uid) and (
        ns_flag == 1 or
        nfc_uid != _last_nfc["uid"] or
        _now - _last_nfc["ts"] > 30
    )
    if new_scan:
        _last_nfc["uid"] = nfc_uid
        _last_nfc["ts"]  = _now

    if not person_name or person_name == "Unknown":
        person_name = UID_PERSONS.get(nfc_uid, "Unknown")

    # AI scoring
    result = ai.predict(
        temp_s      = temp_s,
        temp_r      = temp_r,
        hum         = hum,
        co2         = co2,
        door        = door,
        motion      = motion,
        nfc_valid   = nfc_valid,
        after_hours = after_hours,
    )

    with get_db() as conn:
        # Main readings table
        conn.execute(
            """INSERT INTO readings
               (timestamp,day,temp_s,temp_r,hum,co2,door,motion,
                nfc_uid,nfc_valid,person_name,alert,alert_type,
                after_hours,risk_score,risk_status,risk_reason)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (timestamp, day,
             temp_s, temp_r, hum, co2, door, motion,
             nfc_uid, nfc_valid, person_name,
             alert, alert_type, after_hours,
             result["score"], result["status"], result["reason"])
        )

        # Access log — only on fresh NFC scan
        if nfc_uid and new_scan:
            conn.execute(
                """INSERT INTO access_log
                   (timestamp,day,nfc_uid,person_name,nfc_valid,door_open,after_hours)
                   VALUES (?,?,?,?,?,?,?)""",
                (timestamp, day, nfc_uid, person_name,
                 nfc_valid, door, after_hours)
            )

        # Notifications — only on alert
        if alert and alert_type:
            message = build_notification(alert_type, person_name, result["score"], after_hours)
            conn.execute(
                """INSERT INTO notifications
                   (timestamp,day,type,message,person_name,risk_score)
                   VALUES (?,?,?,?,?,?)""",
                (timestamp, day, alert_type, message, person_name, result["score"])
            )

    # Broadcast to dashboard
    payload = {
        "timestamp":   timestamp,
        "day":         day,
        "temp_s":      temp_s,
        "temp_r":      temp_r,
        "hum":         hum,
        "co2":         co2,
        "door":        door,
        "motion":      motion,
        "nfc_uid":     nfc_uid,
        "nfc_valid":   nfc_valid,
        "person_name": person_name,
        "alert":       alert,
        "alert_type":  alert_type,
        "after_hours": after_hours,
        "risk_score":  result["score"],
        "risk_status": result["status"],
        "risk_reason": result["reason"],
        "notification": build_notification(alert_type, person_name,
                                           result["score"], after_hours) if alert else ""
    }
    socketio.emit("sensor_update", payload)

    # Emit real-time access event on fresh NFC scan
    if nfc_uid and new_scan:
        access_msg = ("✅ Access Granted" if nfc_valid else "❌ Access Denied")
        person_label = person_name if person_name and person_name != "Unknown" else nfc_uid
        socketio.emit("access_event", {
            "timestamp":   timestamp,
            "day":         day,
            "nfc_uid":     nfc_uid,
            "person_name": person_name,
            "nfc_valid":   nfc_valid,
            "door":        door,
            "after_hours": after_hours,
            "message":     f"{access_msg} — {person_label}"
        })

    # Emit separate notification event for popup
    if alert and alert_type:
        socketio.emit("new_notification", {
            "timestamp":   timestamp,
            "day":         day,
            "message":     build_notification(alert_type, person_name,
                                              result["score"], after_hours),
            "person_name": person_name,
            "risk_score":  result["score"],
            "risk_status": result["status"],
            "alert_type":  alert_type
        })

    return jsonify({"status": "ok", "risk_score": result["score"]}), 200

# Dashboard API endpoints ───────
@app.route("/api/latest")
@login_required
def api_latest():
    with get_db() as conn:
        row = conn.execute("SELECT * FROM readings ORDER BY id DESC LIMIT 1").fetchone()
    return jsonify(dict(row) if row else {})

@app.route("/api/history")
@login_required
def api_history():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM readings ORDER BY id DESC LIMIT 60"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts")
@login_required
def api_alerts():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM readings WHERE alert=1 ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/access_log")
@login_required
def api_access_log():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM access_log ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/notifications")
@login_required
def api_notifications():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/notifications/read", methods=["POST"])
@login_required
def mark_notifications_read():
    with get_db() as conn:
        conn.execute("UPDATE notifications SET read=1 WHERE read=0")
    return jsonify({"status": "ok"})

# Auth routes ────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USER and
                request.form.get("password") == ADMIN_PASS):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
