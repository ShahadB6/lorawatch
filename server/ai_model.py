"""
AI Security Scoring Model
Trains an MLP classifier on synthetic data and exposes a predict() method
that returns a 0-100 risk score, a status label, and a human-readable reason.
"""

import os
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

MODEL_PATH  = os.path.join(os.path.dirname(__file__), "security_model.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "security_scaler.pkl")

LABELS = ["normal", "warning", "critical", "breach"]


# Synthetic training data ───────
def _generate_data(n: int = 2000):
    rng = np.random.default_rng(42)

    def row(ts, tr, h, co2, door, motion, nfc, ah, label):
        return [ts, tr, h, co2, door, motion, nfc, ah, label]

    rows = []

    # Normal — everything is in range, authorised access
    for _ in range(n):
        rows.append(row(
            rng.uniform(22, 38), rng.uniform(18, 27),
            rng.uniform(30, 60), rng.uniform(400, 580),
            0, 0, 1, 0, "normal"
        ))

    # Warning — elevated environment, authorised user
    for _ in range(n // 2):
        rows.append(row(
            rng.uniform(38, 50), rng.uniform(27, 34),
            rng.uniform(60, 78), rng.uniform(580, 980),
            rng.integers(0, 2), rng.integers(0, 2),
            1, 0, "warning"
        ))

    # Critical — environment critical, still authorised
    for _ in range(n // 3):
        rows.append(row(
            rng.uniform(50, 75), rng.uniform(34, 48),
            rng.uniform(78, 100), rng.uniform(980, 2000),
            rng.integers(0, 2), rng.integers(0, 2),
            rng.integers(0, 2), rng.integers(0, 2),
            "critical"
        ))

    # Security breach — door/motion with invalid NFC
    for _ in range(n // 2):
        rows.append(row(
            rng.uniform(22, 55), rng.uniform(18, 36),
            rng.uniform(30, 80), rng.uniform(400, 1500),
            1, 1, 0,
            rng.choice([0, 1], p=[0.3, 0.7]),
            "breach"
        ))

    # Suspicious — after-hours motion without NFC
    for _ in range(n // 3):
        rows.append(row(
            rng.uniform(22, 42), rng.uniform(18, 30),
            rng.uniform(30, 65), rng.uniform(400, 700),
            rng.integers(0, 2), 1, 0, 1,
            "breach"
        ))

    rows = np.array(rows, dtype=object)
    X = rows[:, :8].astype(float)
    y = rows[:, 8]
    return X, y


def compute_risk_score(temp_s, temp_r, hum, co2, door, motion, nfc_valid, after_hours):
    score = 0
    if temp_s > 50:  score += 20
    elif temp_s > 40: score += 10
    if temp_r > 35:  score += 15
    elif temp_r > 28: score += 8
    if hum > 85:     score += 10
    elif hum > 70:   score += 5
    if co2 > 1000:   score += 15
    elif co2 > 600:  score += 8
    if door and not nfc_valid:   score += 30
    if motion and not nfc_valid: score += 25
    if after_hours and (door or motion): score += 20
    return min(int(score), 100)


class SecurityAIModel:
    def __init__(self):
        self.clf     = None
        self.scaler  = StandardScaler()
        self.encoder = LabelEncoder()

    # Persistence ───────
    def save(self):
        joblib.dump(self.clf,     MODEL_PATH)
        joblib.dump((self.scaler, self.encoder), SCALER_PATH)

    def load(self) -> bool:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.clf = joblib.load(MODEL_PATH)
            self.scaler, self.encoder = joblib.load(SCALER_PATH)
            print("[AI] Model loaded from disk.")
            return True
        return False

    # Training ───────
    def train(self):
        print("[AI] Generating training data and fitting model …")
        X, y = _generate_data(2000)
        X_s  = self.scaler.fit_transform(X)
        y_enc = self.encoder.fit_transform(y)   # encode string labels - integers
        self.clf = MLPClassifier(
            hidden_layer_sizes=(32, 16),
            activation="relu",
            max_iter=600,
            random_state=42,
        )
        self.clf.fit(X_s, y_enc)
        self.save()
        print("[AI] Model trained and saved.")

    # Inference ───────
    def predict(self, temp_s, temp_r, hum, co2, door, motion, nfc_valid, after_hours) -> dict:
        score  = compute_risk_score(temp_s, temp_r, hum, co2, door, motion, nfc_valid, after_hours)
        status = "normal"

        if self.clf is not None:
            X      = np.array([[temp_s, temp_r, hum, co2, door, motion, nfc_valid, after_hours]])
            X_s    = self.scaler.transform(X)
            y_pred = self.clf.predict(X_s)[0]
            status = self.encoder.inverse_transform([y_pred])[0]  # decode integer - string label

        # Reconcile: rule score always determines final bucket
        if score <= 30:   status = "normal"
        elif score <= 60: status = "warning"  if status not in ("critical","breach") else status
        elif score <= 80: status = "critical" if status != "breach" else status
        else:             status = "breach"

        parts = []
        if temp_s > 40:            parts.append(f"Server temp {temp_s:.1f}°C")
        if temp_r > 28:            parts.append(f"Room temp {temp_r:.1f}°C")
        if hum > 70:               parts.append(f"Humidity {hum:.1f}%")
        if co2 > 600:              parts.append(f"CO₂ {co2} ppm")
        if door and not nfc_valid: parts.append("Unauthorized door access")
        if motion and not nfc_valid: parts.append("Motion without authorization")
        if after_hours and (door or motion): parts.append("After-hours activity")
        reason = ", ".join(parts) if parts else "All systems nominal"

        return {"score": score, "status": status, "reason": reason}
