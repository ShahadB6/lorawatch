# LoRaWatch — Server Room Security & Environmental Monitoring System

A real-time IoT system that monitors server room temperature, humidity, CO₂, motion, and NFC door access — transmitting AES-128-ECB encrypted sensor data over LoRa radio to a live AI-powered security dashboard.

🌐 **Website:** [lorawatch.site](https://lorawatch.site)  
📧 **Email:** info@lorawatch.site

---

## Repository Structure

```
lorawatch/
├── esp32_transmitter/
│   └── esp32_transmitter.ino   # ESP32-S3 transmitter firmware
├── esp32_receiver/
│   └── esp32_receiver.ino      # ESP32-S3 receiver firmware
└── server/
    ├── app.py                  # Flask server & WebSocket backend
    ├── ai_model.py             # AI risk scoring engine
    └── templates/
        ├── dashboard.html      # Live monitoring dashboard
        └── login.html          # Admin login page
```

---

## Quick Start

### 1. Flash the ESP32 Firmware
- Open `esp32_transmitter/esp32_transmitter.ino` in Arduino IDE and flash to the transmitter ESP32-S3
- Open `esp32_receiver/esp32_receiver.ino` in Arduino IDE and flash to the receiver ESP32-S3

### 2. Install Python Dependencies
```bash
pip install flask flask-socketio eventlet scikit-learn numpy
```

### 3. Run the Server
```bash
cd server
python app.py
```

### 4. Open the Dashboard
Navigate to `http://localhost:5000` in your browser.  
Default credentials: `admin` / `admin123`

---

## Hardware Requirements

| Component | Quantity |
|-----------|----------|
| ESP32-S3 Development Board | 2 |
| EBYTE E32-433T20D LoRa Module | 2 |
| DHT11 Temperature & Humidity Sensor | 2 |
| PN532 NFC Reader Module | 1 |
| PIR Motion Sensor | 1 |
| Analog CO₂ Sensor | 1 |
| Magnetic Reed Switch (Door Sensor) | 1 |
| 16×2 LCD Display (I2C) | 1 |
| Active Buzzer | 1 |
| LEDs (Red & Green) | 2 |

---

## System Architecture

```
[Sensors] → [ESP32 Transmitter] → AES-128 Encrypt → [LoRa Radio]
                                                           ↓
[Dashboard] ← WebSocket ← [Flask Server] ← HTTP POST ← [ESP32 Receiver]
```

---

## License

This project was developed as a Senior Project (2025–2026).
