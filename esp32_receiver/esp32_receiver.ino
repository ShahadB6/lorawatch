//  Second ESP32 — Receiver / Gateway Node
//  LoRa → AES-128 decrypt → binary unpack → JSON → WiFi → Python Server

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/aes.h"

// WiFi Configuration ───────────
const char* WIFI_SSID     = "TP-Link_A819";
const char* WIFI_PASSWORD = "40727590";
const char* SERVER_URL    = "http://192.168.0.156:5000/api/data";
const char* API_KEY       = "esp32-secret-key-2026";   

// LoRa UART pins ────────
#define LORA_RX_PIN   16   
#define LORA_TX_PIN   17   
#define LORA_M0_PIN   11   // LoRa mode control
#define LORA_M1_PIN   12   // LoRa mode control  (M0=LOW,M1=LOW → normal)
#define LORA_AUX_PIN   5   // LoRa ready signal  
HardwareSerial LoRaSerial(2);

// AES-128-ECB key must match esp32_transmitter ────
static const uint8_t AES_KEY[16] = {
  0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
  0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
};

void setup() {
  Serial.begin(115200);

  // LoRa M0/M1: Normal (transparent) mode ────────
  pinMode(LORA_M0_PIN,  OUTPUT);
  pinMode(LORA_M1_PIN,  OUTPUT);
  pinMode(LORA_AUX_PIN, INPUT);
  digitalWrite(LORA_M0_PIN, LOW);   // M0=LOW
  digitalWrite(LORA_M1_PIN, LOW);   // M1=LOW → Mode 0: transparent
  delay(100);                        // delay to let module settle

  LoRaSerial.setRxBufferSize(512);   // prevent overflow during blocking HTTP POST
  LoRaSerial.begin(9600, SERIAL_8N1, LORA_RX_PIN, LORA_TX_PIN);

  connectWiFi();
}

// CRC-16 (Modbus) matching transmitter ──────────
uint16_t crc16(const String &s) {
  uint16_t crc = 0xFFFF;
  for (int i = 0; i < (int)s.length(); i++) {
    crc ^= (uint8_t)s[i];
    for (int b = 0; b < 8; b++)
      crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : (crc >> 1);
  }
  return crc;
}

String validatePacket(const String &s) {
  if ((int)s.length() != 36) return "";
  for (int i = 0; i < 36; i++) {
    if (!isHexChar(s[i])) return "";
  }
  String hexData = s.substring(0, 32);
  uint16_t expected = (uint16_t)strtoul(s.substring(32).c_str(), nullptr, 16);
  if (crc16(hexData) != expected) {
    Serial.println("[RX] CRC mismatch — corrupted packet.");
    return "";
  }
  return hexData;
}

enum RxState { SEEKING, READING_LEN, READING_PAYLOAD };

RxState       rxState    = SEEKING;
String        rxLenStr   = "";      // accumulates 3 length chars
int           rxExpected = 0;       // payload chars to collect
String        rxPayload  = "";      // accumulates payload
unsigned long rxTimeoutMs = 0;

String lastJson   = "";
unsigned long lastFwdTime = 0;

// AES hex output is uppercase 0-9 A-F; CRC is also hex  (one filter covers all)
inline bool isHexChar(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

// Process a fully collected payload ─────────
void processPayload() {
  String hexData = validatePacket(rxPayload);
  if (hexData.length() == 0) {
    Serial.println("[RX] CRC mismatch — discarding.");
    return;
  }
  Serial.println("[RX] Encrypted: " + hexData);
  static uint8_t bin[16];
  if (!decryptToBytes(hexData, bin)) {
    Serial.println("[RX] Decrypt failed — discarding.");
    return;
  }
  String json = binaryToJson(bin);
  Serial.println("[RX] Decoded: " + json);
  unsigned long now = millis();
  if (json == lastJson && now - lastFwdTime < 2000) {
    Serial.println("[RX] Duplicate — skipped.");
  } else {
    sendToServer(json);
    lastJson    = json;
    lastFwdTime = now;
  }
}

void loop() {
  // Reconnect WiFi if dropped
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  // Timeout guard — reset if stuck mid-frame for more than 3 s
  // If 8 s with no new chars, give up on current frame
  if (rxState != SEEKING && millis() - rxTimeoutMs > 8000) {
    Serial.printf("[RX] Timeout (state=%d collected=%u) — resetting.\n",
                  rxState, rxPayload.length());
    rxState  = SEEKING;
    rxLenStr = "";
    rxPayload = "";
  }

  while (LoRaSerial.available()) {
    char c = (char)LoRaSerial.read();

    switch (rxState) {

      // Wait for '$' start marker ──────
      case SEEKING:
        if (c == '$') {
          rxLenStr  = "";
          rxPayload = "";
          rxState   = READING_LEN;
          rxTimeoutMs = millis();
        }
        break;

      // Collect exactly 3 hex chars as the payload length ─
      case READING_LEN:
        if (c == '$') {                 
          rxLenStr    = "";
          rxTimeoutMs = millis();
          break;
        }
        if (!isHexChar(c)) break;       // skip E32 separators  (\r \n | # ) etc
        rxTimeoutMs = millis();         // reset watchdog on every good char
        rxLenStr += c;
        if (rxLenStr.length() == 3) {
          rxExpected = (int)strtol(rxLenStr.c_str(), nullptr, 16);
          if (rxExpected == 36) {   // always 32 AES-ECB hex + 4 CRC
            rxPayload   = "";
            rxState     = READING_PAYLOAD;
            rxTimeoutMs = millis();
          } else {
            Serial.printf("[RX] Bad length %d — resetting.\n", rxExpected);
            rxState  = SEEKING;
            rxLenStr = "";
          }
        }
        break;

      case READING_PAYLOAD:
        if (c == '$') {
          Serial.printf("[RX] New frame mid-payload (had %u/%d) — restarting.\n",
                        rxPayload.length(), rxExpected);
          rxLenStr    = "";
          rxPayload   = "";
          rxState     = READING_LEN;
          rxTimeoutMs = millis();
          break;
        }
        // Skip all other non-hex bytes (E32 separators: |, \r, \n, #, …) 
        if (!isHexChar(c)) break;
        rxTimeoutMs = millis();         // reset watchdog on every good char
        rxPayload += c;
        if ((int)rxPayload.length() >= rxExpected) {
          processPayload();
          rxState   = SEEKING;
          rxLenStr  = "";
          rxPayload = "";
        }
        break;
    }
  }
}

// WiFi connection ───────
void connectWiFi() {
  Serial.print("[WiFi] Connecting to ");
  Serial.print(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print('.');
    attempts++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[WiFi] Connected: " + WiFi.localIP().toString());
  } else {
    Serial.println("\n[WiFi] Failed — will retry in loop.");
  }
}

// Hex string → byte array ───────
bool hexToBytes(const String &hex, uint8_t *out, int n) {
  if ((int)hex.length() != n * 2) return false;
  for (int i = 0; i < n; i++) {
    char b[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
    out[i] = (uint8_t)strtol(b, nullptr, 16);
  }
  return true;
}

bool decryptToBytes(const String &hexInput, uint8_t out16[16]) {
  static uint8_t in[16], out[16];
  if (!hexToBytes(hexInput, in, 16)) return false;

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, AES_KEY, 128);
  mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, in, out);
  mbedtls_aes_free(&ctx);

  memcpy(out16, out, 16);
  return true;
}

// Unpack 16-byte binary → JSON string (sent to Python server) ─
String binaryToJson(const uint8_t bin[16]) {
  static const char* ALERT_NAMES[] = {
    "unauthorized_access", "motion_no_auth", "server_overheat",
    "room_overheat",       "high_humidity",  "high_co2"
  };
  static const char* PERSON_NAMES[] = { "", "Admin Card", "Staff Tag", "Visitor Sticker" };

  uint16_t co2      = ((uint16_t)bin[3] << 8) | bin[4];
  uint8_t  flags    = bin[5];
  uint8_t  uidLen   = bin[6];
  uint8_t  nameIdx  = bin[14];
  uint8_t  alertMask = bin[15];

  // UID bytes - uppercase hex string
  String uid = "";
  for (int i = 0; i < uidLen && i < 7; i++) {
    char h[3];
    snprintf(h, 3, "%02X", bin[7 + i]);
    uid += h;
  }

  // Alert type string from bitmask
  String at = "";
  for (int b = 0; b < 6; b++) {
    if (alertMask & (1 << b)) {
      if (at.length()) at += ",";
      at += ALERT_NAMES[b];
    }
  }

  StaticJsonDocument<300> doc;
  doc["ts"]  = bin[0];
  doc["tr"]  = bin[1];
  doc["h"]   = bin[2];
  doc["c"]   = co2;
  doc["d"]   = (flags >> 0) & 1;
  doc["m"]   = (flags >> 1) & 1;
  doc["uid"] = uid;
  doc["v"]   = (flags >> 2) & 1;
  doc["n"]   = (nameIdx < 4) ? PERSON_NAMES[nameIdx] : "";
  doc["a"]   = (flags >> 3) & 1;
  doc["at"]  = at;
  doc["ns"]  = (flags >> 4) & 1;

  String json;
  serializeJson(doc, json);
  return json;
}

// POST decrypted JSON to Python server ───────
void sendToServer(const String &jsonData) {
  if (WiFi.status() != WL_CONNECTED) return;

  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-Key", API_KEY);
  http.setTimeout(5000);   // 5 s max, avoids read Timeout on slow responses

  int code = http.POST(jsonData);
  if (code > 0) {
    Serial.println("[HTTP] Response: " + String(code));
  } else {
    Serial.println("[HTTP] Error: " + http.errorToString(code));
  }
  http.end();
}
