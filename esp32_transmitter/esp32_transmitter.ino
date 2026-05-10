//  First ESP32 — Server Room Transmitter Node
//  Sensors → 16-byte binary → AES-128-CBC → LoRa → ESP32 #2

#include <DHT.h>
#include <Wire.h>
#include <Adafruit_PN532.h>
#include <LiquidCrystal_I2C.h>
#include "mbedtls/aes.h"

// Mapping of the pins ──────
#define DHT_SERVER_PIN   6    
#define DHT_ROOM_PIN     7    
#define CO2_PIN          35
#define PIR_PIN          36
#define DOOR_PIN         39
#define RED_LED_PIN      13
#define GREEN_LED_PIN    14
#define LORA_RX_PIN      16
#define LORA_TX_PIN      17
#define LORA_M0_PIN      11   // LoRa mode control
#define LORA_M1_PIN      12   // LoRa mode control  (M0=LOW,M1=LOW → normal/transparent)
#define LORA_AUX_PIN     47   // LoRa ready signal (HIGH means idle)
#define BUZZER_PIN       2    
//  I2C: SDA=21, SCL=0 (same pins are shared by LCD and NFC)

// Sensor objects ─────────
DHT dhtServer(DHT_SERVER_PIN, DHT11);
DHT dhtRoom  (DHT_ROOM_PIN,   DHT11);
Adafruit_PN532    nfc(-1, -1, &Wire);
LiquidCrystal_I2C lcd(0x27, 16, 2);   
HardwareSerial    LoRaSerial(2);

// AES-128-ECB key (matching the esp32_receiver) ───────
// ECB mode uses the key only — no IV required
static const uint8_t AES_KEY[16] = {
  0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
  0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
};

// Registration of authorized NFC UIDs and names ──────
static const String VALID_UIDS[]  = { "1BDD3A06", "5DE95006", "FF0F9806120100" };
static const String VALID_NAMES[] = { "Admin Card", "Staff Tag", "Visitor Sticker" };
static const int    VALID_UID_COUNT = 3;

// Alert thresholds ────────
#define TEMP_S_CRIT    50  //Server temperature (Type: Critical)
#define TEMP_S_WARN    40  //Server tempaerature (Type: Warning)
#define TEMP_R_CRIT    35  //Room temperature (Type: Critical)
#define TEMP_R_WARN    28  //Room temperature (Type:Warning)
#define HUM_CRIT       85  //Humidity (Type: Critical)
#define HUM_WARN       70  //Humidity (Type: Warning)
#define CO2_CRIT       1000  //CO2 (Type: Critical)
#define CO2_WARN       600  //CO2 (Type: Warning)
#define NFC_TIMEOUT_MS 10000UL
#define SEND_INTERVAL  1500UL   // 1.5 s interval - dashboard updates ~every 1.5 s
#define LCD_INTERVAL   3000UL

// Working hours (24h format) ───────
// Important Note: ESP32 #1 (the transmitter) has no RTC/WiFi — after-hours check is done on server side
// The flag is included in transmitted data for server to evaluate

// Runtime state ─────
float  tempServer = 25.0, tempRoom = 25.0, humidity = 50.0;
int    co2Level   = 400;
bool   doorOpen   = false;
bool   motionDetected = false;
bool   nfcValid   = false;
String lastUID    = "";
String lastPersonName = "";

unsigned long lastNFCTime  = 0;
unsigned long lastSendTime = 0;
unsigned long lastLCDTime  = 0;
unsigned long lastDHTRead  = 0;
unsigned long alarmStart   = 0;
bool   alarmActive = false;
bool   newScan     = false;   // This becomes true only when there is fresh NFC scan, cleared after transmit

// Transmit tracking as soon as the state changes 
bool   prevAlertActive = false;
String prevAlertType   = "";

int    lcdPage     = 0;
bool   alertActive = false;
String alertType   = "";

void setup() {
  Serial.begin(115200);

  Wire.begin(21, 0);  // SDA=21, SCL=G0

  // DHT pull-ups: force internal pull-up before begin() ──────
  gpio_set_pull_mode((gpio_num_t)DHT_SERVER_PIN, GPIO_PULLUP_ONLY);
  gpio_set_pull_mode((gpio_num_t)DHT_ROOM_PIN,   GPIO_PULLUP_ONLY);

  // LoRa M0/M1 is set to normal (transparent) mode BEFORE serial ──
  pinMode(LORA_M0_PIN,  OUTPUT);
  pinMode(LORA_M1_PIN,  OUTPUT);
  pinMode(LORA_AUX_PIN, INPUT);
  digitalWrite(LORA_M0_PIN, LOW);   // M0=LOW
  digitalWrite(LORA_M1_PIN, LOW);   // M1=LOW  → Mode 0: transparent
  delay(100);                        // delay to let module settle

  LoRaSerial.setTxBufferSize(256);
  LoRaSerial.begin(9600, SERIAL_8N1, LORA_RX_PIN, LORA_TX_PIN);

  dhtServer.begin();
  dhtRoom.begin();

  nfc.begin();
  if (nfc.getFirmwareVersion()) {
    nfc.SAMConfig();
    Serial.println("[NFC] Ready.");
  } else {
    Serial.println("[NFC] Not found.");
  }

  lcd.init();
  lcd.backlight();
  lcdPrint("Server Room Mon", "  Starting...  ");

  pinMode(PIR_PIN,       INPUT);
  pinMode(DOOR_PIN,      INPUT);
  pinMode(RED_LED_PIN,   OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN,    OUTPUT);

  digitalWrite(RED_LED_PIN,   LOW);
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN,    LOW);

  delay(2000);
  lcd.clear();
  Serial.println("[BOOT] System ready.");
}

void loop() {
  readSensors();
  checkNFC();
  checkAlerts();
  handleAlarm();
  updateLCD();

  // Send on normal interval or immediately when alert state changes
  bool alertChanged = (alertActive != prevAlertActive) || (alertType != prevAlertType);
  if ((millis() - lastSendTime >= SEND_INTERVAL) || alertChanged) {
    transmitData();
    lastSendTime = millis();
  }
  prevAlertActive = alertActive;
  prevAlertType   = alertType;
}

// Sensor reading ──────
void readSensors() {
  motionDetected = digitalRead(PIR_PIN); //read every loop
  doorOpen       = digitalRead(DOOR_PIN); //read every loop
  int raw  = analogRead(CO2_PIN); //read every loop
  co2Level = map(raw, 0, 4095, 400, 2000);

  // DHT — throttle to once every 3 s; retry up to 3 times on NaN
  if (millis() - lastDHTRead < 3000) return;
  lastDHTRead = millis();

  for (int attempt = 0; attempt < 3; attempt++) {
    float ts = dhtServer.readTemperature();
    float tr = dhtRoom.readTemperature();
    float h  = dhtRoom.readHumidity();

    bool tsOk = !isnan(ts) && ts >= 0 && ts <= 80;   // Allow overheating readings
    bool trOk = !isnan(tr) && tr >= 0 && tr <= 80;   // Allow overheating readings
    bool hOk  = !isnan(h)  && h  >= 0 && h  <= 100;

    if (tsOk) tempServer = ts;
    if (trOk) tempRoom   = tr;
    if (hOk)  humidity   = h;

    if (tsOk && trOk && hOk) break;   // If everything is good, no retry needed

    Serial.printf("[DHT] Attempt %d failed (ts=%.1f tr=%.1f h=%.1f) — retrying\n",
                  attempt + 1, ts, tr, h);
    delay(200);   // short settle before retrying
  }
}

// NFC scanning ────────
void checkNFC() {
  uint8_t uid[7];
  uint8_t uidLength;

  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 50)) return;

  String uidStr = "";
  for (uint8_t i = 0; i < uidLength; i++) {
    if (uid[i] < 0x10) uidStr += "0";
    uidStr += String(uid[i], HEX);
  }
  uidStr.toUpperCase();
  lastUID       = uidStr;
  nfcValid      = false;
  lastPersonName = "Unknown";

  Serial.println("[NFC] Card UID: " + uidStr);

  for (int i = 0; i < VALID_UID_COUNT; i++) {
    if (uidStr == VALID_UIDS[i]) {
      nfcValid       = true;
      lastPersonName = VALID_NAMES[i];
      break;
    }
  }
  lastNFCTime = millis();
  newScan     = true;   // flags fresh scan for the next transmission

  if (nfcValid) {
    // Authorized — green LED and 1 short beep, then back to normal quickly
    digitalWrite(GREEN_LED_PIN, HIGH);
    digitalWrite(RED_LED_PIN,   LOW);
    beep(1, 100);   // 1 × 200 ms total — minimal blocking
    lcdPrint("Access Granted  ", lastPersonName.substring(0, 16));
    Serial.println("[NFC] Access granted: " + lastPersonName);
    delay(400);     
    digitalWrite(GREEN_LED_PIN, LOW);

  } else {
    // Unauthorized — red LED and 1 short beep (alarm buzzer handles the rest)
    digitalWrite(RED_LED_PIN,   HIGH);
    digitalWrite(GREEN_LED_PIN, LOW);
    beep(1, 100);   // 1 beep only — was 3×400 ms = 1500 ms blocking
    lcdPrint("Access DENIED   ", uidStr.substring(0, 16));
    Serial.println("[NFC] Access DENIED for UID: " + uidStr);
    delay(400);     
    digitalWrite(RED_LED_PIN, LOW);
  }
  lcd.clear();
}

// Alert logic ──────
void checkAlerts() {
  alertActive = false;
  alertType   = "";

  bool nfcExpired = (millis() - lastNFCTime) > NFC_TIMEOUT_MS;

  // Security alerts — trigger full alarm
  if (doorOpen && (nfcExpired || !nfcValid))  addAlert("unauthorized_access");
  if (motionDetected && nfcExpired)            addAlert("motion_no_auth");

  // Environmental alerts — trigger alarm
  if (tempServer > TEMP_S_CRIT)  addAlert("server_overheat");
  if (tempRoom   > TEMP_R_CRIT)  addAlert("room_overheat");
  if (humidity   > HUM_CRIT)     addAlert("high_humidity");
  if (co2Level   > CO2_CRIT)     addAlert("high_co2");

  if (alertActive) {
    digitalWrite(RED_LED_PIN, HIGH);
    if (!alarmActive) {
      alarmActive = true;
      alarmStart  = millis();
    }
  } else {
    digitalWrite(RED_LED_PIN,  LOW);
    digitalWrite(BUZZER_PIN,   LOW);
    alarmActive = false;
  }
}

void addAlert(const String &type) {
  alertActive = true;
  alertType   = alertType.length() ? alertType + "," + type : type;
}

// Alarm handler (non-blocking continuous beep during alert) 
void handleAlarm() {
  if (!alarmActive) return;

  // Rapid beeping pattern (200ms on, 200ms off)
  unsigned long elapsed = (millis() - alarmStart) % 400;
  bool buzzerOn = elapsed < 200;
  digitalWrite(BUZZER_PIN, buzzerOn ? HIGH : LOW);
}

// LCD display ───────
void updateLCD() {
  if (millis() - lastLCDTime < LCD_INTERVAL) return;
  lastLCDTime = millis();
  lcd.clear();

  switch (lcdPage) {
    case 0:
      lcd.setCursor(0,0); lcd.print("Srv:" + String(tempServer,1) + "\xDFC");
      lcd.setCursor(0,1); lcd.print("Rm: " + String(tempRoom,  1) + "\xDFC");
      break;
    case 1:
      lcd.setCursor(0,0); lcd.print("Hum: " + String(humidity,1) + "%");
      lcd.setCursor(0,1); lcd.print("CO2: " + String(co2Level) + "ppm");
      break;
    case 2:
      lcd.setCursor(0,0); lcd.print("Door:" + String(doorOpen       ? "OPEN  " : "CLOSED"));
      lcd.setCursor(0,1); lcd.print("PIR: " + String(motionDetected ? "MOTION" : "clear "));
      break;
    case 3:
      lcd.setCursor(0,0); lcd.print(alertActive ? "!! ALERT !!     " : "Status: OK      ");
      lcd.setCursor(0,1); lcd.print(alertActive ? alertType.substring(0,16) : "All systems ok  ");
      break;
  }
  lcdPage = (lcdPage + 1) % 4;
}

void lcdPrint(const String &l1, const String &l2) {
  lcd.clear();
  lcd.setCursor(0,0); lcd.print(l1);
  lcd.setCursor(0,1); lcd.print(l2);
}

// Buzzer beep helper ──────
void beep(int times, int ms) {
  for (int i = 0; i < times; i++) {
    digitalWrite(BUZZER_PIN, HIGH); delay(ms);
    digitalWrite(BUZZER_PIN, LOW);  delay(100);
  }
}

String encryptBinary(const uint8_t data[16]) {
  static uint8_t out[16];

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, AES_KEY, 128);
  mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, data, out);
  mbedtls_aes_free(&ctx);

  char hex[33];
  for (int i = 0; i < 16; i++) snprintf(hex + i * 2, 3, "%02X", out[i]);
  return String(hex);   // Always 32 uppercase hex chars
}

// CRC-16 (Modbus) over a hex string ─────
uint16_t crc16(const String &s) {
  uint16_t crc = 0xFFFF;
  for (int i = 0; i < (int)s.length(); i++) {
    crc ^= (uint8_t)s[i];
    for (int b = 0; b < 8; b++)
      crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : (crc >> 1);
  }
  return crc;
}

// Wait for LoRa AUX pin to go HIGH (module to be ready) ──────────
void waitLoRaReady() {
  // AUX = LOW while the E32 is busy (UART buffering or RF transmission)
  // Wait up to 3 s, this is necessary when transmitting at slow air data rates
  unsigned long t = millis();
  while (digitalRead(LORA_AUX_PIN) == LOW && millis() - t < 3000) delay(10);
  delay(10);  // Extra settle time
}

// Transmit AES-encrypted binary sensor packet over LoRa ─────
void transmitData() {
  // Pack 12 sensor fields into 16 bytes (1 AES block) ─────────
  // Byte layout:
  //  [0]    tempServer  uint8 (°C, integer)
  //  [1]    tempRoom    uint8 (°C, integer)
  //  [2]    humidity    uint8 (%, integer)
  //  [3-4]  co2Level    uint16 big-endian
  //  [5]    flags       bit0=door bit1=motion bit2=nfcValid bit3=alert bit4=newScan
  //  [6]    uid_len     number of UID bytes (0-7)
  //  [7-13] uid_bytes   raw UID, zero-padded to 7 bytes
  //  [14]   name_idx    0=unknown 1=Admin Card 2=Staff Tag 3=Visitor Sticker
  //  [15]   alert_mask  0x01=unauth 0x02=motion 0x04=srvHeat 0x08=rmHeat
  //                     0x10=humidity 0x20=co2
  uint8_t bin[16] = {0};

  bin[0] = (uint8_t)constrain((int)round(tempServer), 0, 255);
  bin[1] = (uint8_t)constrain((int)round(tempRoom),  0, 255);
  bin[2] = (uint8_t)constrain((int)round(humidity),  0, 100);

  uint16_t co2u = (uint16_t)constrain(co2Level, 0, 65535);
  bin[3] = (uint8_t)(co2u >> 8);
  bin[4] = (uint8_t)(co2u & 0xFF);

  bin[5] = (doorOpen       ? 0x01 : 0)
         | (motionDetected ? 0x02 : 0)
         | (nfcValid       ? 0x04 : 0)
         | (alertActive    ? 0x08 : 0)
         | (newScan        ? 0x10 : 0);

  int uidByteLen = min((int)(lastUID.length() / 2), 7);
  bin[6] = (uint8_t)uidByteLen;
  for (int i = 0; i < uidByteLen; i++) {
    char b[3] = { lastUID[i * 2], lastUID[i * 2 + 1], '\0' };
    bin[7 + i] = (uint8_t)strtol(b, nullptr, 16);
  }

  bin[14] = 0;
  for (int i = 0; i < VALID_UID_COUNT; i++) {
    if (nfcValid && lastUID == VALID_UIDS[i]) { bin[14] = (uint8_t)(i + 1); break; }
  }

  uint8_t am = 0;
  if (alertType.indexOf("unauthorized_access") >= 0) am |= 0x01;
  if (alertType.indexOf("motion_no_auth")      >= 0) am |= 0x02;
  if (alertType.indexOf("server_overheat")     >= 0) am |= 0x04;
  if (alertType.indexOf("room_overheat")       >= 0) am |= 0x08;
  if (alertType.indexOf("high_humidity")       >= 0) am |= 0x10;
  if (alertType.indexOf("high_co2")            >= 0) am |= 0x20;
  bin[15] = am;

  // Encrypt - always 64 hex chars ────────
  String cipher = encryptBinary(bin);

  // CRC-16 → 4 hex chars ──────
  char crcBuf[5];
  snprintf(crcBuf, sizeof(crcBuf), "%04X", crc16(cipher));
  String packet = cipher + crcBuf;   // always 68 chars

  char lenStr[4];
  snprintf(lenStr, sizeof(lenStr), "%03X", packet.length());
  String frame = "$" + String(lenStr) + packet;

  waitLoRaReady();
  LoRaSerial.print(frame);    
  delay(20);           // let AUX drop before we poll it
  waitLoRaReady();     // wait for RF transmission to complete

  newScan = false;
  Serial.printf("[TX] frame=$%s len=%u  ts=%.1f°C tr=%.1f°C h=%.1f%% co2=%d\n",
                lenStr, (unsigned)frame.length(),
                tempServer, tempRoom, humidity, co2Level);
}
