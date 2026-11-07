// Receive-only LoRa sniffer for the Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262).
//
// It never transmits. The host (sniffowireless) tells it which LoRa settings to listen on, over the USB serial port,
// and it prints every packet it receives, one line each:
//
//   RX,<ms>,<freq MHz>,<bw kHz>,<sf>,<sync>,<rssi dBm>,<snr dB>,<freq error Hz>,<length>,<hex bytes>
//
// Host -> device (one command per line):
//   CFG,<freq MHz>,<bw kHz>,<sf>,<cr 5-8>,<sync, e.g. 0x2B>,<preamble symbols>   listen with these settings
//   PING                                                                         -> PONG
//   INFO                                                                         -> INFO,...
// Device -> host besides RX:
//   READY,lora-sniffer,1,heltec_v3,sx1262     after boot
//   OK,CFG,...  /  ERR,CFG,<RadioLib status>  answer to CFG
//   STAT,<ms>,<packets>,<crc errors>          every 10 s
//
// The SX1262 filters packets by sync word in hardware, so a network is only heard while the radio is set to its
// frequency, bandwidth, spreading factor and sync word: the host hops between such "profiles".
#include <Arduino.h>
#include <RadioLib.h>
#include <SPI.h>

// Heltec WiFi LoRa 32 V3 wiring (the same as Meshtastic and the Heltec RadioLib examples use).
static const int LORA_NSS = 8, LORA_DIO1 = 14, LORA_RST = 12, LORA_BUSY = 13;
static const int LORA_SCK = 9, LORA_MISO = 11, LORA_MOSI = 10;
static const int PIN_VEXT = 36;  // active low: powers the display and the LoRa front end
static const int PIN_LED = 35;
static const float TCXO_VOLTAGE = 1.8;  // the SX1262's clock comes from a TCXO fed through DIO3

SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);

static volatile bool rxFlag = false;
static bool configured = false;
static float cfgFreq = 0, cfgBw = 0;
static uint8_t cfgSf = 0, cfgSync = 0;
static uint32_t packets = 0, crcErrors = 0, lastStat = 0, ledOffAt = 0;
static String line;

void IRAM_ATTR onReceive() { rxFlag = true; }

static void led(bool on) { digitalWrite(PIN_LED, on ? HIGH : LOW); }

// 1-byte sync word as RadioLib expects it (0x12 private, 0x34 LoRaWAN public, 0x2B Meshtastic).
static bool applyConfig(float freq, float bw, int sf, int cr, int sync, int preamble) {
  int state = radio.begin(freq, bw, sf, cr, (uint8_t)sync, 10, preamble, TCXO_VOLTAGE, false);
  if (state == RADIOLIB_ERR_NONE) state = radio.setDio2AsRfSwitch(true);
  if (state == RADIOLIB_ERR_NONE) state = radio.setCRC(2);        // 2-byte CRC: frames that fail it are not delivered
  if (state == RADIOLIB_ERR_NONE) state = radio.setRxBoostedGainMode(true);
  if (state != RADIOLIB_ERR_NONE) {
    configured = false;
    Serial.printf("ERR,CFG,%d\n", state);
    return false;
  }
  radio.setPacketReceivedAction(onReceive);
  rxFlag = false;
  state = radio.startReceive();
  if (state != RADIOLIB_ERR_NONE) {
    configured = false;
    Serial.printf("ERR,CFG,%d\n", state);
    return false;
  }
  cfgFreq = freq; cfgBw = bw; cfgSf = sf; cfgSync = sync;
  configured = true;
  Serial.printf("OK,CFG,%.4f,%.1f,%d,%d,0x%02X,%d\n", freq, bw, sf, cr, sync, preamble);
  return true;
}

static void handleLine(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;
  if (cmd == "PING") { Serial.println("PONG"); return; }
  if (cmd == "INFO") {
    Serial.printf("INFO,lora-sniffer,1,heltec_v3,sx1262,%s,%.4f,%.1f,%d,0x%02X,%lu,%lu\n", configured ? "listening" : "idle",
                  cfgFreq, cfgBw, cfgSf, cfgSync, (unsigned long)packets, (unsigned long)crcErrors);
    return;
  }
  if (cmd.startsWith("CFG,")) {
    float freq, bw; int sf, cr, preamble; char sync[12];
    if (sscanf(cmd.c_str() + 4, "%f,%f,%d,%d,%11[^,],%d", &freq, &bw, &sf, &cr, sync, &preamble) == 6) {
      long syncWord = strtol(sync, nullptr, 0);
      if (sf >= 5 && sf <= 12 && cr >= 5 && cr <= 8 && syncWord >= 0 && syncWord <= 0xFF && preamble >= 6 && preamble <= 65535) {
        applyConfig(freq, bw, sf, cr, (int)syncWord, preamble);
        return;
      }
    }
    Serial.println("ERR,CFG,bad");
    return;
  }
  Serial.println("ERR,unknown");
}

static void readPacket() {
  size_t len = radio.getPacketLength();  // must come before readData
  uint8_t buf[256];
  if (len == 0 || len > sizeof(buf)) { radio.startReceive(); return; }
  int state = radio.readData(buf, len);
  float rssi = radio.getRSSI(), snr = radio.getSNR(), ferr = radio.getFrequencyError();
  radio.startReceive();
  if (state == RADIOLIB_ERR_CRC_MISMATCH) { crcErrors++; return; }
  if (state != RADIOLIB_ERR_NONE) return;
  packets++;
  led(true);
  ledOffAt = millis() + 60;
  Serial.printf("RX,%lu,%.4f,%.1f,%u,0x%02X,%.1f,%.2f,%.0f,%u,", (unsigned long)millis(), cfgFreq, cfgBw, cfgSf, cfgSync, rssi, snr,
                ferr, (unsigned)len);
  for (size_t i = 0; i < len; i++) Serial.printf("%02x", buf[i]);
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_VEXT, OUTPUT);
  digitalWrite(PIN_VEXT, LOW);
  pinMode(PIN_LED, OUTPUT);
  led(false);
  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);
  delay(200);
  Serial.println("READY,lora-sniffer,1,heltec_v3,sx1262");
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') { handleLine(line); line = ""; }
    else if (c != '\r' && line.length() < 120) line += c;
  }
  if (rxFlag) { rxFlag = false; if (configured) readPacket(); }
  if (ledOffAt && (int32_t)(millis() - ledOffAt) >= 0) { led(false); ledOffAt = 0; }
  if (millis() - lastStat >= 10000) {
    lastStat = millis();
    Serial.printf("STAT,%lu,%lu,%lu\n", (unsigned long)millis(), (unsigned long)packets, (unsigned long)crcErrors);
  }
}
