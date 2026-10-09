/*
 * SECUREVAULT HSM v2 - MULTI-APPLICATION OFFLINE TOTP AUTHORITY
 *
 * Hardware: ESP32 Dev Module + SSD1306 (I2C 21/22) + DS3231
 * Transport: USB serial only. Wi-Fi/Bluetooth are never used.
 *
 * v2 changes:
 *   - 8 independent encrypted TOTP slots.
 *   - Android can provision a fresh secret into the next free slot.
 *   - Each protected Android application gets its own hardware slot.
 *   - Verification is explicitly bound to a slot: VERIFY_TOTP:<slot>:<code>
 *   - Android never receives a TOTP secret.
 *   - USB session timeout clears plaintext secret RAM.
 *   - OLED shows the selected application/slot and current TOTP.
 *
 * Commands:
 *   HELLO
 *   HEARTBEAT
 *   SYNC_TIME:<unix-time>
 *   GET_STATUS
 *   GET_SLOTS
 *   PROVISION_AUTO:<app-name>
 *   REMOVE_SLOT:<slot>
 *   SELECT_SLOT:<slot>
 *   VERIFY_TOTP:<slot>:<6-digit-code>
 *   SESSION_CLOSE
 *   LOCK
 *
 * Development PIN remains internal to this prototype so Android does not
 * need to know or transmit an HSM management PIN.
 */

#include <Arduino.h>
#include <Wire.h>
#include <Preferences.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <RTClib.h>
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "esp_system.h"

#define SDA_PIN 21
#define SCL_PIN 22
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define OLED_ADDRESS 0x3C

static const uint8_t MAX_SLOTS = 8;
static const size_t SALT_LEN = 16;
static const size_t KEY_LEN = 32;
static const size_t GCM_IV_LEN = 12;
static const size_t GCM_TAG_LEN = 16;
static const size_t SECRET_MAX_LEN = 64;
static const uint16_t PBKDF2_ITERATIONS = 12000;
static const uint32_t USB_SESSION_TIMEOUT_MS = 6000UL;
static const uint32_t RATE_LIMIT_MS = 180UL;
static const uint8_t MAX_TOTP_FAILURES = 5;
static const uint32_t TOTP_LOCKOUT_MS = 15000UL;
static const char* DEFAULT_PIN = "123456";

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
RTC_DS3231 rtc;
Preferences prefs;

struct VaultSlot {
  uint8_t active;
  char account[32];
  uint8_t vmkIv[GCM_IV_LEN];
  uint8_t encryptedVmk[KEY_LEN];
  uint8_t vmkTag[GCM_TAG_LEN];
  uint8_t secretIv[GCM_IV_LEN];
  uint8_t encryptedSecret[SECRET_MAX_LEN];
  uint8_t secretTag[GCM_TAG_LEN];
  uint8_t secretLen;
};

struct VaultStore {
  uint8_t initialized;
  uint8_t salt[SALT_LEN];
  uint8_t pinHash[32];
  VaultSlot slots[MAX_SLOTS];
};

VaultStore store;
uint8_t activeSlot = 0;
bool slotSelected = false;
bool hostConnected = false;
bool adminSession = false;
bool localUnlocked = false;
bool rtcOk = false;
uint8_t vmk[KEY_LEN];
char decryptedSecret[SECRET_MAX_LEN + 1];
uint32_t lastHeartbeatMs = 0;
uint32_t sessionExpiryMs = 0;
uint32_t lastCommandMs = 0;
uint8_t totpFailures = 0;
uint32_t totpLockoutUntil = 0;
uint32_t lastDisplayMs = 0;
String usbLine;

static void secureZero(void* p, size_t n) {
  volatile uint8_t* b = (volatile uint8_t*)p;
  while (n--) *b++ = 0;
}

static bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
  return diff == 0;
}

static void randomBytes(uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; i += 4) {
    uint32_t r = esp_random();
    size_t take = (n - i < 4) ? (n - i) : 4;
    memcpy(out + i, &r, take);
  }
}

static bool sha256Buffer(const uint8_t* data, size_t len, uint8_t out[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md(info, data, len, out) == 0;
}

static bool deriveKek(const char* pin, const uint8_t salt[SALT_LEN], uint8_t out[KEY_LEN]) {
  return mbedtls_pkcs5_pbkdf2_hmac_ext(
    MBEDTLS_MD_SHA256,
    (const unsigned char*)pin, strlen(pin), salt, SALT_LEN,
    PBKDF2_ITERATIONS, KEY_LEN, out) == 0;
}

static bool aesEncrypt(const uint8_t key[KEY_LEN], const uint8_t* plain, size_t len,
                       const uint8_t iv[GCM_IV_LEN], uint8_t* cipher, uint8_t tag[GCM_TAG_LEN]) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0) rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, iv,
                                                GCM_IV_LEN, nullptr, 0, plain, cipher,
                                                GCM_TAG_LEN, tag);
  mbedtls_gcm_free(&ctx);
  return rc == 0;
}

static bool aesDecrypt(const uint8_t key[KEY_LEN], const uint8_t* cipher, size_t len,
                       const uint8_t iv[GCM_IV_LEN], const uint8_t tag[GCM_TAG_LEN], uint8_t* plain) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0) rc = mbedtls_gcm_auth_decrypt(&ctx, len, iv, GCM_IV_LEN, nullptr, 0,
                                               tag, GCM_TAG_LEN, cipher, plain);
  mbedtls_gcm_free(&ctx);
  return rc == 0;
}

static int base32Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

static size_t base32Decode(const char* in, uint8_t* out, size_t maxOut) {
  uint32_t buffer = 0;
  int bits = 0;
  size_t n = 0;
  for (size_t i = 0; in[i]; ++i) {
    if (in[i] == '=' || in[i] == ' ' || in[i] == '\r' || in[i] == '\n') continue;
    int v = base32Value(in[i]);
    if (v < 0) return 0;
    buffer = (buffer << 5) | (uint32_t)v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (n >= maxOut) return 0;
      out[n++] = (uint8_t)((buffer >> bits) & 0xFF);
    }
  }
  return n;
}

static bool generateTotp(uint32_t epoch, char output[7]) {
  if (!decryptedSecret[0]) return false;
  uint8_t key[128];
  size_t keyLen = base32Decode(decryptedSecret, key, sizeof(key));
  if (!keyLen) return false;
  uint64_t counter = epoch / 30ULL;
  uint8_t msg[8];
  for (int i = 7; i >= 0; --i) { msg[i] = (uint8_t)(counter & 0xFF); counter >>= 8; }

  uint8_t hmac[20];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (!info || mbedtls_md_setup(&ctx, info, 1) != 0) { mbedtls_md_free(&ctx); secureZero(key, sizeof(key)); return false; }
  bool ok = mbedtls_md_hmac_starts(&ctx, key, keyLen) == 0 &&
            mbedtls_md_hmac_update(&ctx, msg, sizeof(msg)) == 0 &&
            mbedtls_md_hmac_finish(&ctx, hmac) == 0;
  mbedtls_md_free(&ctx);
  secureZero(key, sizeof(key));
  if (!ok) return false;
  int off = hmac[19] & 0x0F;
  uint32_t binary = ((uint32_t)(hmac[off] & 0x7F) << 24) |
                    ((uint32_t)hmac[off + 1] << 16) |
                    ((uint32_t)hmac[off + 2] << 8) |
                    hmac[off + 3];
  snprintf(output, 7, "%06lu", (unsigned long)(binary % 1000000UL));
  secureZero(hmac, sizeof(hmac));
  return true;
}

static uint32_t unixNow() { return rtcOk ? rtc.now().unixtime() : 0; }
static bool timeReached(uint32_t a, uint32_t b) { return (int32_t)(a - b) >= 0; }

static bool saveStore() {
  prefs.begin("svault2", false);
  size_t n = prefs.putBytes("store", &store, sizeof(store));
  prefs.end();
  return n == sizeof(store);
}

static bool loadStore() {
  memset(&store, 0, sizeof(store));
  prefs.begin("svault2", true);
  size_t n = prefs.getBytes("store", &store, sizeof(store));
  prefs.end();
  return n == sizeof(store) && store.initialized == 1;
}

static int freeSlot() {
  for (int i = 0; i < MAX_SLOTS; ++i) if (!store.slots[i].active) return i;
  return -1;
}

static int activeSlotCount() {
  int n = 0;
  for (int i = 0; i < MAX_SLOTS; ++i) if (store.slots[i].active) ++n;
  return n;
}

static bool decryptSlot(uint8_t slot) {
  if (slot >= MAX_SLOTS || !store.slots[slot].active) return false;
  uint8_t kek[KEY_LEN];
  if (!deriveKek(DEFAULT_PIN, store.salt, kek)) return false;

  uint8_t candidateVmk[KEY_LEN];
  if (!aesDecrypt(kek, store.slots[slot].encryptedVmk, KEY_LEN,
                  store.slots[slot].vmkIv, store.slots[slot].vmkTag, candidateVmk)) {
    secureZero(kek, sizeof(kek));
    return false;
  }

  uint8_t plain[SECRET_MAX_LEN];
  bool ok = aesDecrypt(candidateVmk, store.slots[slot].encryptedSecret, SECRET_MAX_LEN,
                       store.slots[slot].secretIv, store.slots[slot].secretTag, plain);
  if (ok) {
    memcpy(vmk, candidateVmk, KEY_LEN);
    memset(decryptedSecret, 0, sizeof(decryptedSecret));
    uint8_t n = store.slots[slot].secretLen;
    if (n > SECRET_MAX_LEN) n = SECRET_MAX_LEN;
    memcpy(decryptedSecret, plain, n);
    decryptedSecret[n] = '\0';
    activeSlot = slot;
    slotSelected = true;
    localUnlocked = true;
  }
  secureZero(plain, sizeof(plain));
  secureZero(candidateVmk, sizeof(candidateVmk));
  secureZero(kek, sizeof(kek));
  return ok;
}

static String generateBase32Secret() {
  static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  uint8_t bytes[20];
  randomBytes(bytes, sizeof(bytes));
  String out;
  out.reserve(32);
  uint32_t buffer = 0;
  int bits = 0;
  for (size_t i = 0; i < sizeof(bytes); ++i) {
    buffer = (buffer << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) out += alphabet[(buffer << (5 - bits)) & 31];
  secureZero(bytes, sizeof(bytes));
  return out;
}

static bool createSlot(uint8_t index, const String& account, const String& secret) {
  if (index >= MAX_SLOTS || store.slots[index].active) return false;
  if (secret.length() < 16 || secret.length() > SECRET_MAX_LEN) return false;
  uint8_t kek[KEY_LEN], slotVmk[KEY_LEN], plain[SECRET_MAX_LEN];
  if (!deriveKek(DEFAULT_PIN, store.salt, kek)) return false;
  memset(&store.slots[index], 0, sizeof(VaultSlot));
  VaultSlot& s = store.slots[index];
  s.active = 1;
  strncpy(s.account, account.c_str(), sizeof(s.account) - 1);
  s.secretLen = (uint8_t)secret.length();
  randomBytes(slotVmk, KEY_LEN);
  randomBytes(s.vmkIv, GCM_IV_LEN);
  randomBytes(s.secretIv, GCM_IV_LEN);
  memset(plain, 0, sizeof(plain));
  memcpy(plain, secret.c_str(), secret.length());
  bool ok = aesEncrypt(kek, slotVmk, KEY_LEN, s.vmkIv, s.encryptedVmk, s.vmkTag) &&
            aesEncrypt(slotVmk, plain, SECRET_MAX_LEN, s.secretIv, s.encryptedSecret, s.secretTag);
  secureZero(kek, sizeof(kek));
  secureZero(slotVmk, sizeof(slotVmk));
  secureZero(plain, sizeof(plain));
  if (!ok) { memset(&s, 0, sizeof(s)); return false; }
  if (!saveStore()) { memset(&s, 0, sizeof(s)); return false; }
  return true;
}

static void lockVault() {
  localUnlocked = false;
  slotSelected = false;
  hostConnected = false;
  adminSession = false;
  activeSlot = 0;
  secureZero(vmk, sizeof(vmk));
  secureZero(decryptedSecret, sizeof(decryptedSecret));
  updateDisplay();
}

static void sendResponse(const String& s) { Serial.println(s); }
static void sendSV2(const String& s) { Serial.println("SV2|" + s); }

static void displayCentered(const String& text, int y, uint8_t size) {
  display.setTextSize(size);
  int16_t x1, y1; uint16_t w, h;
  display.getTextBounds(text, 0, y, &x1, &y1, &w, &h);
  int x = (128 - (int)w) / 2; if (x < 0) x = 0;
  display.setCursor(x, y); display.print(text);
}

static void updateDisplay() {
  display.clearDisplay(); display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1); display.setCursor(0, 0); display.print("SECUREVAULT HSM");
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);

  if (!hostConnected || !localUnlocked || !slotSelected) {
    displayCentered("LOCKED", 22, 2);
    displayCentered(hostConnected ? "SELECT APP SLOT" : "WAITING FOR USB", 46, 1);
    display.display(); return;
  }
  if (!rtcOk) { displayCentered("RTC ERROR", 22, 2); displayCentered("CHECK DS3231", 48, 1); display.display(); return; }

  char code[7];
  if (!generateTotp(unixNow(), code)) { displayCentered("TOTP ERROR", 24, 2); display.display(); return; }
  display.setTextSize(2); display.setCursor(15, 15);
  for (int i = 0; i < 6; ++i) { display.print(code[i]); if (i == 2) display.print(" "); }
  display.setTextSize(1); display.setCursor(4, 39);
  display.print("SLOT "); display.print(activeSlot + 1); display.print("  "); display.print(store.slots[activeSlot].account);
  uint32_t remain = 30 - (unixNow() % 30);
  display.setCursor(4, 51); display.print("EXPIRES "); display.print(remain); display.print("s");
  display.display();
}

static void handleHello() {
  if (!store.initialized) { sendResponse("HSM_UNLOCK_FAILED"); return; }
  hostConnected = true; adminSession = true; lastHeartbeatMs = millis(); sessionExpiryMs = millis() + USB_SESSION_TIMEOUT_MS;
  sendResponse("USB_HOST_READY");
  sendSV2("VERSION|4"); sendSV2("TRANSPORT|USB_SERIAL_ONLY"); sendSV2("SECURITY|ESP32_TOTP_AUTHORITY");
  sendSV2("SECRET|NEVER_EXPORTED"); sendSV2("SLOTS|8"); sendSV2("STATUS|USB_HOST_READY"); sendSV2("END");
  updateDisplay();
}

static void handleHeartbeat() {
  if (!hostConnected) { sendResponse("USB_NOT_CONNECTED"); return; }
  lastHeartbeatMs = millis(); sessionExpiryMs = millis() + USB_SESSION_TIMEOUT_MS; sendResponse("HEARTBEAT_OK");
}

static void handleSyncTime(const String& value) {
  if (!hostConnected || !adminSession || !rtcOk) { sendResponse("SYNC_TIME_INVALID"); return; }
  uint32_t epoch = strtoul(value.c_str(), nullptr, 10);
  if (epoch < 1700000000UL) { sendResponse("SYNC_TIME_INVALID"); return; }
  rtc.adjust(DateTime(epoch));
  sendResponse("TIME_SYNCED");
  updateDisplay();
}

static void handleGetStatus() {
  sendSV2(String("STATUS|READY"));
  sendSV2(String("USB_HOST_CONNECTED:") + (hostConnected ? "YES" : "NO"));
  sendSV2(String("HSM_UNLOCKED:") + (localUnlocked ? "YES" : "NO"));
  sendSV2("TRANSPORT|USB_SERIAL_ONLY"); sendSV2("TOTP_EXPORT|DISABLED");
  sendSV2("WIFI|OFF"); sendSV2("BLUETOOTH|OFF"); sendSV2(String("RTC:") + (rtcOk ? "OK" : "ERROR"));
  sendSV2("TOTP_STEP_SECONDS:30"); sendSV2("MAX_SLOTS:8"); sendSV2("END");
}

static void handleGetSlots() {
  if (!hostConnected || !adminSession) { sendResponse("USB_NOT_CONNECTED"); return; }
  sendResponse("SLOTS:" + String(activeSlotCount()));
  for (int i = 0; i < MAX_SLOTS; ++i) {
    if (store.slots[i].active) sendResponse("SLOT:" + String(i + 1) + ":" + String(store.slots[i].account));
  }
}

static void handleProvisionAuto(const String& payload) {
  if (!hostConnected || !adminSession) { sendResponse("SLOT_ERROR:USB_NOT_CONNECTED"); return; }
  String name = payload;
  name.trim();
  if (!name.length()) { sendResponse("SLOT_ERROR:BAD_REQUEST"); return; }
  int idx = freeSlot();
  if (idx < 0) { sendResponse("SLOT_ERROR:ALL_SLOTS_FULL"); return; }

  // The hardware generates the credential locally. The TOTP secret never crosses USB.
  String secret = generateBase32Secret();
  bool ok = createSlot((uint8_t)idx, name, secret);
  if (secret.length() > 0) memset(secret.begin(), 0, secret.length());
  if (!ok) { sendResponse("SLOT_ERROR:PROVISION_FAILED"); return; }
  sendResponse("SLOT_CREATED:" + String(idx + 1) + ":" + name);
}


static void handleRemoveSlot(uint8_t slot) {
  if (!hostConnected || !adminSession) { sendResponse("SLOT_ERROR:USB_NOT_CONNECTED"); return; }
  if (slot >= MAX_SLOTS || !store.slots[slot].active) { sendResponse("SLOT_ERROR:INVALID_SLOT"); return; }
  memset(&store.slots[slot], 0, sizeof(VaultSlot));
  saveStore();
  if (slotSelected && activeSlot == slot) { localUnlocked = false; slotSelected = false; secureZero(decryptedSecret, sizeof(decryptedSecret)); }
  sendResponse("SLOT_REMOVED:" + String(slot + 1));
  updateDisplay();
}

static void handleSelectSlot(uint8_t slot) {
  if (!hostConnected || !adminSession) { sendResponse("USB_NOT_CONNECTED"); return; }
  if (slot >= MAX_SLOTS || !store.slots[slot].active) { sendResponse("SLOT_ERROR:INVALID_SLOT"); return; }
  if (!decryptSlot(slot)) { sendResponse("SLOT_ERROR:DECRYPT_FAILED"); return; }
  lastHeartbeatMs = millis(); sessionExpiryMs = millis() + USB_SESSION_TIMEOUT_MS;
  sendResponse("SLOT_SELECTED:" + String(slot + 1));
  updateDisplay();
}

static bool totpLocked() {
  if (!totpLockoutUntil) return false;
  if (timeReached(millis(), totpLockoutUntil)) { totpLockoutUntil = 0; totpFailures = 0; return false; }
  return true;
}

static void handleVerifyTotp(uint8_t slot, const String& candidate) {
  if (!hostConnected || !adminSession) { sendResponse("USB_NOT_CONNECTED"); return; }
  if (slot >= MAX_SLOTS || !store.slots[slot].active) { sendResponse("TOTP_INVALID"); return; }
  if (totpLocked()) { sendResponse("TOTP_RATE_LOCKED:15"); return; }

  // Strict application -> slot binding: VERIFY_TOTP may never select or
  // decrypt a different slot. SELECT_SLOT must have established the active
  // hardware slot for this authentication attempt first.
  if (!slotSelected || activeSlot != slot || !localUnlocked) {
    sendResponse("TOTP_INVALID_SLOT");
    return;
  }
  char expected[7]; bool valid = false; uint32_t now = unixNow();
  const int offsets[] = {-30, 0, 30};
  for (int i = 0; i < 3; ++i) {
    int64_t t = (int64_t)now + offsets[i]; if (t < 0) t = 0;
    if (generateTotp((uint32_t)t, expected) && candidate == String(expected)) { valid = true; break; }
  }
  lastHeartbeatMs = millis(); sessionExpiryMs = millis() + USB_SESSION_TIMEOUT_MS;
  if (valid) { totpFailures = 0; sendResponse("TOTP_VALID"); }
  else { if (++totpFailures >= MAX_TOTP_FAILURES) { totpFailures = 0; totpLockoutUntil = millis() + TOTP_LOCKOUT_MS; sendResponse("TOTP_RATE_LOCKED:15"); } else sendResponse("TOTP_INVALID"); }
}

static void handleCommand(String cmd) {
  cmd.trim(); if (!cmd.length()) return;
  uint32_t now = millis(); if (now - lastCommandMs < RATE_LIMIT_MS) { sendResponse("RATE_LIMITED"); return; }
  lastCommandMs = now;

  if (cmd == "HELLO") { handleHello(); return; }
  if (cmd == "HEARTBEAT") { handleHeartbeat(); return; }
  if (cmd == "GET_STATUS") { handleGetStatus(); return; }
  if (cmd == "GET_SLOTS") { handleGetSlots(); return; }
  if (cmd.startsWith("PROVISION_AUTO:")) { handleProvisionAuto(cmd.substring(15)); return; }
  if (cmd.startsWith("REMOVE_SLOT:")) { int s = cmd.substring(12).toInt() - 1; if (s >= 0) handleRemoveSlot((uint8_t)s); else sendResponse("SLOT_ERROR:INVALID_SLOT"); return; }
  if (cmd.startsWith("SELECT_SLOT:")) { int s = cmd.substring(12).toInt() - 1; if (s >= 0) handleSelectSlot((uint8_t)s); else sendResponse("SLOT_ERROR:INVALID_SLOT"); return; }
  if (cmd.startsWith("VERIFY_TOTP:")) {
    String p = cmd.substring(12); int a = p.indexOf(':');
    if (a <= 0) { sendResponse("TOTP_INVALID"); return; }
    int s = p.substring(0, a).toInt() - 1; String code = p.substring(a + 1);
    if (s < 0) { sendResponse("TOTP_INVALID"); return; }
    handleVerifyTotp((uint8_t)s, code); return;
  }
  if (cmd == "SESSION_CLOSE" || cmd == "LOCK") { lockVault(); sendResponse("LOCKED"); return; }
  if (cmd == "GET_TOTP") { sendResponse("TOTP_EXPORT_DISABLED"); return; }
  if (cmd.startsWith("SYNC_TIME:")) { handleSyncTime(cmd.substring(10)); return; }
  sendResponse("INVALID_COMMAND");
}

static void serviceSerial() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') { if (usbLine.length()) { handleCommand(usbLine); usbLine = ""; } }
    else if (c != '\r') { if (usbLine.length() < 512) usbLine += c; else usbLine = ""; }
  }
}

static void initializeStore() {
  if (loadStore()) return;
  memset(&store, 0, sizeof(store));
  randomBytes(store.salt, SALT_LEN);
  sha256Buffer((const uint8_t*)DEFAULT_PIN, strlen(DEFAULT_PIN), store.pinHash);
  store.initialized = 1;
  saveStore();
}

void setup() {
  Serial.begin(115200); delay(300);
  Wire.begin(SDA_PIN, SCL_PIN);
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) while (true) delay(1000);
  rtcOk = rtc.begin();
  if (rtcOk && rtc.lostPower()) rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
  initializeStore();
  lockVault();
  display.clearDisplay(); display.setTextColor(SSD1306_WHITE);
  displayCentered("SECUREVAULT HSM", 10, 1); displayCentered("LOCKED", 27, 2); displayCentered("WAITING FOR USB", 51, 1); display.display();
  Serial.println("SV2|BOOT|READY"); Serial.println("SV2|SECURITY|MULTI_SLOT"); Serial.println("SV2|SECRETS|NEVER_EXPORTED"); Serial.println("SV2|END");
}

void loop() {
  serviceSerial();
  uint32_t now = millis();
  if (hostConnected && (now - lastHeartbeatMs > USB_SESSION_TIMEOUT_MS || timeReached(now, sessionExpiryMs))) {
    lockVault(); sendResponse("USB_SESSION_EXPIRED");
  }
  if (localUnlocked && rtcOk && now - lastDisplayMs >= 1000UL) { lastDisplayMs = now; updateDisplay(); }
  delay(5);
}
