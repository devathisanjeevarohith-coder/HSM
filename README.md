SecureVault Locker

A hardware-backed app locker for Android. Protected apps can only be opened after the user types a 6-digit TOTP code that is generated and displayed on a physical ESP32 HSM, connected to the phone over USB-OTG. The TOTP secret never leaves the ESP32, and the Android app has no internet permission.

How it works
 Protected app opened
        │
        ▼
 AppMonitorService (Accessibility Service) detects the foreground app
        │
        ▼
 LockOverlayActivity covers the app and asks for a code
        │
        ▼
 User reads the 6-digit code on the ESP32 OLED and types it in
        │
        ▼
 Android ──USB serial──►  SELECT_SLOT:<n>  →  VERIFY_TOTP:<n>:<code>  ──► ESP32 HSM
        ◄──────────────  OK / TOTP_INVALID / TOTP_RATE_LOCKED  ◄──────
        │
        ▼
 Valid → temporary unlock session (15 s launch grace period)
Features
Per-app hardware protection: each protected app is bound to its own persistent HSM slot (max 8 slots).
On-device secret generation: PROVISION_AUTO:<app-name> makes the ESP32 generate the TOTP secret itself. Android never generates, receives, or stores it.
Slot binding: VERIFY_TOTP is only accepted for the slot chosen with SELECT_SLOT; any other slot is rejected.
Encrypted storage on the HSM: slot secrets are encrypted with AES-256-GCM (key derived with PBKDF2-HMAC-SHA256) in ESP32 flash. GET_TOTP export is disabled.
Brute-force protection: command rate limiting plus a 15-second lockout after repeated wrong codes.
Offline by design: no INTERNET permission; communication is USB Host/OTG only.
Control center (Settings): HSM status, user-triggered connect/reconnect/disconnect, guided USB test, system readiness check, session revocation, and diagnostic log view/export/clear.
Diagnostics: USB handshake, permission, driver/port and timing events are logged locally; TOTP codes are redacted and secrets are never logged.
Project structure
SecureVaultLocker_FINAL_PROJECT/
├── app/                                  Android app (Kotlin, Compose + Views)
│   └── src/main/java/com/android/securevaultlocker/
│       ├── locker/service/
│       │   ├── AppMonitorService.kt          Accessibility service, lock/slot mappings, sessions
│       │   ├── SecureVaultUsbManager.kt      USB permission, serial session, HSM protocol
│       │   └── SecureVaultDiagnosticLogger.kt
│       ├── locker/ui/
│       │   ├── MainActivity.kt               Home, USB connect (owns permission flow)
│       │   ├── ApplicationVaultActivity.kt   Choose and manage protected apps
│       │   ├── LockOverlayActivity.kt        TOTP prompt shown over locked apps
│       │   └── SettingsActivity.kt           Control center
│       └── ui/theme/                         Compose theme
├── hardware/SecureVault_HSM_MultiSlot_v2.ino ESP32 firmware
├── SecureVault_HSM_MultiSlot_v2.ino          Top-level copy (identical)
├── SecureVault_HSM_MultiSlot_FINAL.ino       Top-level copy (identical)
├── SHA256_FIRMWARE.txt                       Firmware checksum
├── CHANGES.md / README_FINAL.md / ESP32_Firmware_README.txt
└── build.gradle.kts, settings.gradle.kts, gradle/
Requirements

Hardware

Part	Notes
ESP32 Dev Module	Connects to the phone by USB
SSD1306 OLED (128×64, I²C, addr 0x3C)	Shows the live TOTP code
DS3231 RTC	Keeps accurate time for TOTP
Android phone with USB Host/OTG	Android 8.0+ (API 26+)
USB-OTG cable	Phone ↔ ESP32

Wiring (I²C): SDA → GPIO 21, SCL → GPIO 22, plus 3.3 V and GND for the OLED and RTC.

Software

Android Studio (recent version; the project uses AGP 9.2.1, Gradle 9.4.1, Kotlin 2.2.10, compileSdk/targetSdk 37)
Arduino IDE with ESP32 board support
Arduino libraries: Adafruit GFX, Adafruit SSD1306, RTClib (mbedtls and Preferences ship with the ESP32 core)
Android dependency: usb-serial-for-android 3.11.0 (resolved via JitPack, so make sure maven { url = uri("https://jitpack.io") } is in your repositories)
Setup
1. Flash the ESP32
Open hardware/SecureVault_HSM_MultiSlot_v2.ino in Arduino IDE.
Select ESP32 Dev Module and the correct port.
Upload.
(Optional) verify the file against SHA256_FIRMWARE.txt:
bash
   sha256sum hardware/SecureVault_HSM_MultiSlot_v2.ino

Flash the firmware before testing the Android build; the two must match.

2. Build and install the app
Open the SecureVaultLocker_FINAL_PROJECT folder in Android Studio and let Gradle sync.
Run on a physical device (USB Host is required, so emulators won't work), or build an APK from Build → Build APK(s).
3. First-time configuration
Open the app and tap Connect ESP32. Approve the USB permission prompt (it is only requested when you tap the button).
Go to Settings and enable:
the SecureVault App Interceptor accessibility service
Display over other apps (overlay permission)
Open Application Vault, pick an app to protect, and provision it (the ESP32 assigns a slot and generates the secret).
Open the protected app, then enter the 6-digit code shown on the OLED.
HSM serial protocol (115200 baud, newline-terminated)
Command	Purpose
HELLO	Handshake / protocol info
HEARTBEAT	Keep-alive
GET_STATUS	HSM status
GET_SLOTS	List provisioned slots
SYNC_TIME:<epoch>	Set RTC from the phone
PROVISION_AUTO:<app-name>	Generate a TOTP secret on the ESP32 in a free slot
SELECT_SLOT:<slot>	Select the slot for the next verification
VERIFY_TOTP:<slot>:<code>	Verify a 6-digit code (30 s step, ±1 step tolerance)
REMOVE_SLOT:<slot>	Delete a slot
SESSION_CLOSE / LOCK	Lock the HSM session
GET_TOTP	Always returns TOTP_EXPORT_DISABLED

Typical responses include TOTP_INVALID, TOTP_RATE_LOCKED:15, RATE_LIMITED, SLOT_ERROR:INVALID_SLOT, TIME_SYNCED, HEARTBEAT_OK, and LOCKED.

Known limitations (prototype)
Fixed development PIN: the firmware derives its storage key from a compiled-in default PIN (123456). Anyone with the firmware source and physical access to the flash could decrypt slots. Use a per-device PIN or secure-boot/flash encryption before real use.
Accessibility-based locking: the lock relies on an Android accessibility service. It can be disabled by the user or force-stopped by the OS, and it is not a substitute for OS-level security.
Unlock grace period: an unlocked app stays accessible for a short window (15 s launch grace) and until the session is revoked.
Release build: code shrinking/obfuscation is currently disabled in app/build.gradle.kts.
The firmware is duplicated in three places (identical); keep hardware/ as the source of truth.
Documentation
CHANGES.md: USB lifecycle, firmware and control-center changes
README_FINAL.md: package notes
ESP32_Firmware_README.txt: firmware quick reference
