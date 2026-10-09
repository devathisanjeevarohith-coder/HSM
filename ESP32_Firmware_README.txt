SecureVault ESP32 HSM Firmware
==============================

Firmware:
  hardware/SecureVault_HSM_MultiSlot_v2.ino

Hardware:
  ESP32 Dev Module
  SSD1306 OLED I2C: SDA GPIO21, SCL GPIO22
  DS3231 RTC

Transport:
  USB serial only

Important:
  Flash this .ino to the ESP32 before testing the matching Android build.
  This firmware generates TOTP secrets on the ESP32 during PROVISION_AUTO.
  Android never generates, receives, or stores the TOTP secret.

Provisioning command:
  PROVISION_AUTO:<app-name>

Authentication:
  SELECT_SLOT:<slot>
  VERIFY_TOTP:<same-slot>:<6-digit-code>

VERIFY_TOTP is strictly bound to the currently selected hardware slot.
A verification request for any other slot is rejected.

Maximum hardware slots: 8
