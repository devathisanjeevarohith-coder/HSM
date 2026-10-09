# SecureVault — USB + HSM Final Build

This package contains both sides of the SecureVault system:

- `app/` — Android SecureVault Locker
- `hardware/SecureVault_HSM_MultiSlot_v2.ino` — ESP32 HSM firmware
- `SecureVault_HSM_MultiSlot_v2.ino` — clearly visible top-level firmware copy

## USB lifecycle

MainActivity owns the foreground USB permission flow. AppMonitorService and LockOverlayActivity only observe the shared USB manager.

## HSM credential generation

The ESP32 generates each TOTP secret locally during `PROVISION_AUTO:<app-name>`. The Android application does not generate or receive the secret.

## Slot binding

Each protected application has one persistent hardware slot. The ESP32 requires `SELECT_SLOT:<slot>` before `VERIFY_TOTP:<same-slot>:<code>` and rejects verification for a different slot.

Maximum hardware slots: 8.

## Flashing

Use `SecureVault_HSM_MultiSlot_v2.ino` in Arduino IDE with the ESP32 Dev Module selected. The OLED uses GPIO 21 (SDA) and GPIO 22 (SCL).


## SecureVault control center

Settings now centralizes operational controls without changing the core TOTP/slot security model:
- HSM status and protocol metadata
- user-triggered connection/reconnect/disconnect
- guided USB connection test
- App monitoring and lock-overlay setup status
- Application Vault shortcut and configuration refresh
- active unlock-session revocation
- local USB diagnostic log viewing/export/clear
- system readiness check
- About / architecture information

The Home screen remains focused on everyday status and the Application Vault. USB permission is user-triggered rather than automatically requested merely by opening the app.

## Diagnostics and recovery

The Android USB manager records device identity, permission state, driver/port selection, serial configuration, handshake TX/RX activity, state transitions, timeouts and errors. TOTP codes are redacted from diagnostic logs, and TOTP secrets are never logged.

The serial reader runs on its own executor so connection recovery cannot be blocked by the continuous read loop. The HSM handshake waits briefly after opening the serial port to allow ESP32 USB-serial reset/boot settling, then sends HELLO and applies a finite handshake timeout.
