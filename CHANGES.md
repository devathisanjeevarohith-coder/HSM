# SecureVault USB/HSM Lifecycle Fixes

## Android
- MainActivity is the only foreground component that initiates USB permission.
- USB attach detection in SecureVaultUsbManager never opens a background permission prompt.
- LockOverlayActivity and ApplicationVaultActivity only observe the shared USB manager.
- Permission requests are guarded against duplicate requests.
- Retry does not clear an active permission request.
- App-to-slot selection is retained and TOTP verification is rejected unless the requested slot matches the selected slot.
- Android no longer generates a TOTP secret during provisioning.
- Disabling an app preserves its persistent app-to-slot mapping so re-enabling reuses the same hardware slot.
- Existing mappings are counted separately from currently enabled protected apps so the 8-slot hardware limit is enforced.

## ESP32
- `PROVISION_AUTO:<app-name>` now causes the ESP32 to generate the TOTP secret locally.
- The generated secret is encrypted into the hardware slot and is never transmitted to Android.
- Existing `PROVISION_AUTO:<app-name>:<secret>` provisioning is intentionally removed from this firmware revision.

Additional verification:
- Included the ESP32 HSM firmware explicitly at the package root and hardware/ directory.
- Tightened ESP32 VERIFY_TOTP so it cannot switch/decrypt another slot during verification.
- Added firmware README and final package README.


## Control center and diagnostics
- Added SettingsActivity as the central operational control center.
- Added HSM status details, user-triggered reconnect/disconnect and a guided connection-test action.
- Added system check covering App monitoring, lock overlay, HSM state and 8-slot capacity.
- Added View/Export/Clear USB diagnostic log controls using the existing app-private FileProvider.
- Added recovery actions for refreshing Android-side application configuration and revoking active unlock sessions.
- Added Home Settings entry and compact security-setup status summary.
- Moved Accessibility/overlay setup entry points into Settings instead of duplicating them on Home.

## USB transport robustness
- USB manager initialization no longer auto-requests USB permission; Connect ESP32 remains user-triggered.
- Added a dedicated serial-read executor so disconnect/reconnect cannot be starved behind the continuous read loop.
- Added ESP32 boot-settle delay before HELLO and finite handshake/time-sync timeouts.
- Added diagnostic capture of driver, port, serial parameters, DTR/RTS and protocol events.
- TOTP verification values are redacted from logs.
