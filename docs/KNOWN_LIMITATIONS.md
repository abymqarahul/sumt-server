# Known limitations (honest list)

## Licensing / anti-sharing
- **Clearing app data or reinstalling** deletes the Keystore key, so the app registers as a *new* installation ID. This is by design: the old licence is not lost, and the owner moves it with **Transfer** in the Admin app.
- **Rooted or hooked devices:** an attacker with root and Frida can patch the app to skip its local licence check. Server-side protections still hold: keys are one-time and bound to one installation, firmware and repair-data downloads need a valid signed request plus an ACTIVE licence, and revocation works. Client-side tamper resistance (R8, integrity checks, optional Play Integrity) raises the cost but cannot make it impossible. No app can.
- **Device cloning:** Keystore keys are hardware-backed on most phones and cannot be copied. On devices with only software Keystore (rare, old or emulators), a full-device clone could copy the key. The optional Play Integrity `enforce` mode mitigates this.
- **Play Integrity:** implemented (off / log / enforce) but **not validated**, because it needs a Google Cloud service account linked to a Play Console app. APKs distributed outside Play fail the *app* verdict, so only the *device* verdict is enforced.
- **Offline grace:** default 72 h. A revoked device keeps working offline until its grace period ends.
- Keystore **key attestation** certificate chains are not verified server-side yet (possible future hardening).

## Firmware / resources
- Files are stored on a single Railway Volume (one replica). For multi-replica scaling, move to S3/R2 object storage.
- Upload size limit is `MAX_UPLOAD_MB` (default 512 MB).

## Features from the reference APK that need owner input
- Proprietary data tables in the reference app (TCON "division" repair images, PMIC register profiles, Samsung VGH/VGL profiles, the merged ESP32 firmware) are **not copied**. SUMT provides the engines. Data must be your own or properly licensed, uploaded as resources.
- USB IR dongle and eMMC ISP bridge: the hardware model must be specified before a driver can be written.
- Per-SoC UART recovery command profiles must be validated on real boards before they are enabled.

## Not yet built (by agreed order)
- Customer app and Admin app (Android). They start after you send the Railway URL.
