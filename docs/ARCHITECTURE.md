# SUMT — Independent architecture proposal

```
 ┌──────────────── Customer app "SUMT" (com.sumt.terminal) ────────────────┐
 │ UI: Jetpack Compose + Material 3, 5 themes, reduced-motion aware        │
 │ core-license  : Keystore EC P-256 key, signed requests, licence token  │
 │ core-hw       : UsbSerial, CH341A, BT-SPP, WiFi-socket transports      │
 │ core-files    : SAF import/export, resource cache (SHA-256 verified)   │
 │ tools/*       : recovery, esp32, programmer, edid, pmic, emmc, ir, adb  │
 │ ai/*          : rule engine + knowledge base, ML Kit OCR, PDF reports   │
 └──────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTPS (device-signed requests)
 ┌──────────────── Backend (Railway) ┴─────────────────────────────────────┐
 │ Fastify 5 + TypeScript, Prisma 6, PostgreSQL 16                         │
 │ /installations  /activations  /licenses  /resources (firmware/OTA)      │
 │ /admin/*  (JWT access + rotating refresh, roles, audit)                 │
 │ Ed25519-signed licence tokens (offline grace)                           │
 │ Resource storage: Railway Volume (/data) — SHA-256 + size recorded      │
 └──────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTPS (admin JWT)
 ┌──────────────── Admin app "SUMT Admin" (com.sumt.admin) ────────────────┐
 │ Login, dashboard, installations, key generation, revoke/block/reset,   │
 │ expiry, transfer, firmware/resource upload & publishing, audit logs    │
 └─────────────────────────────────────────────────────────────────────────┘
```

## Activation & anti-sharing (summary)
1. First launch: the app generates a non-exportable **EC P-256 key in the Android Keystore** (StrongBox if available) and registers its public key with a proof-of-possession signature.
2. The server assigns an installation ID such as `SUMT-10001` from a Postgres sequence, so IDs never collide.
3. The admin generates a key bound to that installation, for example `SUMT-7K2Q-…`, with 80 bits of entropy. Only its HMAC-SHA256 (with a server pepper) is stored.
4. The customer enters the key. The request is **signed by the device key**. The server consumes the key with one atomic `UPDATE … WHERE consumed_at IS NULL RETURNING` inside a transaction, so of two simultaneous requests only one wins.
5. The server returns an **Ed25519-signed licence token** (installation, key fingerprint, expiry, offline-grace deadline). The app verifies it with the embedded *public* key, and verification only works on the device whose key fingerprint matches.
6. A copied APK creates a new Keystore key, which means a new installation ID with PENDING status. The old key is already consumed and bound to the other installation, so it fails.

## Firmware / resource updates
The admin uploads a file and sets its kind (FIRMWARE, REPAIR_DATA, WIRING_DIAGRAM, KNOWLEDGE_BASE, APP_UPDATE), target hardware, version code and channel. The server computes the SHA-256 and stores the file on the volume. Customer apps call `GET /api/v1/resources` (signed, licensed devices only) at launch and every 12 h (WorkManager), compare version codes, download through a short-lived ticket URL, verify the SHA-256, then cache the file. Publishing or unpublishing is instant.

## Local AI (Android phase)
A rule-based diagnostic engine plus a versioned JSON knowledge base (delivered as a `KNOWLEDGE_BASE` resource), ML Kit on-device text and barcode recognition for the board scanner, and local PDF reports through `PdfDocument`. No mandatory cloud or LLM. An optional local LLM will be evaluated later and is never required.
