# SUMT API v1

Base: `https://<railway-domain>/api/v1`. JSON throughout. Errors use the shape `{ statusCode, error: "CODE", message, details? }`.

## Device authentication (customer app)

**Key:** Android Keystore EC P-256, `KeyGenParameterSpec` with `PURPOSE_SIGN`, digest SHA-256, StrongBox when available. The key is never exportable.

**Signed request headers:**
| Header | Value |
|---|---|
| `X-SUMT-Installation` | installation UUID (from register) |
| `X-SUMT-Timestamp` | `System.currentTimeMillis()` |
| `X-SUMT-Nonce` | 16–64 chars `[A-Za-z0-9_-]`, random per request |
| `X-SUMT-Signature` | base64 of `SHA256withECDSA` (DER) over the canonical string |

Canonical string (joined with `\n`):
```
SUMT-v1
<METHOD>
<path + query exactly as sent, e.g. /api/v1/licenses/verify>
<timestamp>
<nonce>
<hex sha256 of the exact body bytes; sha256("") for GET>
```
Requests outside ±5 min of server time are rejected with `CLOCK_SKEW`. A reused nonce is rejected with `REPLAY_DETECTED`.

### `POST /installations/register` (unsigned, proof-of-possession)
```json
{ "publicKey": "<SPKI DER base64>", "timestamp": "1763...", "nonce": "...",
  "signature": "<sign('SUMT-register-v1\\n'+publicKey+'\\n'+timestamp+'\\n'+nonce)>",
  "device": { "manufacturer": "Xiaomi", "model": "Redmi Note 13", "sdkInt": 34, "appVersionName": "1.0.0", "appVersionCode": 1 },
  "integrityToken": "optional Play Integrity token, nonce = base64url(sha256(SPKI))" }
```
Returns `201` (new) or `200` (same key seen before) with a **LicenseView**:
```json
{ "created": true, "installationId": "uuid", "displayId": "SUMT-10001", "status": "PENDING",
  "plan": null, "expiresAt": null, "licenseToken": null, "offlineGraceUntil": null,
  "serverTime": "...", "message": "Activation required..." }
```
`status` is one of PENDING | ACTIVE | EXPIRED | REVOKED | BLOCKED.

### `POST /activations/consume` (signed)
Body: `{ "activationKey": "SUMT-XXXX-XXXX-XXXX-XXXX" }` (case and spaces are ignored).
Success returns a LicenseView with `status: ACTIVE` and a `licenseToken`.
Errors: `INVALID_KEY` 400 (unknown, or belongs to another installation), `KEY_ALREADY_USED` 409, `KEY_EXPIRED` 400, `KEY_REVOKED` 400, `ACTIVATION_LOCKED` 423 (10 failures → 30 min lock), `INSTALLATION_BLOCKED` 403, `RATE_LIMITED` 429.

### `GET /licenses/verify` (signed)
Returns the current LicenseView. Call it on every launch and every few hours.

### Licence token (offline check)
Format `v1.<base64url(JSON)>.<base64url(DER ECDSA-SHA256 over "v1.<payload>")>`.
Verify it with `LICENSE_PUBLIC_KEY` (SPKI) embedded in the app. Payload:
`{ v, iid, did, kfp, st:"ACTIVE", lid, plan, iat, exp|null, gu }`.
The app must check that `kfp` equals sha256(its own SPKI) hex, `iid` matches, and `now < gu`. If `exp` is set, it must also check `now < exp`. Otherwise it must go online.

### Resources / firmware updates (signed, ACTIVE licence only)
- `GET /resources?kind=FIRMWARE&channel=STABLE|BETA` returns the latest published version per `slug`: `{ items:[{ id, kind, slug, name, versionName, versionCode, sizeBytes, sha256, targetHardware, minAppVersionCode, releaseNotes, ... }] }`.
- `POST /resources/:id/ticket` returns `{ url, path, expiresAt, sha256, sizeBytes }`, valid for 10 min.
- `GET /resources/download/:ticket` streams the file (unsigned). It supports `Range` for resume and sends an `X-SUMT-SHA256` header. **The app must verify the SHA-256 before using any file.**

### Public
- `GET /health` returns `{ status, db, version, time }`, or 503 if the DB is down.
- `GET /public-key` returns the licence verification key.

## Admin API (`/admin`, `Authorization: Bearer <accessToken>`)

| Method & path | Role | Purpose |
|---|---|---|
| POST `/admin/login` `{email,password}` | — | Returns `{accessToken (15 min), refreshToken (30 d), admin}`. 5 failures → 15 min lock |
| POST `/admin/refresh` `{refreshToken}` | — | Rotating refresh. Reuse of an old token kills all sessions |
| POST `/admin/logout` `{refreshToken}` | — | |
| GET `/admin/me` · POST `/admin/me/password` | VIEWER | |
| GET `/admin/dashboard` | VIEWER | Totals, pending, active, expired, blocked, revoked, expiring in 7 days, new in 24 h |
| GET `/admin/installations?status=&q=&page=&pageSize=&sort=&order=` | VIEWER | `q` matches the ID (`SUMT-10001` or `10001`), customer name/phone, model, notes. `status` also accepts EXPIRED |
| GET `/admin/installations/:id` | VIEWER | `:id` = UUID or `SUMT-10001`. Includes licences, key history (hint only), audit trail |
| PATCH `/admin/installations/:id` `{customerName,customerPhone,notes}` | ADMIN | |
| POST `/admin/activations/generate` `{installationId, licenseDays?: number\|null, keyValidHours?: 72, plan?}` | ADMIN | Returns **`activationKey` (shown once)**. Previous unused keys are revoked |
| GET `/admin/activations/history?installationId=` | VIEWER | |
| POST `/admin/activations/:keyId/revoke` | ADMIN | Unused key only |
| POST `/admin/licenses/:id/revoke` `{reason?}` | ADMIN | |
| PATCH `/admin/licenses/:id` `{expiresAt: ISO\|null}` | ADMIN | Set or extend expiry. `null` = lifetime |
| POST `/admin/installations/:id/block` `{reason?}` · `/unblock` | ADMIN | |
| POST `/admin/installations/:id/reset` `{reason?}` | ADMIN | Revokes licences and keys, clears the lock, sets status to PENDING |
| POST `/admin/installations/:id/transfer` `{toInstallationId}` | ADMIN | Reinstall recovery: moves the remaining licence |
| GET `/admin/resources?kind=&slug=` | VIEWER | |
| POST `/admin/resources` multipart: `file` + `kind, slug, name, versionName, versionCode, channel?, targetHardware?, minAppVersionCode?, releaseNotes?, publish?=true\|false, sha256?` | ADMIN | Server computes the SHA-256. If `sha256` is sent, it must match |
| PATCH `/admin/resources/:id` `{published?, name?, releaseNotes?, targetHardware?, minAppVersionCode?}` | ADMIN | Publish/unpublish takes effect instantly |
| DELETE `/admin/resources/:id` | SUPERADMIN | |
| GET/POST `/admin/admins`, PATCH `/admin/admins/:id` | SUPERADMIN | Create, disable or change the role of admins |
| GET `/admin/audit-logs?action=&targetId=&actorId=` | VIEWER | |

`ResourceKind`: FIRMWARE, REPAIR_DATA, WIRING_DIAGRAM, KNOWLEDGE_BASE, APP_UPDATE.

### Sending a firmware update to all customers
1. In the Admin app, go to Resources → Upload. Pick the file, choose kind `FIRMWARE`, slug `esp32-bridge`, a higher `versionCode`, and Publish.
2. Customer apps check `/resources` at launch and every 12 h. Any slug with a higher `versionCode` than the cached one is downloaded, its SHA-256 verified, and the user is notified.
3. To roll back, unpublish the bad version. Devices then see the previous one again.

With curl (the Admin app does the same):
```bash
curl -X POST $URL/api/v1/admin/resources -H "Authorization: Bearer $TOKEN" \
  -F kind=FIRMWARE -F slug=esp32-bridge -F name="ESP32 Bridge" \
  -F versionName=1.1.0 -F versionCode=2 -F targetHardware=ESP32 -F publish=true \
  -F file=@sumt-esp32-bridge-1.1.0.bin
```
