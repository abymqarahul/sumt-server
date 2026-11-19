# Test plan

## Backend (automated: see BACKEND_TEST_REPORT.md)
Registration (sequential IDs, idempotency, concurrency, proof of possession, clock skew, invalid keys) · signed requests (missing headers, forged signatures, replay, body tampering, impersonation) · activation (happy path, normalisation, one-time use, 12 concurrent consumes → exactly 1 succeeds, anti-sharing across devices, expired/superseded keys, brute-force lock, renewal, lifetime) · licences (revoke, expiry and extension, block/unblock, reset, transfer) · admin (login, lockout, refresh rotation and reuse detection, logout, role enforcement, admin management, password change, validation, bootstrap) · resources (upload + SHA-256, latest per slug, channels, publish/unpublish, licence gating, ticket tampering, Range, checksum mismatch, duplicates, size limit, delete) · security (rate limits, HTTPS enforcement, no secret or stack leakage).

## Android (to be executed in phase 2)
Fresh install · restart · activation · duplicate activation · no internet · server down · licence expiry · revocation · reinstall → new ID → transfer · clear data · USB permission denial · unplugging hardware mid-operation · invalid firmware · wrong chip selection · read-back verification · background/foreground · low storage · phone/tablet sizes · all 5 themes · reduced motion · branding and exclusion grep audit.
