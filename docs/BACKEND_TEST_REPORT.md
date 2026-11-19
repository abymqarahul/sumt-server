# Backend test report

Run: 2026-11-19, Node v22.23.5, PostgreSQL 16.15 (real database, real migrations), Vitest.

Also verified: production build (`tsc`), compiled server smoke test over HTTP, the Docker image (migrate deploy, health, admin login, graceful SIGTERM). The Docker check skipped only the apt layer, which the sandbox network blocks; Railway runs the full Dockerfile.

```
 ✓ tests/activation.test.ts > health > reports ok with database connectivity
 ✓ tests/activation.test.ts > installation registration > assigns sequential SUMT IDs starting at 10001 and starts PENDING
 ✓ tests/activation.test.ts > installation registration > is idempotent for the same Keystore key
 ✓ tests/activation.test.ts > installation registration > handles concurrent first-launch registration without duplicates
 ✓ tests/activation.test.ts > installation registration > rejects a registration without proof of key possession
 ✓ tests/activation.test.ts > installation registration > rejects a wrong clock and invalid keys
 ✓ tests/activation.test.ts > signed device requests > require headers, a valid signature and a fresh nonce
 ✓ tests/activation.test.ts > signed device requests > bind the signature to the body (tampering fails)
 ✓ tests/activation.test.ts > signed device requests > reject an installation impersonated by another key
 ✓ tests/activation.test.ts > activation lifecycle > generate → consume → ACTIVE with a device-bound licence token
 ✓ tests/activation.test.ts > activation lifecycle > accepts the key typed in lowercase with spaces
 ✓ tests/activation.test.ts > activation lifecycle > a key works only once
 ✓ tests/activation.test.ts > activation lifecycle > only one of many simultaneous consume requests succeeds
 ✓ tests/activation.test.ts > activation lifecycle > anti-sharing: a copied APK gets its own ID and cannot use the original key
 ✓ tests/activation.test.ts > activation lifecycle > rejects expired keys
 ✓ tests/activation.test.ts > activation lifecycle > a newly generated key supersedes the previous unused one
 ✓ tests/activation.test.ts > activation lifecycle > locks activation after repeated failures (brute-force protection)
 ✓ tests/activation.test.ts > activation lifecycle > renewal extends from the current expiry
 ✓ tests/activation.test.ts > activation lifecycle > lifetime keys produce a licence without expiry
 ✓ tests/activation.test.ts > licence management > revocation takes effect on the next verify
 ✓ tests/activation.test.ts > licence management > expiry: an expired licence reports EXPIRED and can be extended
 ✓ tests/activation.test.ts > licence management > block / unblock
 ✓ tests/activation.test.ts > licence management > reset returns the installation to PENDING
 ✓ tests/activation.test.ts > licence management > transfer moves the remaining licence to a reinstalled device
 ✓ tests/activation.test.ts > admin views > dashboard counts, search and installation details
 ✓ tests/admin-auth.test.ts > admin authentication > logs in with correct credentials only
 ✓ tests/admin-auth.test.ts > admin authentication > locks the account after repeated failures
 ✓ tests/admin-auth.test.ts > admin authentication > rotates refresh tokens and detects reuse
 ✓ tests/admin-auth.test.ts > admin authentication > logout revokes the refresh token
 ✓ tests/admin-auth.test.ts > admin authorisation is enforced by the server > rejects missing, forged and device credentials
 ✓ tests/admin-auth.test.ts > admin authorisation is enforced by the server > VIEWER can read but not generate keys or block
 ✓ tests/admin-auth.test.ts > admin authorisation is enforced by the server > only SUPERADMIN manages admins; disabling an admin kills their session
 ✓ tests/admin-auth.test.ts > admin authorisation is enforced by the server > password change invalidates existing sessions
 ✓ tests/admin-auth.test.ts > admin authorisation is enforced by the server > validates input
 ✓ tests/admin-auth.test.ts > bootstrap admin > creates the first SUPERADMIN only when none exists
 ✓ tests/resources.test.ts > firmware / resource distribution > upload computes SHA-256; licensed devices list, get a ticket and download the exact bytes
 ✓ tests/resources.test.ts > firmware / resource distribution > device sees only the latest published version per slug
 ✓ tests/resources.test.ts > firmware / resource distribution > publish / unpublish takes effect immediately, including for issued tickets
 ✓ tests/resources.test.ts > firmware / resource distribution > unlicensed devices cannot list or download
 ✓ tests/resources.test.ts > firmware / resource distribution > download stops working when the licence is revoked
 ✓ tests/resources.test.ts > firmware / resource distribution > rejects tampered tickets
 ✓ tests/resources.test.ts > firmware / resource distribution > validates uploads: checksum, duplicates, size, metadata
 ✓ tests/resources.test.ts > firmware / resource distribution > only SUPERADMIN can delete; delete removes the file
 ✓ tests/security.test.ts > rate limiting (production-like limits) > throttles admin login attempts per IP
 ✓ tests/security.test.ts > rate limiting (production-like limits) > throttles activation attempts
 ✓ tests/security.test.ts > transport security > rejects plain HTTP in production and sets HSTS on HTTPS
 ✓ tests/security.test.ts > transport security > never leaks secrets or stack traces in errors
 ✓ tests/unit.crypto.test.ts > activation keys > have the SUMT-XXXX-XXXX-XXXX-XXXX format and are unique
 ✓ tests/unit.crypto.test.ts > activation keys > normalise case, spacing and look-alike characters
 ✓ tests/unit.crypto.test.ts > activation keys > hash depends on the pepper
 ✓ tests/unit.crypto.test.ts > device keys > accepts EC P-256 SPKI and verifies DER signatures
 ✓ tests/unit.crypto.test.ts > device keys > rejects other curves and RSA keys
 ✓ tests/unit.crypto.test.ts > licence tokens > round-trip and detect tampering
 ✓ tests/unit.crypto.test.ts > download tickets > reject modified payloads and wrong secrets
 ✓ tests/unit.crypto.test.ts > helpers > parse byte ranges
 ✓ tests/unit.crypto.test.ts > helpers > sanitise file names
 ✓ tests/unit.crypto.test.ts > helpers > enforce password strength
 ✓ tests/unit.crypto.test.ts > helpers > refuse to start with missing secrets
 Test Files  5 passed (5)
      Tests  58 passed (58)
```
