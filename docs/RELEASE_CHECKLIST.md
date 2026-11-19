# Release checklist

Backend
- [ ] `npm test` green against a real PostgreSQL
- [ ] `railway up` deploy healthy (`/api/v1/health` → ok)
- [ ] BOOTSTRAP_ADMIN_* variables removed
- [ ] Postgres backups enabled; `sumt-secrets.txt` stored in a password manager
- [ ] Rate limits at production defaults

Android (phase 2)
- [ ] Release build signed with the SUMT upload key (keystore backed up offline)
- [ ] Stable applicationIds: `com.sumt.terminal`, `com.sumt.admin`
- [ ] `LICENSE_PUBLIC_KEY` and the API base URL come from one build config
- [ ] Old-brand and exclusion grep audit = 0 hits
- [ ] R8 enabled; no debug builds published
- [ ] Output: `SUMT-Customer.apk`, `SUMT-Admin.apk`
