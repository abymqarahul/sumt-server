# Deploy the SUMT backend to Railway

Total time: about 10 minutes. Everything runs from the `backend/` folder.

## 0. Prerequisites (on your PC)
- Node.js 20 or newer: `node -v`
- Railway CLI: `npm i -g @railway/cli`

## 1. Generate your secrets (once, keep them safe)
```bash
cd backend
npm ci
npm run build
npm run keys:generate > ../sumt-secrets.txt
```
`sumt-secrets.txt` contains 4 secret values plus 1 public key. **Never commit this file or share it.** Keep a backup in a password manager. If `LICENSE_SIGNING_PRIVATE_KEY` is lost, every installed app will need an update. If `ACTIVATION_KEY_PEPPER` is lost, keys that were generated but not yet used stop working.

## 2. Create the project, database, volume and service
```bash
railway login
railway init                       # project name: SUMT
railway add --database postgres    # adds a PostgreSQL service named "Postgres"
railway add                        # choose "Empty Service", name it: sumt-backend
railway service sumt-backend       # link this folder to that service
railway volume add                 # mount path: /data   (stores firmware uploads)
```

## 3. Set variables
Copy the 4 secret values from `sumt-secrets.txt` into the commands below. Use **single quotes** so the shell doesn't change them.
```bash
railway variable set 'DATABASE_URL=${{Postgres.DATABASE_URL}}'
railway variable set 'NODE_ENV=production'
railway variable set 'STORAGE_DIR=/data/resources'
railway variable set 'LICENSE_SIGNING_PRIVATE_KEY=PASTE_VALUE'
railway variable set 'ACTIVATION_KEY_PEPPER=PASTE_VALUE'
railway variable set 'JWT_ACCESS_SECRET=PASTE_VALUE'
railway variable set 'DOWNLOAD_TICKET_SECRET=PASTE_VALUE'
railway variable set 'BOOTSTRAP_ADMIN_EMAIL=you@example.com'
railway variable set 'BOOTSTRAP_ADMIN_PASSWORD=Choose-A-Strong-Passw0rd!'
```
The admin password needs at least 12 characters and three of: lowercase, uppercase, digits, symbols.

## 4. Deploy and get a public URL
```bash
railway up --detach          # builds the Dockerfile and runs "prisma migrate deploy" before start
railway domain               # prints https://<something>.up.railway.app
railway variable set 'PUBLIC_BASE_URL=https://<something>.up.railway.app'
railway logs -n 50           # look for "Bootstrap SUPERADMIN created"
```

## 5. Verify
```bash
curl https://<something>.up.railway.app/api/v1/health
# {"status":"ok","db":"ok",...}

curl -X POST https://<something>.up.railway.app/api/v1/admin/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"Choose-A-Strong-Passw0rd!"}'
# returns accessToken + refreshToken
```

## 6. Remove the bootstrap password (important)
```bash
railway variable delete BOOTSTRAP_ADMIN_PASSWORD
railway variable delete BOOTSTRAP_ADMIN_EMAIL
```
The admin account remains in the database. To add more admins later, use the Admin app, or run:
`railway ssh` → `node dist/scripts/create-admin.js --email helper@example.com --role ADMIN`

## 7. Send me
1. The URL from step 4.
2. The `LICENSE_PUBLIC_KEY` line from `sumt-secrets.txt`. It's public and safe to share, and it gets embedded in the customer app.

## Updating later
Change the code, then run `railway up --detach`. Migrations run automatically. Firmware uploads survive because they live on the `/data` volume.

## Backups
Railway Postgres: enable backups in the Postgres service → Backups. Volume: `railway volume files download …` or snapshot from the dashboard.
