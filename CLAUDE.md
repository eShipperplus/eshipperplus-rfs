# eShipper+ RFS App — Project Reference

## Overview
Mobile-first warehouse app for tracking RFS (Ready-for-Ship) orders from putaway → pickup → BOL upload. Pulls D2B-SPD and D2B LTL/FTL orders from Logiwa at status 16 ("Ready to Ship"), records pallet locations in Tunnel zone, and pushes the signed BOL back to Logiwa as DocumentType 5.

## Sister Projects
- **Warehouse billing** — `C:\Users\user\Desktop\Claude\eshipper-warehouse-billing\` — primary app, jobs/billing
- **CRM** — `C:\Users\user\Desktop\Claude\eshipperplus-crm\`
- **Reporting/SLA** — `C:\Users\user\Desktop\Claude\webapp\` (Python Flask on Railway)

## Stack
- Node.js + Express on Cloud Run (region `northamerica-northeast1`)
- Firebase Auth (Google + email/password) + Firestore (`eshipper-f56c3`)
- Firebase Storage (BOL photo backup)
- Logiwa API v3.1
- Vanilla-JS SPA in `public/` — `index.html` + `app.js` + `firebase-config.js`

## Key Files
| File | Purpose |
|------|---------|
| `server.js` | Express backend — auth, sync, putaway/load/BOL routes |
| `logiwa.js` | Logiwa client — token cache, LQL list, multipart BOL upload |
| `import-locations.js` | One-shot xlsx → Firestore importer for `rfs_locations` |
| `public/index.html` | SPA shell + styles |
| `public/app.js` | All client logic (auth, state, render, scanner) |
| `public/firebase-config.js` | Public Firebase web config (replace REPLACE_ME) |

## Logiwa specifics — facts confirmed against live API
- **Status filter**: `Status.eq=16` (Ready to Ship). Full status list at `GET /v3.1/Helper/shipmentorderstatustypes`. Logiwa LQL syntax = `{field}.{operator}={value}` (dot, NOT colon).
- **Order type filter**: `ShipmentOrderTypeName.eq=...` — supports `eq` only (no `in`). Two parallel calls, one per type.
- **Order types used**: `D2B Order - SPD`, `D2B Order - LTL/FTL` (exact strings).
- **eShipper+ warehouse identifier**: `8320f545-d1d3-4bbc-bf08-b44d11c93b94`.
- **BOL upload**: `POST /v3.1/ShipmentOrder/document` (multipart), `DocumentType=5`, accepts `ShipmentOrderIdentifier` OR `ShipmentOrderCode`.
- **Token TTL**: 25 minutes, cached in-memory; auto-retry on 401.
- **App does NOT change Logiwa status** — team flips that manually. App owns its own `rfsState`.

## Firestore collections
- `rfs_orders/{logiwaIdentifier}` — synced orders + putaway/pickup state
- `rfs_locations/{sanitizedCode}` — Tunnel-zone locations from xlsx + `priorityRank` for `26-*` priority
- `rfs_users/{uid}`, `rfs_invites/{email}` — auth/role
- All client writes blocked via `firestore.rules` — server-only mutations

## State machine for `rfsState`
```
awaiting_putaway → staged → loading → loaded → shipped
                         ↑                ↓
                      partial         BOL upload
                      pallets         pushes to
                      pending         Logiwa as
                                      DocumentType 5
```

## Roles
| Role | Access |
|------|--------|
| `worker` | Sync, putaway, pickup, BOL upload |
| `supervisor` | Worker + view all locations |
| `admin` | All + invite users |

First user is `worker` unless pre-invited via `rfs_invites/{email}` doc with role field.

## Local Dev
```bash
cd eshipperplus-rfs
npm install
# Set env vars (FIREBASE_SERVICE_ACCOUNT, LOGIWA_EMAIL, LOGIWA_PASSWORD)
npm run dev          # → http://localhost:8080
```

## Deploy
GitHub Actions on push to `main`. Secrets needed: `GCP_SA_KEY` (Action secret) and Cloud Secret Manager: `FIREBASE_SA_JSON`, `LOGIWA_EMAIL`, `LOGIWA_PASSWORD`.

## Verification reminders
- Logiwa pushes are real — don't test BOL upload casually. Use the sandbox URL `https://myapisandbox.logiwa.com` if you need to dry-run.
- Camera scanning needs HTTPS in production (Cloud Run is HTTPS by default; localhost gets a free pass).
- Firestore index for `rfs_locations` empty-query is composite (5 fields + sort) — must be deployed via `firestore.indexes.json` before the available-locations endpoint will work.
