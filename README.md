# eShipper+ RFS — Putaway & Dispatch Tracker

Mobile-first internal app for tracking RFS (Ready-for-Ship) orders from putaway through driver pickup and BOL upload. Pulls orders from Logiwa, lets warehouse workers stage pallets to locations, and pushes the final signed BOL back to Logiwa as a Bill-of-Lading document attachment.

## Flow

1. Worker taps **Sync from Logiwa** → app pulls all `D2B Order - SPD` and `D2B Order - LTL/FTL` orders at status `16` (Ready to Ship) from the eShipper+ warehouse.
2. **Putaway**: tap an order → enter pallet count → for each pallet, scan or type a Tunnel-zone location code (priority `26-*` codes are suggested first).
3. **Pickup**: driver arrives → worker switches to the Pickup tab → scans the order code → app shows each pallet's location → worker marks each loaded.
4. **BOL upload**: once all pallets are loaded → take a photo of the signed BOL → upload. Photo is saved to Firebase Storage AND posted to Logiwa as `DocumentType=5` (Bill of Lading). Order moves to `shipped` and disappears from the active list.

Logiwa status is **not** modified by the app — your team flips that manually. The app's own state (`rfsState`) determines what shows in the active list.

## Stack

- Node.js + Express on Google Cloud Run
- Firestore (`eshipper-f56c3` project, `rfs_*` collection prefix)
- Firebase Auth (Google SSO + email/password fallback)
- Firebase Storage (BOL photo backup)
- Logiwa WMS API v3.1 (LQL filtering, multipart document upload)
- Vanilla-JS SPA in `public/index.html` + `public/app.js`
- `html5-qrcode` for camera barcode scanning

## Setup

### 1. Install

```bash
cd eshipperplus-rfs
npm install
```

### 2. Firebase web config

Open the Firebase console → Project settings → Your apps → register a web app called "rfs", then copy the config object into [`public/firebase-config.js`](public/firebase-config.js) (replace the `REPLACE_ME` values). These are non-secret identifiers.

### 3. Service-account JSON

Download a service-account JSON for the Firebase project (Firebase console → Project settings → Service accounts → Generate new private key). Save it locally as `service-account.json` (gitignored). Set the env var:

```bash
# Windows PowerShell
$env:FIREBASE_SERVICE_ACCOUNT = (Get-Content service-account.json -Raw)

# bash / WSL
export FIREBASE_SERVICE_ACCOUNT="$(cat service-account.json)"
```

Also set the Logiwa creds (same as warehouse-billing):

```bash
export LOGIWA_EMAIL=logiwa_api_user1@eshipperplus.com
export LOGIWA_PASSWORD='eShipper+123'
export LOGIWA_ESHIPPER_WH_IDENTIFIER=8320f545-d1d3-4bbc-bf08-b44d11c93b94
```

### 4. Import locations

Drop the latest Logiwa Warehouse Location Report (xlsx) at any path and run:

```bash
npm run import-locations -- "C:/Users/user/Downloads/WarehouseLocationReport_2f22fc99-8336-42bd-bd60-3173cc366ad4.xlsx"
```

The script filters to `eShipper+` warehouse + `Tunnel` zone (currently 7,902 rows), writes them to the `rfs_locations` Firestore collection, and stamps a `priorityRank` field (0 for codes starting with `26-`, 1 otherwise) so the Putaway screen sorts those first. Re-run any time you re-export the report to refresh `hasInventory` flags.

### 5. Run locally

```bash
npm run dev
# open http://localhost:8080 on your phone (over local Wi-Fi) or laptop
```

### 6. Make yourself admin

The first user to sign in becomes a `worker` by default. To grant admin, drop a Firestore doc:

```
rfs_invites/<your-email-lowercase> = { role: "admin" }
```

Then sign in — the role is applied on first auth. After that, use the in-app **Admin → Invite a user** form for further invites.

### 7. Deploy

This repo is set up for the same GitHub Actions → Cloud Run flow as `eshipper-warehouse-billing`. You'll need:

1. A new GitHub repo, e.g. `eShipperplus/eshipperplus-rfs`
2. GitHub Action secrets:
   - `GCP_SA_KEY` — same GCP service account as the warehouse-billing app
3. Cloud Secret Manager secrets (referenced in [.github/workflows/deploy.yml](.github/workflows/deploy.yml)):
   - `FIREBASE_SA_JSON` — service-account JSON
   - `LOGIWA_EMAIL`, `LOGIWA_PASSWORD`

Then `git push origin main` triggers the deploy.

## Firestore indexes

Apply once: `firebase deploy --only firestore:indexes` (or use the Firebase console to create them — see [firestore.indexes.json](firestore.indexes.json)).

## Firestore security rules

Apply: `firebase deploy --only firestore:rules`. The rules block all client-side writes — every mutation goes through the Express API which uses the Admin SDK.

## Data model

`rfs_orders/{logiwaIdentifier}`
- `logiwaIdentifier`, `logiwaCode`, `shipmentOrderTypeName`
- `clientName`, `customerName`, `totalQuantity`, `totalWeight`, `expectedShipmentDate`
- `bolReference`, `proNumber`, `poNumber`, `note` (mirrored from Logiwa)
- `rfsState` — `awaiting_putaway` → `staged` → `loading` → `loaded` → `shipped`
- `pallets[]` — `{ palletNo, locationCode, state: 'staged'|'loaded', stagedAt, stagedBy, loadedAt, loadedBy }`
- `bolPhotoUrl`, `bolStoragePath`, `logiwaDocumentResult`, `shippedAt`, `shippedBy`

`rfs_locations/{code-with-illegals-replaced}`
- `code`, `warehouse`, `zone`, `group`, `type`, `rack`, `position`, `level`, `aisle`, `column`, `locationBarcode`
- `hasInventory`, `lockLocation`, `preventAllocation` (from xlsx)
- `priorityRank` — 0 if code starts with `26-`, 1 otherwise
- `currentPalletOrderId`, `currentPalletOrderCode`, `currentPalletNo` — null when free, set when an RFS pallet is staged here

`rfs_users/{uid}` and `rfs_invites/{email}` — auth + role mapping.

## Roles

| Role | Can |
|---|---|
| `worker` | Sync, putaway, pickup, BOL upload |
| `supervisor` | Worker + view all locations |
| `admin` | Everything + invite users |

## Known gaps / next steps

- **Logiwa upload retry**: if the Logiwa BOL POST fails after Storage upload, the BOL is saved with a `logiwaUploadError` field on the order. There's no admin "retry" button yet — it's a manual Firestore touch for now.
- **Order list real-time**: list polls on tab switch. Could add Firestore `onSnapshot` listeners for live updates if multiple workers are using the app at once.
- **Pallet partial loading**: if a driver only takes some pallets, the order goes to `loading` and stays there. There's no "shipping partial" flow yet.
- **Logs**: no audit log collection. Consider adding `rfs_logs` if you need to trace who did what.
