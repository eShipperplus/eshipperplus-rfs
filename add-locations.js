'use strict';

// One-off helper to add specific locations to rfs_locations.
// Run with: node add-locations.js
// Requires FIREBASE_SERVICE_ACCOUNT env var (same as server.js / make-admin.js).
//
// Edit LOCATIONS_TO_ADD below before re-running to add a different set.

const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, Timestamp } = require('firebase-admin/firestore');

const LOCATIONS_TO_ADD = [
  { code: '26-A-31', locationBarcode: '26A31' },
  { code: '26-A-32', locationBarcode: '26A32' },
  { code: '26-A-33', locationBarcode: '26A33' },
  { code: '26-A-34', locationBarcode: '26A34' },
];

function locDocId(code) {
  return String(code).replace(/[\/\.\#\$\[\]]/g, '_');
}

async function main() {
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!sa) {
    console.error('FIREBASE_SERVICE_ACCOUNT env var must be set');
    process.exit(1);
  }

  initializeApp({ credential: cert(JSON.parse(sa)), projectId: 'eshipper-f56c3' });
  const db = getFirestore();

  let added = 0, skipped = 0;
  for (const loc of LOCATIONS_TO_ADD) {
    const ref = db.collection('rfs_locations').doc(locDocId(loc.code));
    const snap = await ref.get();
    if (snap.exists) {
      console.log(`  already exists: ${loc.code}  (skipped)`);
      skipped += 1;
      continue;
    }
    await ref.set({
      code: loc.code,
      warehouse: 'eShipper+',
      zone: 'Tunnel',
      group: null,
      type: null,
      areaType: null,
      rack: null,
      position: null,
      level: null,
      aisle: null,
      column: null,
      locationBarcode: loc.locationBarcode,
      hasInventory: false,
      lockLocation: false,
      preventAllocation: false,
      // priorityRank 0 = codes starting with "26-" → suggested first on putaway
      priorityRank: loc.code.startsWith('26-') ? 0 : 1,
      currentPalletOrderId: null,
      currentPalletOrderCode: null,
      currentPalletNo: null,
      importedAt: Timestamp.now(),
      addedManuallyAt: Timestamp.now(),
    });
    console.log(`  added: ${loc.code}  (barcode: ${loc.locationBarcode})`);
    added += 1;
  }

  console.log(`\nDone. Added ${added}, skipped ${skipped}.`);
}

main().catch(err => { console.error(err); process.exit(1); });
