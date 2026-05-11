'use strict';

// One-shot script: imports a Logiwa Warehouse Location Report (.xlsx) into
// Firestore collection `rfs_locations`. Re-run any time you re-export the report
// to refresh `hasInventory` / `preventAllocation` / `lockLocation` flags.
//
// Usage:
//   node import-locations.js <path-to-xlsx>
//
// Requires FIREBASE_SERVICE_ACCOUNT env var (same as server.js).

const fs = require('fs');
const path = require('path');
const XLSX = require('xlsx');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const PROJECT_ID = 'eshipper-f56c3';
const TARGET_WAREHOUSE = 'eShipper+';
const TARGET_ZONE = 'Tunnel';
const PRIORITY_PREFIX = '26';

function yn(v) { return String(v).trim().toLowerCase() === 'yes'; }

function priorityRank(code) {
  return String(code).startsWith(PRIORITY_PREFIX) ? 0 : 1;
}

async function main() {
  const xlsxPath = process.argv[2];
  if (!xlsxPath) {
    console.error('Usage: node import-locations.js <path-to-xlsx>');
    process.exit(1);
  }
  if (!fs.existsSync(xlsxPath)) {
    console.error('File not found:', xlsxPath);
    process.exit(1);
  }

  const sa = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!sa) {
    console.error('FIREBASE_SERVICE_ACCOUNT env var must be set');
    process.exit(1);
  }
  initializeApp({ credential: cert(JSON.parse(sa)), projectId: PROJECT_ID });
  const db = getFirestore();

  console.log('Reading', xlsxPath);
  const wb = XLSX.readFile(xlsxPath);
  const sheet = wb.Sheets[wb.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });
  console.log('Total rows in xlsx:', rows.length);

  const filtered = rows.filter(r =>
    r['Warehouse'] === TARGET_WAREHOUSE && r['Location Zone'] === TARGET_ZONE
  );
  console.log(`Rows matching ${TARGET_WAREHOUSE} / ${TARGET_ZONE}:`, filtered.length);

  const importedAt = FieldValue.serverTimestamp();
  let written = 0;
  const BATCH_SIZE = 400;

  for (let i = 0; i < filtered.length; i += BATCH_SIZE) {
    const chunk = filtered.slice(i, i + BATCH_SIZE);
    const batch = db.batch();
    for (const row of chunk) {
      const code = String(row['Location Code']).trim();
      if (!code) continue;
      const docId = code.replace(/[\/\.\#\$\[\]]/g, '_');
      const ref = db.collection('rfs_locations').doc(docId);
      batch.set(ref, {
        code,
        warehouse: row['Warehouse'],
        zone: row['Location Zone'],
        group: row['Location Group'] || null,
        type: row['Location Type'] || null,
        areaType: row['Area Type'] || null,
        rack: row['Rack'] || null,
        position: row['Position'] || null,
        level: row['Level'] || null,
        aisle: row['Aisle'] || null,
        column: row['Column'] || null,
        locationBarcode: row['Location Barcode'] || code,
        hasInventory: yn(row['Has Inventory']),
        lockLocation: yn(row['Lock Location?']),
        preventAllocation: yn(row['Prevent Allocation?']),
        priorityRank: priorityRank(code),
        currentPalletOrderCode: null,
        currentPalletOrderId: null,
        currentPalletNo: null,
        importedAt,
      }, { merge: true });
      written += 1;
    }
    await batch.commit();
    console.log(`  committed ${Math.min(i + BATCH_SIZE, filtered.length)} / ${filtered.length}`);
  }

  console.log(`\nDone. Wrote ${written} location docs to rfs_locations.`);
  console.log(`Priority "26-*" locations:`, filtered.filter(r => String(r['Location Code']).startsWith(PRIORITY_PREFIX)).length);
  console.log(`Currently empty (Has Inventory == No):`, filtered.filter(r => !yn(r['Has Inventory'])).length);
}

main().catch(err => {
  console.error('Import failed:', err);
  process.exit(1);
});
