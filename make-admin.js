'use strict';

// Promote an email to admin role.
// Usage: node make-admin.js <email>
// Requires FIREBASE_SERVICE_ACCOUNT env var (same as server.js).

const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, Timestamp } = require('firebase-admin/firestore');

async function main() {
  const email = (process.argv[2] || '').trim().toLowerCase();
  if (!email) { console.error('Usage: node make-admin.js <email>'); process.exit(1); }

  const sa = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!sa) { console.error('FIREBASE_SERVICE_ACCOUNT env var must be set'); process.exit(1); }

  initializeApp({ credential: cert(JSON.parse(sa)), projectId: 'eshipper-f56c3' });
  const db = getFirestore();

  // 1. Seed invite (consumed on first sign-in)
  await db.collection('rfs_invites').doc(email).set({
    email,
    role: 'admin',
    invitedBy: 'make-admin.js',
    invitedAt: Timestamp.now(),
  });
  console.log(`Wrote rfs_invites/${email} = { role: "admin" }`);

  // 2. If a user doc already exists for this email, promote it directly
  const snap = await db.collection('rfs_users').where('email', '==', email).get();
  if (!snap.empty) {
    for (const doc of snap.docs) {
      await doc.ref.update({ role: 'admin' });
      console.log(`Updated rfs_users/${doc.id} role -> admin`);
    }
  } else {
    console.log('No existing user doc — admin role will apply on first sign-in.');
  }
}

main().catch(err => { console.error(err); process.exit(1); });
