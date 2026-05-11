'use strict';

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { PDFDocument } = require('pdf-lib');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue, Timestamp } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const { getStorage } = require('firebase-admin/storage');
const logiwa = require('./logiwa');

const PROJECT_ID = 'eshipper-f56c3';
const STORAGE_BUCKET = 'eshipper-f56c3.firebasestorage.app';
const ROLES = ['admin', 'supervisor', 'csm', 'worker'];
// Roles that can view reports (orders + PO history). Admin-only operations
// (user invites, location admin) stay gated separately to `admin`.
const REPORT_ROLES = ['admin', 'supervisor', 'csm'];

const firebaseConfig = process.env.FIREBASE_SERVICE_ACCOUNT
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
  : undefined;

initializeApp(firebaseConfig
  ? { credential: cert(firebaseConfig), storageBucket: STORAGE_BUCKET, projectId: PROJECT_ID }
  : { storageBucket: STORAGE_BUCKET, projectId: PROJECT_ID });

const db = getFirestore();
const auth = getAuth();
const bucket = getStorage().bucket();

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!ALLOWED_ORIGIN) return cb(null, true);
    if (origin === ALLOWED_ORIGIN) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));

app.use(rateLimit({ windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false }));
app.use(express.json({ limit: '15mb' }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth middleware ─────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing auth token' });
  }
  try {
    const decoded = await auth.verifyIdToken(header.slice(7));
    req.uid = decoded.uid;
    req.email = decoded.email;
    const userRef = db.collection('rfs_users').doc(decoded.uid);
    const snap = await userRef.get();
    if (!snap.exists) {
      const inviteSnap = await db.collection('rfs_invites').doc(decoded.email.toLowerCase()).get();
      const role = (inviteSnap.exists && ROLES.includes(inviteSnap.data().role)) ? inviteSnap.data().role : 'worker';
      const userData = {
        uid: decoded.uid,
        email: decoded.email,
        displayName: decoded.name || decoded.email,
        role,
        createdAt: Timestamp.now(),
        lastSeen: Timestamp.now(),
      };
      await userRef.set(userData);
      if (inviteSnap.exists) inviteSnap.ref.delete().catch(() => {});
      req.user = userData;
    } else {
      const data = snap.data();
      userRef.update({ lastSeen: Timestamp.now() }).catch(() => {});
      req.user = data;
    }
    next();
  } catch (err) {
    console.error('requireAuth error:', err.message);
    return res.status(401).json({ error: 'Invalid auth token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function shortOrderForList(o) {
  return {
    logiwaIdentifier: o.logiwaIdentifier,
    logiwaCode: o.logiwaCode,
    shipmentOrderTypeName: o.shipmentOrderTypeName,
    clientName: o.clientName,
    customerName: o.customerName,
    totalQuantity: o.totalQuantity,
    totalWeight: o.totalWeight,
    expectedShipmentDate: o.expectedShipmentDate,
    rfsState: o.rfsState,
    palletCount: (o.pallets || []).length,
    palletsStaged: (o.pallets || []).filter(p => p.state !== 'pending').length,
    palletsLoaded: (o.pallets || []).filter(p => p.state === 'loaded').length,
    bolPhotoUrl: o.bolPhotoUrl || null,
    lastSyncedAt: o.lastSyncedAt || null,
  };
}

// ─── Audit log ───────────────────────────────────────────────────────────────
// Append-only event log. Captures every state change so disputes can be traced.
// Failures here NEVER throw — auditing must not break the action it's auditing.
async function logEvent({ type, actor, subjectType, subjectId, summary, meta }) {
  try {
    await db.collection('rfs_events').add({
      at: Timestamp.now(),
      type,
      actor: actor ? { uid: actor.uid || null, email: actor.email || null, displayName: actor.displayName || null } : null,
      subjectType: subjectType || null,
      subjectId: subjectId || null,
      summary: summary || null,
      meta: meta || {},
    });
  } catch (err) {
    console.error('[audit] failed to log', type, err.message);
  }
}

function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Build a pallet record from incoming partial data, merging with the previous
// pallet (if any) so timestamps + units that were already set are preserved.
function mergePallet(palletNo, input, prev, by) {
  const locationCode = input.locationCode ? String(input.locationCode) : (prev?.locationCode || null);
  const isStaged = !!locationCode;
  const justBecameStaged = isStaged && (!prev || !prev.locationCode);

  const length = num(input.length) ?? prev?.length ?? null;
  const width = num(input.width) ?? prev?.width ?? null;
  const height = num(input.height) ?? prev?.height ?? null;
  const weight = num(input.weight) ?? prev?.weight ?? null;

  return {
    palletNo,
    locationCode,
    length,
    width,
    height,
    weight,
    dimensionUnit: input.dimensionUnit || prev?.dimensionUnit || 'in',
    weightUnit: input.weightUnit || prev?.weightUnit || 'lb',
    state: prev?.state === 'loaded' ? 'loaded' : (isStaged ? 'staged' : 'pending'),
    stagedAt: prev?.stagedAt || (justBecameStaged ? Timestamp.now() : null),
    stagedBy: prev?.stagedBy || (justBecameStaged ? by : null),
    loadedAt: prev?.loadedAt || null,
    loadedBy: prev?.loadedBy || null,
    updatedAt: Timestamp.now(),
    updatedBy: by,
  };
}

function locDocId(code) { return String(code).replace(/[\/\.\#\$\[\]]/g, '_'); }

// Wrap a JPEG/PNG into a single-page PDF for Logiwa CarrierLabel uploads
// (Logiwa's label slots only accept PDF). Pass-through if already PDF.
async function ensurePdf(buffer, mimeType) {
  if (mimeType === 'application/pdf') return buffer;
  const pdfDoc = await PDFDocument.create();
  const isPng = (mimeType || '').toLowerCase().includes('png');
  const image = isPng ? await pdfDoc.embedPng(buffer) : await pdfDoc.embedJpg(buffer);
  const page = pdfDoc.addPage([image.width, image.height]);
  page.drawImage(image, { x: 0, y: 0, width: image.width, height: image.height });
  return Buffer.from(await pdfDoc.save());
}

// Resolve a location from a scanned/typed input. Matches on either `code` (e.g. "26-B-04")
// or `locationBarcode` (e.g. "26B04" — what's printed on the warehouse shelf).
// Returns { ref, snap, code } where `code` is the canonical form from the stored doc.
async function findLocation(tx, codeInput) {
  if (!codeInput) return null;
  const q = String(codeInput).trim();
  const tryCodes = [...new Set([q, q.toUpperCase(), q.toLowerCase()])];

  // 1. Doc-id lookup (matches `code` exactly, with case variations)
  for (const c of tryCodes) {
    const ref = db.collection('rfs_locations').doc(locDocId(c));
    const snap = tx ? await tx.get(ref) : await ref.get();
    if (snap.exists) return { ref, snap, code: snap.data().code };
  }

  // 2. Match by locationBarcode field (the printed shelf barcode, e.g. "26B04")
  for (const c of tryCodes) {
    const query = db.collection('rfs_locations').where('locationBarcode', '==', c).limit(1);
    const snap = tx ? await tx.get(query) : await query.get();
    if (!snap.empty) {
      const doc = snap.docs[0];
      return { ref: doc.ref, snap: doc, code: doc.data().code };
    }
  }

  return null;
}

// ─── Health / Init ───────────────────────────────────────────────────────────
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: { uid: req.user.uid, email: req.user.email, displayName: req.user.displayName, role: req.user.role } });
});

// ─── Sync orders from Logiwa ─────────────────────────────────────────────────
async function runSync(actor) {
  const wh = process.env.LOGIWA_ESHIPPER_WH_IDENTIFIER || undefined;
  const syncStart = Timestamp.now();
  const orders = await logiwa.listAllReadyToShipOrders({ warehouseIdentifier: wh });
  let created = 0, updated = 0;

  for (const o of orders) {
    const ref = db.collection('rfs_orders').doc(o.identifier);
    const snap = await ref.get();
    const base = {
      logiwaIdentifier: o.identifier,
      logiwaCode: o.code,
      shipmentOrderTypeName: o.shipmentOrderTypeName,
      clientIdentifier: o.clientIdentifier,
      clientName: o.clientDisplayName,
      customerName: o.customerFullName || `${o.customerFirstName || ''} ${o.customerLastName || ''}`.trim(),
      totalQuantity: o.totalQuantity || 0,
      totalWeight: o.totalWeight || 0,
      expectedShipmentDate: o.expectedShipmentDate || null,
      carrierName: o.carrierName || null,
      bolReference: o.bol || null,
      proNumber: o.pro || null,
      poNumber: o.po || null,
      note: o.note || null,
      logiwaStatusId: o.shipmentOrderStatusId,
      logiwaStatusName: o.shipmentOrderStatusName,
      lastSyncedAt: syncStart,
    };
    if (!snap.exists) {
      await ref.set({ ...base, rfsState: 'awaiting_putaway', pallets: [], createdAt: syncStart });
      created += 1;
    } else {
      // If this order was archived in a previous sync but Logiwa returned it again,
      // restore it to its prior active state (or awaiting_putaway as a safe default).
      const existing = snap.data();
      const updates = { ...base };
      if (existing.rfsState === 'archived_externally') {
        updates.rfsState = 'awaiting_putaway';
        updates.archivedAt = FieldValue.delete();
        updates.archivedReason = FieldValue.delete();
      }
      await ref.update(updates);
      updated += 1;
    }
  }

  // Archive any active orders that Logiwa did NOT return — they're no longer Ready to Ship
  // (most likely shipped manually in Logiwa). They won't appear in the active list anymore,
  // but stay in the admin history with state `archived_externally`.
  // Note: we use a single-field where + in-memory filter (no composite index required).
  const ACTIVE_STATES = ['awaiting_putaway', 'staged', 'loading', 'loaded'];
  let archived = 0;
  try {
    const activeSnap = await db.collection('rfs_orders')
      .where('rfsState', 'in', ACTIVE_STATES)
      .get();
    const syncStartMs = syncStart.toMillis();
    const stale = activeSnap.docs.filter(d => {
      const t = d.data().lastSyncedAt;
      if (!t) return true; // never synced — shouldn't normally happen, but treat as stale
      return t.toMillis() < syncStartMs;
    });
    for (const doc of stale) {
      await doc.ref.update({
        rfsState: 'archived_externally',
        archivedAt: Timestamp.now(),
        archivedReason: 'No longer Ready to Ship in Logiwa (likely shipped manually).',
      });
      // Free any locations this order was holding
      const o = doc.data();
      for (const p of (o.pallets || [])) {
        if (p.locationCode && p.state !== 'loaded') {
          const locRef = db.collection('rfs_locations').doc(locDocId(p.locationCode));
          locRef.update({ currentPalletOrderId: null, currentPalletOrderCode: null, currentPalletNo: null }).catch(() => {});
        }
      }
      archived += 1;
    }
  } catch (archiveErr) {
    // Archive step is best-effort; a failure here shouldn't break the whole sync
    console.error('archive step error:', archiveErr.message);
  }

  await logEvent({
    type: 'sync.run',
    actor,
    subjectType: 'sync',
    summary: `Fetched ${orders.length}, created ${created}, updated ${updated}, archived ${archived}`,
    meta: { fetched: orders.length, created, updated, archived, source: actor?.uid ? 'user' : 'cron' },
  });

  return { fetched: orders.length, created, updated, archived };
}

// User-triggered sync (manual "Refresh now" button + 5-min interval while app is open)
app.post('/api/rfs/sync', requireAuth, async (req, res) => {
  try {
    const result = await runSync(req.user);
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error('sync error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Cron-triggered sync (Cloud Scheduler hits this every N min). Gated by shared secret.
app.post('/api/cron/sync', async (req, res) => {
  const secret = process.env.CRON_SECRET;
  if (!secret) return res.status(503).json({ error: 'CRON_SECRET not configured' });
  if (req.headers['x-cron-secret'] !== secret) return res.status(401).json({ error: 'Bad cron secret' });
  try {
    const result = await runSync({ uid: 'cron', email: 'cloud-scheduler' });
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error('cron sync error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── List active orders ──────────────────────────────────────────────────────
app.get('/api/rfs/orders', requireAuth, async (req, res) => {
  try {
    const state = req.query.state; // 'awaiting_putaway' | 'staged' | 'loaded' | undefined
    let q;
    if (state) {
      q = db.collection('rfs_orders').where('rfsState', '==', state);
    } else {
      q = db.collection('rfs_orders').where('rfsState', 'not-in', ['shipped', 'archived_externally']);
    }
    const snap = await q.limit(500).get();
    const orders = snap.docs.map(d => shortOrderForList(d.data()));
    res.json({ orders });
  } catch (err) {
    console.error('list orders error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Find one order by Logiwa code (used by mobile scan)
app.get('/api/rfs/orders/by-code/:code', requireAuth, async (req, res) => {
  try {
    const snap = await db.collection('rfs_orders').where('logiwaCode', '==', req.params.code).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: 'Order not found' });
    res.json({ order: snap.docs[0].data() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/rfs/orders/:id', requireAuth, async (req, res) => {
  const snap = await db.collection('rfs_orders').doc(req.params.id).get();
  if (!snap.exists) return res.status(404).json({ error: 'Order not found' });
  res.json({ order: snap.data() });
});

// ─── Putaway ─────────────────────────────────────────────────────────────────
app.post('/api/rfs/orders/:id/putaway', requireAuth, async (req, res) => {
  try {
    const { pallets } = req.body; // [{ palletNo, locationCode?, length?, width?, height?, weight? }]
    if (!Array.isArray(pallets) || pallets.length === 0) {
      return res.status(400).json({ error: 'pallets array required' });
    }

    await db.runTransaction(async (tx) => {
      const orderRef = db.collection('rfs_orders').doc(req.params.id);
      const orderSnap = await tx.get(orderRef);
      if (!orderSnap.exists) throw new Error('Order not found');
      const order = orderSnap.data();
      if (order.rfsState === 'shipped') throw new Error('Order is already shipped');

      const prevByNo = new Map((order.pallets || []).map(p => [p.palletNo, p]));

      // Resolve any provided locationCodes case-insensitively + validate. Empty locationCode is allowed (partial save).
      const locResolved = new Map(); // palletNo -> { ref, code }
      for (const p of pallets) {
        if (!p.locationCode) continue;
        const found = await findLocation(tx, p.locationCode);
        if (!found) throw new Error(`Location ${p.locationCode} not found`);
        const loc = found.snap.data();
        if (loc.lockLocation) throw new Error(`Location ${found.code} is locked`);
        if (loc.preventAllocation) throw new Error(`Location ${found.code} prevents allocation`);
        if (loc.currentPalletOrderId && loc.currentPalletOrderId !== req.params.id) {
          throw new Error(`Location ${found.code} is already holding ${loc.currentPalletOrderCode} pallet ${loc.currentPalletNo}`);
        }
        locResolved.set(p.palletNo, { ref: found.ref, code: found.code });
      }

      // Build new pallets array, merging with previous to preserve timestamps + already-loaded state
      const newPallets = pallets.map(p => {
        const resolved = locResolved.get(p.palletNo);
        const input = { ...p, locationCode: resolved?.code || (p.locationCode ? null : null) };
        // If we resolved a code, use the canonical version
        if (resolved) input.locationCode = resolved.code;
        return mergePallet(p.palletNo, input, prevByNo.get(p.palletNo), req.email);
      });

      const newCodes = new Set(newPallets.filter(p => p.locationCode).map(p => p.locationCode));

      // Free any previously-staged locations no longer referenced by the new pallets array
      for (const old of (order.pallets || [])) {
        if (old.locationCode && !newCodes.has(old.locationCode) && old.state !== 'loaded') {
          const oldLocRef = db.collection('rfs_locations').doc(locDocId(old.locationCode));
          tx.update(oldLocRef, { currentPalletOrderId: null, currentPalletOrderCode: null, currentPalletNo: null });
        }
      }

      // Lock the resolved locations to this order
      for (const [palletNo, { ref }] of locResolved) {
        tx.update(ref, {
          currentPalletOrderId: req.params.id,
          currentPalletOrderCode: order.logiwaCode,
          currentPalletNo: palletNo,
        });
      }

      // Order state: every pallet has a location -> staged. Any missing -> stays awaiting_putaway.
      const allStaged = newPallets.length > 0 && newPallets.every(p => p.locationCode);
      const updates = { pallets: newPallets };
      if (allStaged && order.rfsState === 'awaiting_putaway') {
        updates.rfsState = 'staged';
        updates.stagedAt = Timestamp.now();
        updates.stagedBy = req.email;
      } else if (!allStaged && order.rfsState === 'staged') {
        // Partial save after a previously fully-staged order — revert to awaiting_putaway
        updates.rfsState = 'awaiting_putaway';
      }
      tx.update(orderRef, updates);
    });

    // Re-read the order to grab the canonical pallet info for the audit summary
    const fresh = (await db.collection('rfs_orders').doc(req.params.id).get()).data();
    const summary = (fresh.pallets || [])
      .map(p => `P${p.palletNo}${p.locationCode ? ' @ ' + p.locationCode : ' (pending)'}${p.weight ? ' ' + p.weight + (p.weightUnit||'lb') : ''}`)
      .join(' | ');
    await logEvent({
      type: 'order.staged',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${fresh.logiwaCode}: ${summary}`,
      meta: {
        orderCode: fresh.logiwaCode,
        clientName: fresh.clientName,
        rfsState: fresh.rfsState,
        pallets: fresh.pallets,
      },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('putaway error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// ─── Mark a pallet as loaded ─────────────────────────────────────────────────
app.post('/api/rfs/orders/:id/load-pallet', requireAuth, async (req, res) => {
  try {
    const { palletNo } = req.body;
    if (palletNo === undefined) return res.status(400).json({ error: 'palletNo required' });

    await db.runTransaction(async (tx) => {
      const orderRef = db.collection('rfs_orders').doc(req.params.id);
      // ─── ALL READS FIRST ────────────────────────────────────────────────
      const orderSnap = await tx.get(orderRef);
      if (!orderSnap.exists) throw new Error('Order not found');
      const order = orderSnap.data();
      const targetPallet = (order.pallets || []).find(p => p.palletNo === palletNo);
      let foundLoc = null;
      if (targetPallet?.locationCode && targetPallet.state !== 'loaded') {
        foundLoc = await findLocation(tx, targetPallet.locationCode);
      }

      // ─── THEN ALL WRITES ────────────────────────────────────────────────
      const pallets = (order.pallets || []).map(p => {
        if (p.palletNo === palletNo && p.state !== 'loaded') {
          return { ...p, state: 'loaded', loadedAt: Timestamp.now(), loadedBy: req.email };
        }
        return p;
      });
      const allLoaded = pallets.length > 0 && pallets.every(p => p.state === 'loaded');
      const anyLoaded = pallets.some(p => p.state === 'loaded');
      const updates = { pallets };
      updates.rfsState = allLoaded ? 'loaded' : (anyLoaded ? 'loading' : order.rfsState);
      if (allLoaded) { updates.loadedAt = Timestamp.now(); updates.loadedBy = req.email; }
      tx.update(orderRef, updates);

      if (foundLoc) tx.update(foundLoc.ref, { currentPalletOrderId: null, currentPalletOrderCode: null, currentPalletNo: null });
    });

    const fresh = (await db.collection('rfs_orders').doc(req.params.id).get()).data();
    await logEvent({
      type: 'pallet.loaded',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${fresh.logiwaCode}: P${palletNo} loaded — order now ${fresh.rfsState}`,
      meta: {
        orderCode: fresh.logiwaCode,
        palletNo,
        rfsState: fresh.rfsState,
      },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('load-pallet error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// ─── BOL upload (multipart) ──────────────────────────────────────────────────
app.post('/api/rfs/orders/:id/bol', requireAuth, upload.single('bol'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'BOL file required (field name: bol)' });

    const orderRef = db.collection('rfs_orders').doc(req.params.id);
    const snap = await orderRef.get();
    if (!snap.exists) return res.status(404).json({ error: 'Order not found' });
    const order = snap.data();

    if (order.rfsState !== 'loaded') {
      return res.status(400).json({ error: `Cannot upload BOL while order is in state "${order.rfsState}". All pallets must be loaded first.` });
    }

    // 1. Save the original photo to Firebase Storage (backup for app-side viewing)
    const ts = Date.now();
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const storagePath = `rfs-bols/${order.logiwaCode}/${ts}.${ext}`;
    const file = bucket.file(storagePath);
    await file.save(req.file.buffer, { contentType: req.file.mimetype, resumable: false });
    const [signedUrl] = await file.getSignedUrl({ action: 'read', expires: Date.now() + 10 * 365 * 24 * 60 * 60 * 1000 });

    // 2. Convert to PDF (Logiwa's CarrierLabel slot only accepts PDF) and push as DocumentType=1
    //    with TrackingNumber=order code.
    let logiwaResult = null;
    try {
      const pdfBuffer = await ensurePdf(req.file.buffer, req.file.mimetype);
      logiwaResult = await logiwa.uploadShipmentDocument({
        shipmentOrderIdentifier: order.logiwaIdentifier,
        shipmentOrderCode: order.logiwaCode,
        fileName: `BOL_${order.logiwaCode}_${ts}.pdf`,
        buffer: pdfBuffer,
        mimeType: 'application/pdf',
        trackingNumber: order.logiwaCode,
        documentType: logiwa.DOCUMENT_TYPE_CARRIER_LABEL,
      });
    } catch (logiwaErr) {
      // Don't fail the request — store the upload locally and flag it for retry
      console.error('Logiwa BOL upload failed:', logiwaErr.message);
      await orderRef.update({
        bolPhotoUrl: signedUrl,
        bolStoragePath: storagePath,
        bolUploadedAt: Timestamp.now(),
        bolUploadedBy: req.email,
        logiwaUploadError: logiwaErr.message,
        logiwaUploadAttemptedAt: Timestamp.now(),
      });
      return res.status(502).json({ error: 'BOL saved but Logiwa upload failed', detail: logiwaErr.message, bolPhotoUrl: signedUrl });
    }

    // 3. Mark order shipped
    await orderRef.update({
      bolPhotoUrl: signedUrl,
      bolStoragePath: storagePath,
      bolUploadedAt: Timestamp.now(),
      bolUploadedBy: req.email,
      logiwaDocumentResult: logiwaResult,
      logiwaUploadError: FieldValue.delete(),
      rfsState: 'shipped',
      shippedAt: Timestamp.now(),
      shippedBy: req.email,
    });

    await logEvent({
      type: 'bol.uploaded',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${order.logiwaCode}: BOL uploaded → shipped`,
      meta: {
        orderCode: order.logiwaCode,
        clientName: order.clientName,
        storagePath,
        logiwaDocumentResult: logiwaResult,
      },
    });

    res.json({ ok: true, bolPhotoUrl: signedUrl, logiwaDocumentResult: logiwaResult });
  } catch (err) {
    console.error('bol upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Locations ───────────────────────────────────────────────────────────────
// Available locations for putaway, sorted with "26-*" first
app.get('/api/rfs/locations/available', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const snap = await db.collection('rfs_locations')
      .where('hasInventory', '==', false)
      .where('preventAllocation', '==', false)
      .where('lockLocation', '==', false)
      .where('currentPalletOrderId', '==', null)
      .orderBy('priorityRank', 'asc')
      .orderBy('code', 'asc')
      .limit(limit)
      .get();
    res.json({ locations: snap.docs.map(d => d.data()) });
  } catch (err) {
    console.error('available locations error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Single location lookup (used after a barcode scan) — case-insensitive, matches code or barcode
// Returns the location plus the pallet/order currently held there (if any).
app.get('/api/rfs/locations/:code', requireAuth, async (req, res) => {
  const found = await findLocation(null, req.params.code);
  if (!found) return res.status(404).json({ error: 'Location not found' });
  const location = found.snap.data();

  let currentOrder = null;
  let currentPallet = null;
  if (location.currentPalletOrderId) {
    const orderSnap = await db.collection('rfs_orders').doc(location.currentPalletOrderId).get();
    if (orderSnap.exists) {
      const o = orderSnap.data();
      currentOrder = {
        logiwaIdentifier: o.logiwaIdentifier,
        logiwaCode: o.logiwaCode,
        clientName: o.clientName,
        customerName: o.customerName,
        shipmentOrderTypeName: o.shipmentOrderTypeName,
        rfsState: o.rfsState,
        expectedShipmentDate: o.expectedShipmentDate,
      };
      currentPallet = (o.pallets || []).find(p => p.palletNo === location.currentPalletNo) || null;
    }
  }

  res.json({ location, currentOrder, currentPallet });
});

// Reports/admin: list all locations (paginated, simple) — read-only for supervisor/csm
app.get('/api/rfs/locations', requireAuth, requireRole(...REPORT_ROLES), async (req, res) => {
  const snap = await db.collection('rfs_locations').orderBy('code').limit(500).get();
  res.json({ locations: snap.docs.map(d => d.data()), count: snap.size });
});

// ─── Reports: order history with full timestamps ─────────────────────────────
app.get('/api/rfs/admin/orders', requireAuth, requireRole(...REPORT_ROLES), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '30', 10), 365);
    const since = Timestamp.fromMillis(Date.now() - days * 24 * 60 * 60 * 1000);
    // Pull recent orders by createdAt (covers active + recently-shipped). Also pull active.
    const [recentSnap, activeSnap] = await Promise.all([
      db.collection('rfs_orders').where('createdAt', '>=', since).orderBy('createdAt', 'desc').limit(500).get(),
      db.collection('rfs_orders').where('rfsState', '!=', 'shipped').limit(500).get(),
    ]);
    const seen = new Set();
    const merged = [];
    for (const d of [...recentSnap.docs, ...activeSnap.docs]) {
      if (seen.has(d.id)) continue;
      seen.add(d.id);
      const o = d.data();
      // Hide externally-shipped orders from the history — they don't matter to CSM.
      if (o.rfsState === 'archived_externally') continue;
      const pallets = o.pallets || [];
      const stagedAts = pallets.filter(p => p.stagedAt).map(p => p.stagedAt);
      const loadedAts = pallets.filter(p => p.state === 'loaded' && p.loadedAt).map(p => p.loadedAt);
      merged.push({
        logiwaIdentifier: o.logiwaIdentifier,
        logiwaCode: o.logiwaCode,
        shipmentOrderTypeName: o.shipmentOrderTypeName,
        clientName: o.clientName,
        customerName: o.customerName,
        rfsState: o.rfsState,
        palletCount: pallets.length,
        palletsLoaded: pallets.filter(p => p.state === 'loaded').length,
        firstStagedAt: stagedAts.length ? stagedAts.reduce((a, b) => a.toMillis() < b.toMillis() ? a : b) : null,
        lastStagedAt: stagedAts.length ? stagedAts.reduce((a, b) => a.toMillis() > b.toMillis() ? a : b) : null,
        stagedBy: o.stagedBy || null,
        firstLoadedAt: loadedAts.length ? loadedAts.reduce((a, b) => a.toMillis() < b.toMillis() ? a : b) : null,
        lastLoadedAt: loadedAts.length ? loadedAts.reduce((a, b) => a.toMillis() > b.toMillis() ? a : b) : null,
        loadedBy: o.loadedBy || null,
        bolUploadedAt: o.bolUploadedAt || null,
        bolUploadedBy: o.bolUploadedBy || null,
        shippedAt: o.shippedAt || null,
        shippedBy: o.shippedBy || null,
        bolPhotoUrl: o.bolPhotoUrl || null,
        pallets,
      });
    }
    merged.sort((a, b) => {
      const am = a.shippedAt?.toMillis?.() || a.lastStagedAt?.toMillis?.() || 0;
      const bm = b.shippedAt?.toMillis?.() || b.lastStagedAt?.toMillis?.() || 0;
      return bm - am;
    });
    res.json({ orders: merged });
  } catch (err) {
    console.error('admin orders error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Purchase Order receiving ────────────────────────────────────────────────
// List pending POs (Logiwa status = Pending) for the eShipper+ warehouse.
// Optional ?client=Name filter narrows to one client.
app.get('/api/rfs/pos/pending', requireAuth, async (req, res) => {
  try {
    const wh = process.env.LOGIWA_ESHIPPER_WH_IDENTIFIER || undefined;
    const all = await logiwa.listPendingPurchaseOrders({ warehouseIdentifier: wh });
    const client = req.query.client;
    const filtered = client ? all.filter(p => p.clientDisplayName === client) : all;
    // Build short summaries — full payload is bigger than we need
    const pos = filtered
      .map(p => ({
        identifier: p.identifier,
        code: p.code,
        vendorDisplayName: p.vendorDisplayName,
        clientName: p.clientDisplayName,
        purchaseOrderTypeName: p.purchaseOrderTypeName,
        plannedArrivalDate: p.plannedArrivalDate,
        plannedReceivingDate: p.plannedReceivingDate,
        totalQuantity: p.totalQuantity || 0,
        purchaseOrderStatusName: p.purchaseOrderStatusName,
      }))
      .sort((a, b) => (a.plannedArrivalDate || '').localeCompare(b.plannedArrivalDate || ''));
    const clients = [...new Set(all.map(p => p.clientDisplayName).filter(Boolean))].sort();
    res.json({ pos, clients, total: all.length });
  } catch (err) {
    console.error('pending POs error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Lookup a PO by scanned code; return summary the worker needs to confirm before receiving.
app.get('/api/rfs/pos/by-code/:code', requireAuth, async (req, res) => {
  try {
    const wh = process.env.LOGIWA_ESHIPPER_WH_IDENTIFIER || undefined;
    const po = await logiwa.findPurchaseOrderByCode(req.params.code, { warehouseIdentifier: wh });
    if (!po) return res.status(404).json({ error: `Purchase order ${req.params.code} not found` });
    // Mirror to Firestore so the receipt stream is queryable for the admin view
    const ref = db.collection('rfs_pos').doc(po.identifier);
    const snap = await ref.get();
    const base = {
      logiwaIdentifier: po.identifier,
      logiwaCode: po.code,
      vendorDisplayName: po.vendorDisplayName,
      clientIdentifier: po.clientIdentifier,
      clientName: po.clientDisplayName,
      purchaseOrderTypeName: po.purchaseOrderTypeName,
      logiwaStatusName: po.purchaseOrderStatusName,
      logiwaStatusId: po.purchaseOrderStatusId,
      warehouseIdentifier: po.warehouseIdentifier,
      plannedArrivalDate: po.plannedArrivalDate || null,
      plannedReceivingDate: po.plannedReceivingDate || null,
      actualArrivalDate: po.actualArrivalDate || null,
      currencyCode: po.currencyCode || null,
      purchaseOrderDate: po.purchaseOrderDate || null,
      referenceNumber: po.referenceNumber || null,
      totalQuantity: po.totalQuantity || 0,
      lastSyncedAt: Timestamp.now(),
    };
    if (snap.exists) await ref.update(base);
    else await ref.set({ ...base, createdAt: Timestamp.now(), state: 'pending' });
    const local = (await ref.get()).data();
    res.json({ po: { ...local, raw: po } });
  } catch (err) {
    console.error('PO lookup error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Receive a PO: capture receiptType + count, attach POD photo, set actualArrivalDate in Logiwa.
app.post('/api/rfs/pos/:identifier/arrive', requireAuth, upload.single('pod'), async (req, res) => {
  try {
    const { receiptType, count, note } = req.body;
    if (!receiptType) return res.status(400).json({ error: 'receiptType required' });
    if (!['boxes', 'pallets', 'container'].includes(receiptType)) {
      return res.status(400).json({ error: 'receiptType must be boxes, pallets, or container' });
    }
    const countNum = parseFloat(count);
    if (!countNum || countNum <= 0) return res.status(400).json({ error: 'count required and must be > 0' });
    if (!req.file) return res.status(400).json({ error: 'POD file required (field name: pod)' });

    const ref = db.collection('rfs_pos').doc(req.params.identifier);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'PO not found in app — scan via /api/rfs/pos/by-code first' });
    const po = snap.data();

    const ts = Date.now();
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const storagePath = `rfs-pods/${po.logiwaCode}/${ts}.${ext}`;
    const file = bucket.file(storagePath);
    await file.save(req.file.buffer, { contentType: req.file.mimetype, resumable: false });
    const [signedUrl] = await file.getSignedUrl({ action: 'read', expires: Date.now() + 10 * 365 * 24 * 60 * 60 * 1000 });

    // Convert to PDF for Logiwa (same constraint as BOL)
    const pdfBuffer = await ensurePdf(req.file.buffer, req.file.mimetype);

    let logiwaDocResult = null;
    let logiwaUpdateResult = null;
    let logiwaError = null;

    try {
      logiwaDocResult = await logiwa.uploadPurchaseOrderDocument({
        purchaseOrderIdentifier: po.logiwaIdentifier,
        purchaseOrderCode: po.logiwaCode,
        fileName: `POD_${po.logiwaCode}_${ts}.pdf`,
        buffer: pdfBuffer,
        mimeType: 'application/pdf',
        documentType: logiwa.DOCUMENT_TYPE_EXTERNAL,
      });
    } catch (e) {
      logiwaError = `POD upload to Logiwa failed: ${e.message}`;
      console.error(logiwaError);
    }

    // Set actualArrivalDate in Logiwa via full-PUT. Build the body explicitly because the
    // /list and /detail responses use different field names than /update expects, and we
    // need the lines (from /detail) plus the metadata (from /list, cached in rfs_pos).
    try {
      let currencyId = null;
      if (po.currencyCode) {
        try {
          const map = await logiwa.getCurrencyIdMap();
          currencyId = map[po.currencyCode] || null;
        } catch { /* fall through */ }
      }

      // Fetch lines from /detail and map response → request shape
      let purchaseOrderLineList = [];
      try {
        const detail = await logiwa.getPurchaseOrderDetail(po.logiwaIdentifier);
        purchaseOrderLineList = (detail.purchaseOrderLineList || []).map(l => ({
          sku: l.sku || null,
          packType: l.linePackTypeName || null,
          licensePlateType: l.licensePlateTypeCode || null,
          licensePlateNumber: l.licensePlateNumber || null,
          warehouseLocation: l.warehouseLocationCode || null,
          packQuantity: l.linePackQuantity ?? null,
          unitPrice: l.lineUnitPrice ?? null,
          taxRate: 0,
          note: l.note || null,
          lotBatchNumber: l.lotBatchNumber || null,
          expiryDate: l.expiryDate || null,
          productionDate: l.productionDate || null,
        }));
      } catch (e) {
        console.error('PO line fetch error:', e.message);
      }

      const updateBody = {
        identifier: po.logiwaIdentifier,
        code: po.logiwaCode,
        vendor: po.vendorDisplayName,
        purchaseOrderTypeName: po.purchaseOrderTypeName,
        currencyId,
        clientIdentifier: po.clientIdentifier,
        warehouseIdentifier: po.warehouseIdentifier,
        purchaseOrderDate: po.purchaseOrderDate || null,
        plannedArrivalDate: po.plannedArrivalDate || null,
        plannedReceivingDate: po.plannedReceivingDate || null,
        referenceNumber: po.referenceNumber || null,
        actualArrivalDate: new Date().toISOString(),
        purchaseOrderLineList,
      };
      logiwaUpdateResult = await logiwa.updatePurchaseOrder(updateBody);
    } catch (e) {
      logiwaError = (logiwaError ? logiwaError + ' | ' : '') + `Arrival-date update failed: ${e.message}`;
      console.error('PO update error:', e.message);
    }

    await ref.update({
      state: 'arrived',
      receiptType,
      count: countNum,
      receiveNote: note || null,
      podPhotoUrl: signedUrl,
      podStoragePath: storagePath,
      logiwaDocResult: logiwaDocResult || null,
      logiwaUpdateResult: logiwaUpdateResult || null,
      logiwaError: logiwaError || FieldValue.delete(),
      arrivedAt: Timestamp.now(),
      arrivedBy: req.email,
    });

    await logEvent({
      type: 'po.arrived',
      actor: req.user,
      subjectType: 'po',
      subjectId: req.params.identifier,
      summary: `PO ${po.logiwaCode} (${po.clientName || '—'}): ${countNum} ${receiptType}${logiwaError ? ' — Logiwa sync issue' : ''}`,
      meta: {
        poCode: po.logiwaCode,
        clientName: po.clientName,
        receiptType,
        count: countNum,
        logiwaError: logiwaError || null,
      },
    });

    res.json({ ok: true, podPhotoUrl: signedUrl, logiwaError });
  } catch (err) {
    console.error('PO arrive error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Record an arrival WITHOUT a Logiwa PO — for shipments that arrive before a PO was created.
// No Logiwa write; everything is stored in rfs_pos with isBlind: true.
app.post('/api/rfs/blind-receipt', requireAuth, upload.single('pod'), async (req, res) => {
  try {
    const { receiptType, count, clientName, clientIdentifier, vendorName, note } = req.body;
    if (!['boxes', 'pallets', 'container'].includes(receiptType)) {
      return res.status(400).json({ error: 'receiptType must be boxes, pallets, or container' });
    }
    const countNum = parseFloat(count);
    if (!countNum || countNum <= 0) return res.status(400).json({ error: 'count required and must be > 0' });
    if (!req.file) return res.status(400).json({ error: 'POD file required (field name: pod)' });

    const ref = db.collection('rfs_pos').doc(); // Firestore auto-id
    const ts = Date.now();
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const clientSlug = (clientName || 'no-client').toString().replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30) || 'no-client';
    const storagePath = `rfs-pods/blind/${clientSlug}/${ts}.${ext}`;
    const file = bucket.file(storagePath);
    await file.save(req.file.buffer, { contentType: req.file.mimetype, resumable: false });
    const [signedUrl] = await file.getSignedUrl({ action: 'read', expires: Date.now() + 10 * 365 * 24 * 60 * 60 * 1000 });

    await ref.set({
      isBlind: true,
      logiwaIdentifier: null,
      logiwaCode: null,
      clientIdentifier: clientIdentifier || null,
      clientName: clientName || null,
      vendorDisplayName: vendorName || null,
      receiptType,
      count: countNum,
      receiveNote: note || null,
      podPhotoUrl: signedUrl,
      podStoragePath: storagePath,
      state: 'arrived',
      arrivedAt: Timestamp.now(),
      arrivedBy: req.email,
      createdAt: Timestamp.now(),
    });

    await logEvent({
      type: 'po.blind_received',
      actor: req.user,
      subjectType: 'po',
      subjectId: ref.id,
      summary: `Blind receipt (${clientName || 'client unknown'}): ${countNum} ${receiptType}${vendorName ? ' from ' + vendorName : ''}`,
      meta: {
        clientName: clientName || null,
        vendorName: vendorName || null,
        receiptType,
        count: countNum,
      },
    });

    res.json({ ok: true, id: ref.id, podPhotoUrl: signedUrl });
  } catch (err) {
    console.error('blind receipt error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Distinct client names seen in our data (for the blind-receipt client autocomplete)
app.get('/api/rfs/clients', requireAuth, async (req, res) => {
  try {
    const set = new Set();
    const [oSnap, pSnap] = await Promise.all([
      db.collection('rfs_orders').limit(500).get(),
      db.collection('rfs_pos').limit(500).get(),
    ]);
    for (const d of oSnap.docs) { const c = d.data().clientName; if (c) set.add(c); }
    for (const d of pSnap.docs) { const c = d.data().clientName; if (c) set.add(c); }
    res.json({ clients: [...set].sort() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Reports: audit event log (every state change captured by logEvent)
app.get('/api/rfs/admin/events', requireAuth, requireRole(...REPORT_ROLES), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '7', 10), 365);
    const limit = Math.min(parseInt(req.query.limit || '500', 10), 2000);
    const since = Timestamp.fromMillis(Date.now() - days * 24 * 60 * 60 * 1000);
    let q = db.collection('rfs_events').where('at', '>=', since).orderBy('at', 'desc').limit(limit);
    if (req.query.type) q = q.where('type', '==', req.query.type);
    const snap = await q.get();
    res.json({ events: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
  } catch (err) {
    console.error('events query error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Reports: recent PO receipts (with optional days window)
app.get('/api/rfs/admin/pos', requireAuth, requireRole(...REPORT_ROLES), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '30', 10), 365);
    const since = Timestamp.fromMillis(Date.now() - days * 24 * 60 * 60 * 1000);
    const snap = await db.collection('rfs_pos').where('arrivedAt', '>=', since).orderBy('arrivedAt', 'desc').limit(500).get();
    res.json({ pos: snap.docs.map(d => d.data()) });
  } catch (err) {
    console.error('admin pos error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── User invites (admin) ────────────────────────────────────────────────────
// Create or invite a user. If password is provided, the Firebase Auth account is created
// immediately (admin-set credentials, user can sign in right away). If password is omitted,
// we drop an invite doc and the user self-signs-up via Google or email/password on first visit.
app.post('/api/rfs/invites', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { email, role, password, displayName } = req.body;
    if (!email || !ROLES.includes(role)) return res.status(400).json({ error: 'email and valid role required' });
    const emailLower = email.toLowerCase();

    if (password) {
      if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      // Create the Firebase Auth user. If they already exist, look them up so we can attach the role.
      let userRecord;
      try {
        userRecord = await auth.createUser({ email: emailLower, password, displayName: displayName || emailLower });
      } catch (e) {
        if (e.code === 'auth/email-already-exists') {
          userRecord = await auth.getUserByEmail(emailLower);
        } else {
          throw e;
        }
      }
      // Stamp the role onto rfs_users (the API reads this on every request).
      await db.collection('rfs_users').doc(userRecord.uid).set({
        uid: userRecord.uid,
        email: emailLower,
        displayName: displayName || userRecord.displayName || emailLower,
        role,
        createdAt: Timestamp.now(),
        createdBy: req.email,
      }, { merge: true });
      // Drop any pending invite for this email — it's been consumed.
      await db.collection('rfs_invites').doc(emailLower).delete().catch(() => {});

      await logEvent({
        type: 'user.created',
        actor: req.user,
        subjectType: 'user',
        subjectId: userRecord.uid,
        summary: `Created ${emailLower} as ${role}`,
        meta: { email: emailLower, role, uid: userRecord.uid },
      });
      return res.json({ ok: true, mode: 'created', uid: userRecord.uid });
    }

    // No password — just drop an invite for first-login lookup.
    await db.collection('rfs_invites').doc(emailLower).set({
      email: emailLower, role, invitedBy: req.email, invitedAt: Timestamp.now(),
    });
    await logEvent({
      type: 'user.invited',
      actor: req.user,
      subjectType: 'user',
      subjectId: emailLower,
      summary: `Invited ${emailLower} as ${role}`,
      meta: { email: emailLower, role },
    });
    res.json({ ok: true, mode: 'invited' });
  } catch (err) {
    console.error('invite error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// Admin: list all users + pending invites
app.get('/api/rfs/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const [usersSnap, invitesSnap] = await Promise.all([
      db.collection('rfs_users').limit(500).get(),
      db.collection('rfs_invites').limit(500).get(),
    ]);
    const users = usersSnap.docs.map(d => {
      const u = d.data();
      return {
        uid: u.uid,
        email: u.email,
        displayName: u.displayName || '',
        role: u.role,
        disabled: !!u.disabled,
        lastSeen: u.lastSeen || null,
        createdAt: u.createdAt || null,
        status: 'active',
      };
    });
    const invites = invitesSnap.docs.map(d => {
      const i = d.data();
      return {
        uid: null,
        email: i.email,
        displayName: '',
        role: i.role,
        disabled: false,
        lastSeen: null,
        createdAt: i.invitedAt || null,
        status: 'invited',
      };
    });
    // De-dup: if an active user already exists for an invited email, drop the invite row
    const activeEmails = new Set(users.map(u => u.email));
    const merged = [...users, ...invites.filter(i => !activeEmails.has(i.email))];
    merged.sort((a, b) => (a.email || '').localeCompare(b.email || ''));
    res.json({ users: merged });
  } catch (err) {
    console.error('users list error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Admin: change a user's role
app.put('/api/rfs/admin/users/:uid/role', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { role } = req.body;
    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
    if (req.params.uid === req.user.uid) return res.status(400).json({ error: "Can't change your own role" });
    await db.collection('rfs_users').doc(req.params.uid).update({ role });
    await logEvent({ type: 'user.role_changed', actor: req.user, subjectType: 'user', subjectId: req.params.uid, summary: `Role → ${role}`, meta: { role } });
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Admin: disable / re-enable a user (blocks future sign-in but preserves history)
app.put('/api/rfs/admin/users/:uid/disabled', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const disabled = !!req.body.disabled;
    if (req.params.uid === req.user.uid) return res.status(400).json({ error: "Can't disable yourself" });
    await auth.updateUser(req.params.uid, { disabled });
    await db.collection('rfs_users').doc(req.params.uid).update({ disabled });
    await logEvent({ type: disabled ? 'user.disabled' : 'user.enabled', actor: req.user, subjectType: 'user', subjectId: req.params.uid });
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Admin: cancel a pending invite (email never signed in)
app.delete('/api/rfs/admin/invites/:email', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    await db.collection('rfs_invites').doc(req.params.email.toLowerCase()).delete();
    await logEvent({ type: 'user.invite_cancelled', actor: req.user, subjectType: 'user', subjectId: req.params.email.toLowerCase() });
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// ─── Digital Asset Links — needed for the Android TWA APK to run full-screen ──
// Generated via PWABuilder. Lives inline so a redeploy is the only step to publish updates.
app.get('/.well-known/assetlinks.json', (req, res) => {
  res.json([{
    relation: ['delegate_permission/common.handle_all_urls'],
    target: {
      namespace: 'android_app',
      package_name: 'app.run.northamerica_northeast1.eshipperplus_rfs_960206640545.twa',
      sha256_cert_fingerprints: ['2E:6E:02:C7:13:75:A8:0B:B3:3B:32:B1:AD:AC:13:DD:06:9F:A6:1F:75:B0:14:CC:0D:D9:E9:FF:D8:E7:ED:29'],
    },
  }]);
});

// ─── SPA fallback ────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`eshipperplus-rfs listening on :${PORT}`));
