'use strict';

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');
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
  const evt = {
    at: Timestamp.now(),
    type,
    actor: actor ? { uid: actor.uid || null, email: actor.email || null, displayName: actor.displayName || null } : null,
    subjectType: subjectType || null,
    subjectId: subjectId || null,
    summary: summary || null,
    meta: meta || {},
  };
  try {
    await db.collection('rfs_events').add(evt);
  } catch (err) {
    console.error('[audit] failed to log', type, err.message);
  }
  // Fire notifications async — never blocks the action that triggered the event.
  dispatchNotifications(evt).catch(err => console.error('[notify] dispatch error:', err.message));
}

// ─── Email + notification rules ──────────────────────────────────────────────
// Uses Gmail SMTP via nodemailer (same pattern as warehouse-billing). Set
// SMTP_USER + SMTP_PASS env vars (Gmail address + app password).
const _mailer = (process.env.SMTP_USER && process.env.SMTP_PASS)
  ? nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } })
  : null;

async function sendEmail(to, subject, html) {
  if (!_mailer) {
    console.warn('[email] SMTP not configured — skipping email to', to, 'subject:', subject);
    return { skipped: true };
  }
  try {
    await _mailer.sendMail({ from: `eShipper+ RFS <${process.env.SMTP_USER}>`, to, subject, html });
    return { sent: true };
  } catch (err) {
    console.error('[email] send failed:', err.message);
    return { error: err.message };
  }
}

// Notification rules — stored in Firestore `rfs_notification_rules`.
// Schema: { event, clientName | null (null = any), recipients: string[],
//           condition: 'always' | 'has_dims' | 'has_weight', enabled, createdAt, createdBy }
// `event` matches a logEvent type (order.staged, bol.uploaded, po.arrived, po.blind_received, etc.)
async function dispatchNotifications(event) {
  try {
    const rulesSnap = await db.collection('rfs_notification_rules')
      .where('enabled', '==', true)
      .where('event', '==', event.type)
      .get();
    if (rulesSnap.empty) return;

    for (const ruleDoc of rulesSnap.docs) {
      const rule = ruleDoc.data();
      // Client filter (null = all clients)
      if (rule.clientName && rule.clientName !== '*' && event.meta?.clientName !== rule.clientName) continue;
      // Condition gating
      if (rule.condition === 'has_dims') {
        const pallets = event.meta?.pallets || [];
        const anyDims = pallets.some(p => p.length || p.width || p.height);
        if (!anyDims) continue;
      } else if (rule.condition === 'has_weight') {
        const pallets = event.meta?.pallets || [];
        const anyWt = pallets.some(p => p.weight);
        if (!anyWt) continue;
      }

      const recipients = (rule.recipients || []).filter(Boolean);
      if (!recipients.length) continue;
      const subject = renderEmailSubject(event);
      const html = renderEmailBody(event);
      await sendEmail(recipients.join(','), subject, html);
    }
  } catch (err) {
    console.error('[notifications] dispatch failed:', err.message);
  }
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c]));
}

function renderEmailSubject(event) {
  const m = event.meta || {};
  switch (event.type) {
    case 'order.staged': {
      const who = m.companyName || m.customerName ||
        [m.customerFirstName, m.customerLastName].filter(Boolean).join(' ') ||
        m.clientName || '';
      return `${m.orderCode || ''}${who ? ' · ' + who : ''}`;
    }
    case 'bol.uploaded': return `RFS shipped · ${m.orderCode || ''} · ${m.clientName || ''}`;
    case 'po.arrived':  return `PO received · ${m.poCode || ''} · ${m.clientName || ''}`;
    case 'po.blind_received': return `Blind receipt · ${m.clientName || 'client unknown'} · ${m.count} ${m.receiptType}`;
    default: return `RFS event · ${event.type}`;
  }
}

function renderEmailBody(event) {
  if (event.type === 'order.staged') return renderOrderStagedBody(event);
  // Generic table body for everything else (BOL upload, PO arrive, etc.)
  const m = event.meta || {};
  const palletList = (m.pallets || []).map(p => {
    const dims = (p.length || p.width || p.height) ? `${p.length || '—'}×${p.width || '—'}×${p.height || '—'} ${esc(p.dimensionUnit || 'in')}` : '';
    const wt = p.weight ? `${p.weight} ${esc(p.weightUnit || 'lb')}` : '';
    return `<tr><td style="padding:4px 12px 4px 0">P${p.palletNo}</td><td style="padding:4px 12px 4px 0">${esc(p.locationCode || '—')}</td><td style="padding:4px 12px 4px 0">${dims}</td><td style="padding:4px 0">${wt}</td></tr>`;
  }).join('');
  return `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:14px;color:#1a1a1a">
      <p><strong>${esc(event.summary || event.type)}</strong></p>
      <table cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:13px">
        ${event.actor?.email ? `<tr><td style="padding:2px 12px 2px 0;color:#666">By</td><td>${esc(event.actor.email)}</td></tr>` : ''}
        ${m.orderCode ? `<tr><td style="padding:2px 12px 2px 0;color:#666">Order</td><td>${esc(m.orderCode)}</td></tr>` : ''}
        ${m.poCode ? `<tr><td style="padding:2px 12px 2px 0;color:#666">PO</td><td>${esc(m.poCode)}</td></tr>` : ''}
        ${m.clientName ? `<tr><td style="padding:2px 12px 2px 0;color:#666">Client</td><td>${esc(m.clientName)}</td></tr>` : ''}
        ${m.receiptType ? `<tr><td style="padding:2px 12px 2px 0;color:#666">Received</td><td>${esc(m.count + ' ' + m.receiptType)}</td></tr>` : ''}
      </table>
      ${palletList ? `<p style="margin-top:14px"><strong>Pallets</strong></p>
        <table cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:13px">
          <tr style="color:#666"><td style="padding:2px 12px 2px 0">#</td><td style="padding:2px 12px 2px 0">Location</td><td style="padding:2px 12px 2px 0">Dims</td><td style="padding:2px 0">Weight</td></tr>
          ${palletList}
        </table>` : ''}
      <p style="margin-top:14px;color:#777;font-size:12px">eShipper+ RFS · automated notification</p>
    </div>
  `;
}

// Dedicated template for "putaway done" — what CSM gets when an order is staged.
function renderOrderStagedBody(event) {
  const m = event.meta || {};
  const pallets = m.pallets || [];
  const palletLines = pallets.map(p => {
    const dimsParts = [p.length, p.width, p.height].map(v => v == null || v === '' ? '—' : v);
    const dims = (p.length || p.width || p.height)
      ? `${dimsParts[0]}×${dimsParts[1]}×${dimsParts[2]} ${esc(p.dimensionUnit || 'in')}`
      : 'dims not recorded';
    const wt = p.weight ? `${p.weight} ${esc(p.weightUnit || 'lb')}` : 'weight not recorded';
    return `<li style="margin-bottom:4px"><strong>P${p.palletNo}</strong>: ${dims} · ${wt}</li>`;
  }).join('');

  // Build address rows only for fields that are populated, keep CSM-friendly labels.
  const addressFields = [
    ['First name',    m.customerFirstName],
    ['Last name',     m.customerLastName],
    ['Phone',         m.shipmentPhoneNumber],
    ['Email',         m.customerEmail],
    ['Address line 1', m.shipmentAddressLine1],
    ['Address line 2', m.shipmentAddressLine2],
    ['City',          m.shipmentCity],
    ['State / region', m.shipmentStateOrRegionName],
    ['Postal code',   m.shipmentPostalCode],
    ['Country',       m.shipmentCountryCode],
  ];
  const addressRows = addressFields
    .filter(([, v]) => v)
    .map(([k, v]) => `<tr><td style="padding:2px 14px 2px 0;color:#666;white-space:nowrap">${k}</td><td>${esc(v)}</td></tr>`)
    .join('');

  return `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:14px;color:#1a1a1a;line-height:1.5">
      <p>Hi Team,</p>
      <p>The order has <strong>${pallets.length}</strong> pallet${pallets.length === 1 ? '' : 's'} and here are dims and weight:</p>
      <ul style="margin:8px 0 14px;padding-left:22px">${palletLines}</ul>

      <p style="margin-top:16px"><strong>Shipping address</strong></p>
      <table cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:13px;margin-top:4px">
        ${addressRows || '<tr><td style="color:#999">(no address on the order in Logiwa)</td></tr>'}
      </table>

      <table cellspacing="0" cellpadding="0" style="margin-top:18px;border-collapse:collapse;font-size:13px;color:#444">
        <tr><td style="padding:2px 14px 2px 0;color:#666">Order</td><td><strong>${esc(m.orderCode || '')}</strong></td></tr>
        ${m.clientName ? `<tr><td style="padding:2px 14px 2px 0;color:#666">Client</td><td>${esc(m.clientName)}</td></tr>` : ''}
        ${m.companyName ? `<tr><td style="padding:2px 14px 2px 0;color:#666">Company</td><td>${esc(m.companyName)}</td></tr>` : ''}
      </table>

      <p style="margin-top:18px;color:#777;font-size:12px">eShipper+ RFS · automated notification</p>
    </div>
  `;
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
// Returns { ref, snap, code, isFloor? } where `code` is the canonical form from the stored doc.
// Special case: "Floor" (any case) resolves to a pseudo-location with `isFloor: true`. The Floor
// has no Firestore doc and no occupancy lock — many pallets can sit on the warehouse floor.
async function findLocation(tx, codeInput) {
  if (!codeInput) return null;
  const q = String(codeInput).trim();
  if (q.toLowerCase() === 'floor') {
    return { ref: null, snap: null, code: 'Floor', isFloor: true };
  }
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
      customerFirstName: o.customerFirstName || null,
      customerLastName: o.customerLastName || null,
      customerEmail: o.customerEmail || null,
      companyName: o.companyName || null,
      shipmentAddressLine1: o.shipmentAddressLine1 || null,
      shipmentAddressLine2: o.shipmentAddressLine2 || null,
      shipmentCity: o.shipmentCity || null,
      shipmentPostalCode: o.shipmentPostalCode || null,
      shipmentStateOrRegionName: o.shipmentStateOrRegionName || null,
      shipmentCountryCode: o.shipmentCountryCode || null,
      shipmentPhoneNumber: o.shipmentPhoneNumber || null,
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

// Find one order by Logiwa code (used by mobile scan) — case-insensitive.
// Tries the input as-typed, then upper, then lower. Logiwa codes are usually consistent
// per order but workers often type them with different casing.
app.get('/api/rfs/orders/by-code/:code', requireAuth, async (req, res) => {
  try {
    const q = String(req.params.code).trim();
    const candidates = [...new Set([q, q.toUpperCase(), q.toLowerCase()])];
    for (const c of candidates) {
      const snap = await db.collection('rfs_orders').where('logiwaCode', '==', c).limit(1).get();
      if (!snap.empty) return res.json({ order: snap.docs[0].data() });
    }
    res.status(404).json({ error: 'Order not found' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/rfs/orders/:id', requireAuth, async (req, res) => {
  const snap = await db.collection('rfs_orders').doc(req.params.id).get();
  if (!snap.exists) return res.status(404).json({ error: 'Order not found' });
  res.json({ order: snap.data() });
});

// Edit the internal note on an order. Intentionally NEVER included in event meta
// or notification emails — it's a free-text scratchpad for the warehouse team.
app.put('/api/rfs/orders/:id/note', requireAuth, async (req, res) => {
  try {
    const note = (req.body.note ?? '').toString();
    const ref = db.collection('rfs_orders').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Order not found' });
    const updates = {
      internalNote: note || FieldValue.delete(),
      internalNoteUpdatedAt: note ? Timestamp.now() : FieldValue.delete(),
      internalNoteUpdatedBy: note ? req.email : FieldValue.delete(),
    };
    await ref.update(updates);
    // Audit-log the change (the note text itself is captured for traceability,
    // but emails for this event type are intentionally not subscribed by default).
    await logEvent({
      type: 'order.note_updated',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${snap.data().logiwaCode}: note ${note ? 'updated' : 'cleared'}`,
      meta: { orderCode: snap.data().logiwaCode, hasNote: !!note },
    });
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
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
      const locResolved = new Map(); // palletNo -> { ref, code, isFloor }
      for (const p of pallets) {
        if (!p.locationCode) continue;
        const found = await findLocation(tx, p.locationCode);
        if (!found) throw new Error(`Location ${p.locationCode} not found`);
        // Floor is special — many pallets can sit on the floor; skip the lock/occupancy checks.
        if (!found.isFloor) {
          const loc = found.snap.data();
          if (loc.lockLocation) throw new Error(`Location ${found.code} is locked`);
          if (loc.preventAllocation) throw new Error(`Location ${found.code} prevents allocation`);
          if (loc.currentPalletOrderId && loc.currentPalletOrderId !== req.params.id) {
            throw new Error(`Location ${found.code} is already holding ${loc.currentPalletOrderCode} pallet ${loc.currentPalletNo}`);
          }
        }
        locResolved.set(p.palletNo, { ref: found.ref, code: found.code, isFloor: !!found.isFloor });
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

      // Free any previously-staged locations no longer referenced by the new pallets array.
      // Floor is skipped — there's no doc to free.
      for (const old of (order.pallets || [])) {
        if (old.locationCode && !newCodes.has(old.locationCode) && old.state !== 'loaded') {
          if (String(old.locationCode).toLowerCase() === 'floor') continue;
          const oldLocRef = db.collection('rfs_locations').doc(locDocId(old.locationCode));
          tx.update(oldLocRef, { currentPalletOrderId: null, currentPalletOrderCode: null, currentPalletNo: null });
        }
      }

      // Lock the resolved locations to this order. Skip Floor — no doc, no lock.
      for (const [palletNo, { ref, isFloor }] of locResolved) {
        if (isFloor || !ref) continue;
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
        customerName: fresh.customerName,
        customerFirstName: fresh.customerFirstName,
        customerLastName: fresh.customerLastName,
        customerEmail: fresh.customerEmail,
        companyName: fresh.companyName,
        shipmentAddressLine1: fresh.shipmentAddressLine1,
        shipmentAddressLine2: fresh.shipmentAddressLine2,
        shipmentCity: fresh.shipmentCity,
        shipmentPostalCode: fresh.shipmentPostalCode,
        shipmentStateOrRegionName: fresh.shipmentStateOrRegionName,
        shipmentCountryCode: fresh.shipmentCountryCode,
        shipmentPhoneNumber: fresh.shipmentPhoneNumber,
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
      // Floor has no doc to free — skip the lookup entirely for it.
      if (targetPallet?.locationCode && targetPallet.state !== 'loaded'
          && String(targetPallet.locationCode).toLowerCase() !== 'floor') {
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

      if (foundLoc && !foundLoc.isFloor && foundLoc.ref) {
        tx.update(foundLoc.ref, { currentPalletOrderId: null, currentPalletOrderCode: null, currentPalletNo: null });
      }
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

// ─── Unload a pallet ─────────────────────────────────────────────────────────
// Reverses a load-pallet action. Sets the pallet state back to staged (or pending if no
// location), re-locks the location if it's still free, and downgrades the order's rfsState.
app.post('/api/rfs/orders/:id/unload-pallet', requireAuth, async (req, res) => {
  try {
    const { palletNo } = req.body;
    if (palletNo === undefined) return res.status(400).json({ error: 'palletNo required' });

    await db.runTransaction(async (tx) => {
      const orderRef = db.collection('rfs_orders').doc(req.params.id);
      // ── ALL READS FIRST ─────────────────────────────────────────────
      const orderSnap = await tx.get(orderRef);
      if (!orderSnap.exists) throw new Error('Order not found');
      const order = orderSnap.data();
      const targetPallet = (order.pallets || []).find(p => p.palletNo === palletNo);
      if (!targetPallet) throw new Error(`Pallet ${palletNo} not found`);
      if (targetPallet.state !== 'loaded') throw new Error('Pallet is not in loaded state');

      let foundLoc = null;
      let canRelock = true;
      if (targetPallet.locationCode && String(targetPallet.locationCode).toLowerCase() !== 'floor') {
        foundLoc = await findLocation(tx, targetPallet.locationCode);
        if (foundLoc && !foundLoc.isFloor) {
          const loc = foundLoc.snap.data();
          if (loc.currentPalletOrderId && loc.currentPalletOrderId !== req.params.id) {
            canRelock = false; // Another order has taken the slot in the meantime
          }
        }
      }

      // ── THEN ALL WRITES ─────────────────────────────────────────────
      const pallets = (order.pallets || []).map(p => {
        if (p.palletNo !== palletNo) return p;
        return {
          ...p,
          state: p.locationCode ? 'staged' : 'pending',
          loadedAt: null,
          loadedBy: null,
          updatedAt: Timestamp.now(),
          updatedBy: req.email,
        };
      });

      const allLoaded = pallets.length > 0 && pallets.every(p => p.state === 'loaded');
      const anyLoaded = pallets.some(p => p.state === 'loaded');
      const anyStaged = pallets.some(p => p.state === 'staged');
      let newOrderState;
      if (allLoaded) newOrderState = 'loaded';
      else if (anyLoaded) newOrderState = 'loading';
      else if (anyStaged) newOrderState = 'staged';
      else newOrderState = 'awaiting_putaway';

      const updates = { pallets, rfsState: newOrderState };
      if (newOrderState !== 'loaded') {
        updates.loadedAt = FieldValue.delete();
        updates.loadedBy = FieldValue.delete();
      }
      tx.update(orderRef, updates);

      if (foundLoc && !foundLoc.isFloor && foundLoc.ref && canRelock) {
        tx.update(foundLoc.ref, {
          currentPalletOrderId: req.params.id,
          currentPalletOrderCode: order.logiwaCode,
          currentPalletNo: palletNo,
        });
      }
    });

    const fresh = (await db.collection('rfs_orders').doc(req.params.id).get()).data();
    await logEvent({
      type: 'pallet.unloaded',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${fresh.logiwaCode}: P${palletNo} unloaded — order now ${fresh.rfsState}`,
      meta: { orderCode: fresh.logiwaCode, palletNo, rfsState: fresh.rfsState },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('unload-pallet error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// ─── BOL upload (multipart) ──────────────────────────────────────────────────
// One order can have many BOLs (multi-truck shipment). Each upload appends to bols[].
// Upload no longer auto-flips the order to 'shipped' — that's now an explicit action
// via POST /api/rfs/orders/:id/ship so workers can stage multiple BOLs first.
app.post('/api/rfs/orders/:id/bol', requireAuth, upload.single('bol'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'BOL file required (field name: bol)' });
    const truckLabel = (req.body.truckLabel || '').toString().trim() || null;

    const orderRef = db.collection('rfs_orders').doc(req.params.id);
    const snap = await orderRef.get();
    if (!snap.exists) return res.status(404).json({ error: 'Order not found' });
    const order = snap.data();

    // Allow BOL upload in `loaded` (typical case) or `shipped` (catch-up if a BOL was forgotten).
    if (!['loaded', 'shipped'].includes(order.rfsState)) {
      return res.status(400).json({ error: `Cannot upload BOL while order is in state "${order.rfsState}". All pallets must be loaded first.` });
    }

    // 1. Save the original photo to Firebase Storage
    const ts = Date.now();
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const storagePath = `rfs-bols/${order.logiwaCode}/${ts}.${ext}`;
    const file = bucket.file(storagePath);
    await file.save(req.file.buffer, { contentType: req.file.mimetype, resumable: false });
    const [signedUrl] = await file.getSignedUrl({ action: 'read', expires: Date.now() + 10 * 365 * 24 * 60 * 60 * 1000 });

    // 2. Convert to PDF and push to Logiwa (best-effort — failure is captured per-BOL)
    let logiwaResult = null;
    let logiwaError = null;
    try {
      const pdfBuffer = await ensurePdf(req.file.buffer, req.file.mimetype);
      logiwaResult = await logiwa.uploadShipmentDocument({
        shipmentOrderIdentifier: order.logiwaIdentifier,
        shipmentOrderCode: order.logiwaCode,
        fileName: `BOL_${order.logiwaCode}_${ts}${truckLabel ? '_' + truckLabel.replace(/[^a-zA-Z0-9-]/g, '_') : ''}.pdf`,
        buffer: pdfBuffer,
        mimeType: 'application/pdf',
        trackingNumber: order.logiwaCode,
        documentType: logiwa.DOCUMENT_TYPE_CARRIER_LABEL,
      });
    } catch (e) {
      logiwaError = e.message;
      console.error('Logiwa BOL upload failed:', logiwaError);
    }

    // 3. Append to bols[] (the source of truth going forward).
    //    Legacy single-BOL fields (bolPhotoUrl, bolUploadedAt, etc.) are mirrored to the
    //    LATEST upload so older reports/screens still work without code changes.
    const newBol = {
      photoUrl: signedUrl,
      storagePath,
      uploadedAt: Timestamp.now(),
      uploadedBy: req.email,
      truckLabel,
      logiwaDocumentResult: logiwaResult,
      logiwaError: logiwaError || null,
    };
    const bols = [...(order.bols || []), newBol];
    await orderRef.update({
      bols,
      // Legacy mirrors (latest upload wins)
      bolPhotoUrl: signedUrl,
      bolStoragePath: storagePath,
      bolUploadedAt: Timestamp.now(),
      bolUploadedBy: req.email,
      logiwaDocumentResult: logiwaResult,
      logiwaUploadError: logiwaError || FieldValue.delete(),
    });

    await logEvent({
      type: 'bol.uploaded',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${order.logiwaCode}: BOL #${bols.length} uploaded${truckLabel ? ' (' + truckLabel + ')' : ''}${logiwaError ? ' — Logiwa sync issue' : ''}`,
      meta: {
        orderCode: order.logiwaCode,
        clientName: order.clientName,
        truckLabel,
        bolCount: bols.length,
        logiwaError,
      },
    });

    res.json({ ok: true, bolPhotoUrl: signedUrl, bolCount: bols.length, logiwaError });
  } catch (err) {
    console.error('bol upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Explicit "ship the order" action — flips rfsState to shipped. Worker triggers this
// after all the BOLs they need are uploaded. Decoupling lets one order accept many BOLs
// across multiple trucks before being closed out.
app.post('/api/rfs/orders/:id/ship', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('rfs_orders').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Order not found' });
    const order = snap.data();
    if (order.rfsState === 'shipped') return res.json({ ok: true, alreadyShipped: true });
    if (order.rfsState !== 'loaded') {
      return res.status(400).json({ error: `Cannot ship order in state "${order.rfsState}". All pallets must be loaded first.` });
    }
    await ref.update({
      rfsState: 'shipped',
      shippedAt: Timestamp.now(),
      shippedBy: req.email,
    });
    await logEvent({
      type: 'order.shipped',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${order.logiwaCode}: shipped with ${(order.bols || []).length} BOL${(order.bols || []).length === 1 ? '' : 's'}`,
      meta: {
        orderCode: order.logiwaCode,
        clientName: order.clientName,
        bolCount: (order.bols || []).length,
      },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('ship order error:', err);
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
        // CSM-requested mapping: receipt count goes into Logiwa's customFieldTextBox2
        customFieldTextBox2: String(countNum),
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

// Helper used by both /arrive and /link-logiwa to push POD + arrival date + count to a Logiwa PO.
// Returns { logiwaDocResult, logiwaUpdateResult, logiwaError } — caller persists the result.
async function pushReceiptToLogiwa({ po, podBuffer, podMimeType, podFileName, receiptCount }) {
  let logiwaDocResult = null;
  let logiwaUpdateResult = null;
  let logiwaError = null;

  // 1. POD document
  try {
    logiwaDocResult = await logiwa.uploadPurchaseOrderDocument({
      purchaseOrderIdentifier: po.logiwaIdentifier,
      purchaseOrderCode: po.logiwaCode,
      fileName: podFileName,
      buffer: podBuffer,
      mimeType: podMimeType,
      documentType: logiwa.DOCUMENT_TYPE_EXTERNAL,
    });
  } catch (e) {
    logiwaError = `POD upload to Logiwa failed: ${e.message}`;
    console.error(logiwaError);
  }

  // 2. Update PO (arrival date + count → customFieldTextBox2)
  try {
    let currencyId = null;
    if (po.currencyCode) {
      try { currencyId = (await logiwa.getCurrencyIdMap())[po.currencyCode] || null; } catch {}
    }
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
    } catch (e) { console.error('PO line fetch error:', e.message); }

    logiwaUpdateResult = await logiwa.updatePurchaseOrder({
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
      customFieldTextBox2: receiptCount != null ? String(receiptCount) : null,
      purchaseOrderLineList,
    });
  } catch (e) {
    logiwaError = (logiwaError ? logiwaError + ' | ' : '') + `Arrival-date update failed: ${e.message}`;
    console.error('PO update error:', e.message);
  }

  return { logiwaDocResult, logiwaUpdateResult, logiwaError };
}

// Edit a blind (or any) receipt's metadata. Used to fix typos in count/type/notes after arrival.
app.put('/api/rfs/pos/:id/edit', requireAuth, async (req, res) => {
  try {
    const { receiptType, count, clientName, vendorName, note } = req.body;
    const ref = db.collection('rfs_pos').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Receipt not found' });

    const updates = {};
    if (receiptType !== undefined) {
      if (!['boxes', 'pallets', 'container'].includes(receiptType)) return res.status(400).json({ error: 'Bad receiptType' });
      updates.receiptType = receiptType;
    }
    if (count !== undefined) {
      const n = parseFloat(count);
      if (!n || n <= 0) return res.status(400).json({ error: 'Bad count' });
      updates.count = n;
    }
    if (clientName !== undefined) updates.clientName = clientName || null;
    if (vendorName !== undefined) updates.vendorDisplayName = vendorName || null;
    if (note !== undefined) updates.receiveNote = note || null;
    updates.editedAt = Timestamp.now();
    updates.editedBy = req.email;

    await ref.update(updates);
    await logEvent({ type: 'po.edited', actor: req.user, subjectType: 'po', subjectId: req.params.id, summary: 'Receipt edited', meta: updates });
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Link a previously-blind receipt to a now-existing Logiwa PO.
// Looks up the PO by code, pushes the stored POD + arrival date + count to it,
// then writes the link onto the rfs_pos doc so it no longer shows as blind.
app.post('/api/rfs/pos/:id/link-logiwa', requireAuth, async (req, res) => {
  try {
    const { logiwaCode } = req.body;
    if (!logiwaCode) return res.status(400).json({ error: 'logiwaCode required' });

    const ref = db.collection('rfs_pos').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Receipt not found' });
    const receipt = snap.data();
    if (receipt.logiwaIdentifier) return res.status(400).json({ error: 'Already linked to a Logiwa PO' });
    if (!receipt.podStoragePath) return res.status(400).json({ error: 'No POD photo on file' });

    const wh = process.env.LOGIWA_ESHIPPER_WH_IDENTIFIER || undefined;
    const po = await logiwa.findPurchaseOrderByCode(logiwaCode, { warehouseIdentifier: wh });
    if (!po) return res.status(404).json({ error: `Logiwa PO ${logiwaCode} not found` });

    // Pull POD bytes back from Firebase Storage to push to Logiwa
    const file = bucket.file(receipt.podStoragePath);
    const [podBuffer] = await file.download();
    const ext = (receipt.podStoragePath.split('.').pop() || 'pdf').toLowerCase();
    const podMimeType = ext === 'pdf' ? 'application/pdf' : (ext === 'png' ? 'image/png' : 'image/jpeg');
    // Ensure PDF for Logiwa (same rule as the BOL flow)
    const pdfBuffer = await ensurePdf(podBuffer, podMimeType);

    const enrichedPo = {
      logiwaIdentifier: po.identifier,
      logiwaCode: po.code,
      vendorDisplayName: po.vendorDisplayName,
      clientIdentifier: po.clientIdentifier,
      clientName: po.clientDisplayName,
      purchaseOrderTypeName: po.purchaseOrderTypeName,
      warehouseIdentifier: po.warehouseIdentifier,
      currencyCode: po.currencyCode,
      purchaseOrderDate: po.purchaseOrderDate,
      plannedArrivalDate: po.plannedArrivalDate,
      plannedReceivingDate: po.plannedReceivingDate,
      referenceNumber: po.referenceNumber,
    };

    const result = await pushReceiptToLogiwa({
      po: enrichedPo,
      podBuffer: pdfBuffer,
      podMimeType: 'application/pdf',
      podFileName: `POD_${po.code}_${Date.now()}.pdf`,
      receiptCount: receipt.count,
    });

    await ref.update({
      isBlind: false,
      logiwaIdentifier: po.identifier,
      logiwaCode: po.code,
      vendorDisplayName: po.vendorDisplayName || receipt.vendorDisplayName,
      clientIdentifier: po.clientIdentifier,
      clientName: po.clientDisplayName || receipt.clientName,
      purchaseOrderTypeName: po.purchaseOrderTypeName,
      logiwaDocResult: result.logiwaDocResult,
      logiwaUpdateResult: result.logiwaUpdateResult,
      logiwaError: result.logiwaError || FieldValue.delete(),
      linkedAt: Timestamp.now(),
      linkedBy: req.email,
    });

    await logEvent({
      type: 'po.linked',
      actor: req.user,
      subjectType: 'po',
      subjectId: req.params.id,
      summary: `Blind receipt linked to Logiwa PO ${po.code}${result.logiwaError ? ' (with Logiwa sync issue)' : ''}`,
      meta: { logiwaCode: po.code, logiwaError: result.logiwaError || null },
    });

    res.json({ ok: true, logiwaError: result.logiwaError, logiwaCode: po.code });
  } catch (err) {
    console.error('po link error:', err);
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
    res.json({ pos: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
  } catch (err) {
    console.error('admin pos error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Notification rules (admin) ──────────────────────────────────────────────
const NOTIFY_EVENTS = ['order.staged', 'pallet.loaded', 'pallet.unloaded', 'bol.uploaded', 'order.shipped', 'po.arrived', 'po.blind_received', 'po.linked', 'sync.run'];
const NOTIFY_CONDITIONS = ['always', 'has_dims', 'has_weight'];

app.get('/api/rfs/admin/notification-rules', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const snap = await db.collection('rfs_notification_rules').orderBy('createdAt', 'desc').limit(500).get();
    res.json({ rules: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/rfs/admin/notification-rules', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { event, clientName, recipients, condition, enabled } = req.body;
    if (!NOTIFY_EVENTS.includes(event)) return res.status(400).json({ error: `event must be one of: ${NOTIFY_EVENTS.join(', ')}` });
    const cond = condition || 'always';
    if (!NOTIFY_CONDITIONS.includes(cond)) return res.status(400).json({ error: `condition must be one of: ${NOTIFY_CONDITIONS.join(', ')}` });
    const recip = Array.isArray(recipients) ? recipients.map(s => String(s).trim()).filter(Boolean) : [];
    if (!recip.length) return res.status(400).json({ error: 'At least one recipient email required' });
    const ref = await db.collection('rfs_notification_rules').add({
      event,
      clientName: clientName || null,
      recipients: recip,
      condition: cond,
      enabled: enabled !== false,
      createdAt: Timestamp.now(),
      createdBy: req.email,
    });
    await logEvent({ type: 'notification_rule.created', actor: req.user, subjectType: 'rule', subjectId: ref.id, summary: `${event}${clientName ? ' · ' + clientName : ''} → ${recip.length} recipient(s)` });
    res.json({ ok: true, id: ref.id });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/rfs/admin/notification-rules/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const updates = {};
    if (req.body.event !== undefined) {
      if (!NOTIFY_EVENTS.includes(req.body.event)) return res.status(400).json({ error: 'Bad event' });
      updates.event = req.body.event;
    }
    if (req.body.clientName !== undefined) updates.clientName = req.body.clientName || null;
    if (req.body.recipients !== undefined) {
      const recip = Array.isArray(req.body.recipients) ? req.body.recipients.map(s => String(s).trim()).filter(Boolean) : [];
      if (!recip.length) return res.status(400).json({ error: 'At least one recipient required' });
      updates.recipients = recip;
    }
    if (req.body.condition !== undefined) {
      if (!NOTIFY_CONDITIONS.includes(req.body.condition)) return res.status(400).json({ error: 'Bad condition' });
      updates.condition = req.body.condition;
    }
    if (req.body.enabled !== undefined) updates.enabled = !!req.body.enabled;
    await db.collection('rfs_notification_rules').doc(req.params.id).update(updates);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/rfs/admin/notification-rules/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    await db.collection('rfs_notification_rules').doc(req.params.id).delete();
    await logEvent({ type: 'notification_rule.deleted', actor: req.user, subjectType: 'rule', subjectId: req.params.id });
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Test-fire a rule to confirm SMTP works without waiting for a real event
app.post('/api/rfs/admin/notification-rules/:id/test', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const snap = await db.collection('rfs_notification_rules').doc(req.params.id).get();
    if (!snap.exists) return res.status(404).json({ error: 'Rule not found' });
    const rule = snap.data();
    const result = await sendEmail(rule.recipients.join(','), `[TEST] RFS notification — ${rule.event}`, `
      <p>This is a test email from the eShipper+ RFS notification rule for <strong>${rule.event}</strong>${rule.clientName ? ' · ' + rule.clientName : ''}.</p>
      <p>If you received this, your rule is wired up correctly.</p>
    `);
    res.json({ ok: true, result });
  } catch (err) { res.status(400).json({ error: err.message }); }
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
