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

async function sendEmail(to, subject, html, cc) {
  if (!_mailer) {
    console.warn('[email] SMTP not configured — skipping email to', to, 'subject:', subject);
    return { skipped: true };
  }
  try {
    const msg = { from: `eShipper+ RFS <${process.env.SMTP_USER}>`, to, subject, html };
    if (cc && (Array.isArray(cc) ? cc.length : String(cc).trim())) {
      msg.cc = Array.isArray(cc) ? cc.join(',') : cc;
    }
    await _mailer.sendMail(msg);
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
      // Client filter — supports new `clientNames[]` array and legacy single `clientName` string.
      // Empty list = all clients.
      const clientList = Array.isArray(rule.clientNames) && rule.clientNames.length
        ? rule.clientNames
        : (rule.clientName && rule.clientName !== '*' ? [rule.clientName] : []);
      if (clientList.length > 0 && !clientList.includes(event.meta?.clientName)) continue;
      // Condition gating
      if (rule.condition === 'has_dims') {
        const pallets = event.meta?.pallets || [];
        const anyDims = pallets.some(p => p.length || p.width || p.height);
        if (!anyDims) continue;
      } else if (rule.condition === 'has_weight') {
        const pallets = event.meta?.pallets || [];
        const anyWt = pallets.some(p => p.weight);
        if (!anyWt) continue;
      } else if (rule.condition === 'all_dims_weight_complete') {
        // Fire only when EVERY pallet has L, W, H, AND weight all populated and > 0.
        // Used for putaway-done emails that are useless without the dim/weight data
        // CSM needs to schedule pickups.
        const pallets = event.meta?.pallets || [];
        if (!pallets.length) continue;
        const allComplete = pallets.every(p =>
          Number(p.length) > 0 && Number(p.width) > 0 && Number(p.height) > 0 && Number(p.weight) > 0
        );
        if (!allComplete) continue;
      }

      const recipients = (rule.recipients || []).filter(Boolean);
      if (!recipients.length) continue;
      const cc = (rule.cc || []).filter(Boolean);
      const subject = renderEmailSubject(event);
      const html = renderEmailBody(event);
      await sendEmail(recipients.join(','), subject, html, cc);
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
    case 'order.staged':
    case 'order.dims_complete': {
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

// Branded email shell — wraps the per-event body in an eShipper+ template:
//   - indigo header band with eyebrow label + bold title (Outlook-safe table layout)
//   - white card body with the actual content
//   - muted footer
// `eyebrow` is the small caps label above the title (e.g. "Putaway done", "BOL uploaded").
// `title` is the main heading shown to the recipient (e.g. the order code + customer).
function renderEmailShell({ eyebrow, title, bodyHtml }) {
  // Brand wordmark is rendered as text rather than image — many email clients
  // (Gmail web, Outlook) block external images by default until the recipient
  // clicks "Display images", so a typographic mark survives every render path.
  return `
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:#f8f8f9;padding:24px 12px;font-family:'Inter',-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
      <tr>
        <td align="center">
          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="640" style="max-width:640px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e6e7e8;box-shadow:0 1px 3px rgba(22,23,26,0.08)">
            <tr>
              <td style="background:#34368a;padding:22px 28px;color:#ffffff">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                  <tr>
                    <td style="font-size:22px;font-weight:700;letter-spacing:-0.02em;color:#ffffff;line-height:1">
                      eShipper<span style="color:#62c0ae">+</span>
                    </td>
                    <td align="right" style="font-size:11px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:rgba(255,255,255,0.85);vertical-align:middle">RFS</td>
                  </tr>
                </table>
                <div style="height:14px;line-height:14px;font-size:0">&nbsp;</div>
                <div style="font-size:11px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;opacity:0.85">${esc(eyebrow || 'Notification')}</div>
                <div style="font-size:20px;font-weight:600;letter-spacing:-0.01em;margin-top:4px;color:#ffffff">${esc(title || '')}</div>
              </td>
            </tr>
            <tr>
              <td style="padding:24px 28px 8px 28px;font-size:14px;color:#16171a;line-height:1.55">
                ${bodyHtml}
              </td>
            </tr>
            <tr>
              <td style="padding:14px 28px 22px 28px;border-top:1px solid #f1f1f3;color:#75767e;font-size:12px">
                eShipper+ RFS · automated notification
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  `;
}

function renderEmailBody(event) {
  if (event.type === 'order.staged' || event.type === 'order.dims_complete') return renderOrderStagedBody(event);
  // Generic table body for everything else (BOL upload, PO arrive, etc.)
  const m = event.meta || {};
  const palletList = (m.pallets || []).map(p => {
    const dims = (p.length || p.width || p.height) ? `${p.length || '—'}×${p.width || '—'}×${p.height || '—'} ${esc(p.dimensionUnit || 'in')}` : '';
    const wt = p.weight ? `${p.weight} ${esc(p.weightUnit || 'lb')}` : '';
    return `<tr><td style="padding:4px 12px 4px 0">P${p.palletNo}</td><td style="padding:4px 12px 4px 0">${esc(p.locationCode || '—')}</td><td style="padding:4px 12px 4px 0">${dims}</td><td style="padding:4px 0">${wt}</td></tr>`;
  }).join('');

  // Per-event eyebrow + title for the shell header.
  const eyebrowMap = {
    'bol.uploaded': 'BOL uploaded',
    'bol.blind_recorded': 'BOL recorded (blind)',
    'order.shipped': 'Order shipped',
    'order.updated': 'Order updated',
    'pallet.loaded': 'Pallet loaded',
    'pallet.unloaded': 'Pallet unloaded',
    'po.arrived': 'PO received',
    'po.blind_received': 'Blind receipt',
    'po.linked': 'PO linked',
    'sync.run': 'Logiwa sync',
  };
  const eyebrow = eyebrowMap[event.type] || 'RFS event';
  const titleParts = [m.orderCode || m.poCode, m.clientName].filter(Boolean);
  const title = titleParts.join(' · ') || event.summary || event.type;

  const bodyHtml = `
    <p style="margin:0 0 12px 0">${esc(event.summary || event.type)}</p>
    <table cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:13px">
      ${event.actor?.email ? `<tr><td style="padding:2px 14px 2px 0;color:#75767e;white-space:nowrap">By</td><td>${esc(event.actor.email)}</td></tr>` : ''}
      ${m.orderCode ? `<tr><td style="padding:2px 14px 2px 0;color:#75767e">Order</td><td><strong>${esc(m.orderCode)}</strong></td></tr>` : ''}
      ${m.poCode ? `<tr><td style="padding:2px 14px 2px 0;color:#75767e">PO</td><td><strong>${esc(m.poCode)}</strong></td></tr>` : ''}
      ${m.clientName ? `<tr><td style="padding:2px 14px 2px 0;color:#75767e">Client</td><td>${esc(m.clientName)}</td></tr>` : ''}
      ${m.receiptType ? `<tr><td style="padding:2px 14px 2px 0;color:#75767e">Received</td><td>${esc(m.count + ' ' + m.receiptType)}</td></tr>` : ''}
    </table>
    ${palletList ? `
      <p style="margin:16px 0 6px 0;font-weight:600">Pallets</p>
      <table cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:13px;width:100%">
        <tr style="color:#75767e;background:#f8f8f9">
          <td style="padding:6px 12px 6px 8px">#</td>
          <td style="padding:6px 12px 6px 0">Location</td>
          <td style="padding:6px 12px 6px 0">Dims</td>
          <td style="padding:6px 0">Weight</td>
        </tr>
        ${palletList}
      </table>` : ''}
  `;
  return renderEmailShell({ eyebrow, title, bodyHtml });
}

// Dedicated template for "putaway done" / "dims complete" — what CSM gets when an order is staged.
function renderOrderStagedBody(event) {
  const m = event.meta || {};
  const pallets = m.pallets || [];
  const palletLines = pallets.map(p => {
    const dimsParts = [p.length, p.width, p.height].map(v => v == null || v === '' ? '—' : v);
    const dims = (p.length || p.width || p.height)
      ? `${dimsParts[0]}×${dimsParts[1]}×${dimsParts[2]} ${esc(p.dimensionUnit || 'in')}`
      : 'dims not recorded';
    const wt = p.weight ? `${p.weight} ${esc(p.weightUnit || 'lb')}` : 'weight not recorded';
    const idTag = p.palletId ? ` <span style="color:#75767e;font-weight:400">[${esc(p.palletId)}]</span>` : '';
    return `<li style="margin-bottom:6px"><strong>P${p.palletNo}</strong>${idTag}: ${dims} · ${wt}</li>`;
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
    .map(([k, v]) => `<tr><td style="padding:2px 14px 2px 0;color:#75767e;white-space:nowrap">${k}</td><td>${esc(v)}</td></tr>`)
    .join('');

  // Header eyebrow distinguishes the two events that share this body so recipients can
  // tell them apart at a glance, even though the layout is intentionally the same.
  // NOTE: keep this customer-safe — these emails go to external parties, so avoid
  // internal warehouse jargon (e.g. "putaway done").
  const eyebrow = event.type === 'order.dims_complete' ? 'Dims + weight ready' : 'Order staged';
  const who = m.companyName || m.customerName
    || [m.customerFirstName, m.customerLastName].filter(Boolean).join(' ')
    || m.clientName || '';
  const title = `${m.orderCode || ''}${who ? ' · ' + who : ''}`;

  const bodyHtml = `
    <p style="margin:0 0 8px 0">Hi Team,</p>
    <p style="margin:0 0 8px 0">The order has <strong>${pallets.length}</strong> pallet${pallets.length === 1 ? '' : 's'} and here are dims and weight:</p>
    <ul style="margin:8px 0 18px 0;padding-left:22px">${palletLines}</ul>

    <p style="margin:16px 0 6px 0;font-weight:600">Shipping address</p>
    <table cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:13px;margin-top:4px">
      ${addressRows || '<tr><td style="color:#a8a9b0">(no address on the order in Logiwa)</td></tr>'}
    </table>

    <table cellspacing="0" cellpadding="0" style="margin-top:18px;border-collapse:collapse;font-size:13px;color:#3f4047">
      <tr><td style="padding:2px 14px 2px 0;color:#75767e">Order</td><td><strong>${esc(m.orderCode || '')}</strong></td></tr>
      ${m.clientName ? `<tr><td style="padding:2px 14px 2px 0;color:#75767e">Client</td><td>${esc(m.clientName)}</td></tr>` : ''}
      ${m.companyName ? `<tr><td style="padding:2px 14px 2px 0;color:#75767e">Company</td><td>${esc(m.companyName)}</td></tr>` : ''}
    </table>
  `;
  return renderEmailShell({ eyebrow, title, bodyHtml });
}

function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Pallet ID is a worker-supplied label printed on the physical pallet (or scanned
// from a barcode). We require the "RFS" prefix so it's recognisable on the floor;
// blank is also fine (palletId is optional). Case-insensitive prefix check.
function normalizePalletId(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const s = String(raw).trim();
  if (!s) return null;
  if (!/^rfs/i.test(s)) {
    const err = new Error(`Pallet ID "${s}" must start with "RFS"`);
    err.statusCode = 400;
    throw err;
  }
  return s;
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

  // palletId: if the input includes the field, use that (after RFS-prefix validation);
  // otherwise keep what was previously stored. Lets workers update the id later.
  let palletId = prev?.palletId ?? null;
  if (Object.prototype.hasOwnProperty.call(input, 'palletId')) {
    palletId = normalizePalletId(input.palletId);
  }

  return {
    palletNo,
    palletId,
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
      // restore it to whatever state it was in BEFORE archiving (staged/loading/loaded).
      // Falling back to awaiting_putaway only when we don't have prevRfsState recorded
      // (e.g. orders archived before this fix was deployed).
      const existing = snap.data();
      const updates = { ...base };
      if (existing.rfsState === 'archived_externally') {
        const restorable = ['staged', 'loading', 'loaded'];
        updates.rfsState = restorable.includes(existing.prevRfsState)
          ? existing.prevRfsState
          : 'awaiting_putaway';
        updates.archivedAt = FieldValue.delete();
        updates.archivedReason = FieldValue.delete();
        updates.prevRfsState = FieldValue.delete();
      }
      await ref.update(updates);
      updated += 1;
    }
  }

  // Archive any active orders that Logiwa did NOT return — they're no longer Ready to Ship
  // (most likely shipped manually in Logiwa). They won't appear in the active list anymore,
  // but stay in the admin history with state `archived_externally`.
  //
  // Some clients flip the Logiwa status manually before the physical pallet has left the
  // warehouse (e.g. Marklyn). For them, auto-archive would drop the order from the worker
  // queue too early. SKIP_AUTO_ARCHIVE_CLIENTS env var = comma-separated client names to
  // opt out of auto-archive (case-insensitive match against `clientName`).
  const skipClients = (process.env.SKIP_AUTO_ARCHIVE_CLIENTS || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const ACTIVE_STATES = ['awaiting_putaway', 'staged', 'loading', 'loaded'];
  let archived = 0, archiveSkipped = 0;
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
      const o = doc.data();
      // Skip clients in the opt-out list — keep the order in the queue until the worker
      // finishes putaway/load/BOL in the app (or an admin force-ships it).
      if (o.clientName && skipClients.includes(String(o.clientName).toLowerCase())) {
        archiveSkipped += 1;
        continue;
      }
      await doc.ref.update({
        rfsState: 'archived_externally',
        // Capture the state we're archiving FROM so the restore path can put the order
        // back in the right state if Logiwa returns it later (e.g. status flicker).
        prevRfsState: o.rfsState,
        archivedAt: Timestamp.now(),
        archivedReason: 'No longer Ready to Ship in Logiwa (likely shipped manually).',
      });
      // Free any locations this order was holding
      for (const p of (o.pallets || [])) {
        if (p.locationCode && p.state !== 'loaded') {
          const locRef = db.collection('rfs_locations').doc(locDocId(p.locationCode));
          locRef.update({ currentPalletOrderId: null, currentPalletOrderCode: null, currentPalletNo: null }).catch(() => {});
        }
      }
      archived += 1;
    }
    if (archiveSkipped) {
      console.log(`[sync] kept ${archiveSkipped} order(s) in queue per SKIP_AUTO_ARCHIVE_CLIENTS opt-out`);
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

    // Captures whether the order transitioned awaiting_putaway → staged in this save.
    // The notification event type depends on this — see logEvent call below.
    const txResult = { didStageTransition: false };

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
        txResult.didStageTransition = true;
        // Capture whether this is the FIRST time the order has reached staged. The notification
        // fires only on the first transition — see logEvent call below. If runSync ever resets
        // rfsState back to awaiting_putaway (archive/restore cycle) and a worker re-saves,
        // didStageTransition will be true but stagedNotifiedAt already set → audit-only event.
        txResult.stagedNotifiedAlready = !!order.stagedNotifiedAt;
        if (!order.stagedNotifiedAt) {
          updates.stagedNotifiedAt = Timestamp.now();
        }
      } else if (!allStaged && order.rfsState === 'staged') {
        // Partial save after a previously fully-staged order — revert to awaiting_putaway
        updates.rfsState = 'awaiting_putaway';
      }
      tx.update(orderRef, updates);
    });

    // Re-read the order to grab the canonical pallet info for the audit summary
    const fresh = (await db.collection('rfs_orders').doc(req.params.id).get()).data();
    const summary = (fresh.pallets || [])
      .map(p => `P${p.palletNo}${p.palletId ? ' [' + p.palletId + ']' : ''}${p.locationCode ? ' @ ' + p.locationCode : ' (pending)'}${p.weight ? ' ' + p.weight + (p.weightUnit||'lb') : ''}`)
      .join(' | ');
    // Fire `order.staged` ONLY when the order ACTUALLY hits staged for the first time, ever.
    // `didStageTransition` catches the awaiting_putaway → staged flip, but that flip can happen
    // more than once for the same order if runSync's archive/restore cycle reset rfsState back
    // to awaiting_putaway (e.g. Logiwa briefly dropped the order from status=16 and returned it).
    // The `stagedNotifiedAlready` guard ensures the notification + email fire at most once per
    // order doc, regardless of how many times state churns. Subsequent saves log as
    // `order.updated` for audit history only.
    const firstStagedFire = txResult.didStageTransition && !txResult.stagedNotifiedAlready;
    await logEvent({
      type: firstStagedFire ? 'order.staged' : 'order.updated',
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

    // Detect the "all pallets have full dims + weight" milestone. This fires exactly
    // once per order — whether the worker entered all the data upfront (initial stage)
    // or filled it in later via edits. Subscribe `order.dims_complete` rules to this.
    const allComplete = (fresh.pallets || []).length > 0 && (fresh.pallets || []).every(p =>
      Number(p.length) > 0 && Number(p.width) > 0 && Number(p.height) > 0 && Number(p.weight) > 0
    );
    if (allComplete && !fresh.dimsCompleteAt) {
      await db.collection('rfs_orders').doc(req.params.id).update({
        dimsCompleteAt: Timestamp.now(),
        dimsCompleteBy: req.email,
      });
      await logEvent({
        type: 'order.dims_complete',
        actor: req.user,
        subjectType: 'order',
        subjectId: req.params.id,
        summary: `${fresh.logiwaCode}: all pallets have full dims + weight`,
        // Include the same fields as order.staged so the same email template renders cleanly.
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
    }

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

// ─── Blind BOL upload (no order in the app) ──────────────────────────────────
// Use case: driver shows up with a BOL for an order that's already shipped, or that was
// never tracked through the app. Save the photo + metadata + optionally push to Logiwa.
app.post('/api/rfs/bols/blind', requireAuth, upload.single('bol'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'BOL file required (field name: bol)' });
    const orderCode = (req.body.orderCode || '').toString().trim() || null;
    const clientName = (req.body.clientName || '').toString().trim() || null;
    const carrierName = (req.body.carrierName || '').toString().trim() || null;
    const truckLabel = (req.body.truckLabel || '').toString().trim() || null;
    const note = (req.body.note || '').toString().trim() || null;

    const ts = Date.now();
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const slug = (orderCode || clientName || 'unattached').toString().replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30) || 'unattached';
    const storagePath = `rfs-bols/blind/${slug}/${ts}.${ext}`;
    const file = bucket.file(storagePath);
    await file.save(req.file.buffer, { contentType: req.file.mimetype, resumable: false });
    const [signedUrl] = await file.getSignedUrl({ action: 'read', expires: Date.now() + 10 * 365 * 24 * 60 * 60 * 1000 });

    // If the worker provided an order code, try pushing the BOL to Logiwa as well.
    // Best-effort — we still record the BOL locally even if Logiwa rejects it.
    let logiwaResult = null;
    let logiwaError = null;
    if (orderCode) {
      try {
        const pdfBuffer = await ensurePdf(req.file.buffer, req.file.mimetype);
        logiwaResult = await logiwa.uploadShipmentDocument({
          shipmentOrderCode: orderCode,
          fileName: `BOL_${orderCode}_${ts}${truckLabel ? '_' + truckLabel.replace(/[^a-zA-Z0-9-]/g, '_') : ''}.pdf`,
          buffer: pdfBuffer,
          mimeType: 'application/pdf',
          trackingNumber: orderCode,
          documentType: logiwa.DOCUMENT_TYPE_CARRIER_LABEL,
        });
      } catch (e) {
        logiwaError = e.message;
        console.error('Blind BOL Logiwa upload failed:', logiwaError);
      }
    }

    const ref = db.collection('rfs_blind_bols').doc();
    await ref.set({
      orderCode,
      clientName,
      carrierName,
      truckLabel,
      note,
      photoUrl: signedUrl,
      storagePath,
      logiwaDocumentResult: logiwaResult,
      logiwaError: logiwaError || null,
      uploadedAt: Timestamp.now(),
      uploadedBy: req.email,
    });

    await logEvent({
      type: 'bol.blind_recorded',
      actor: req.user,
      subjectType: 'bol',
      subjectId: ref.id,
      summary: `Blind BOL recorded${orderCode ? ' for ' + orderCode : ' (no order code)'}${truckLabel ? ' · ' + truckLabel : ''}${logiwaError ? ' — Logiwa sync issue' : (orderCode ? ' — pushed to Logiwa' : '')}`,
      meta: { orderCode, clientName, carrierName, truckLabel, logiwaError },
    });

    res.json({ ok: true, id: ref.id, photoUrl: signedUrl, logiwaError });
  } catch (err) {
    console.error('blind bol error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Admin: list recent blind BOLs
app.get('/api/rfs/admin/blind-bols', requireAuth, requireRole(...REPORT_ROLES), async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days || '30', 10), 365);
    const since = Timestamp.fromMillis(Date.now() - days * 24 * 60 * 60 * 1000);
    const snap = await db.collection('rfs_blind_bols').where('uploadedAt', '>=', since).orderBy('uploadedAt', 'desc').limit(500).get();
    res.json({ bols: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
//
// Admins can pass `?force=1` to ship from any non-shipped state — used when a client's
// Logiwa status got flipped externally and the order is stuck in the worker queue.
app.post('/api/rfs/orders/:id/ship', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('rfs_orders').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Order not found' });
    const order = snap.data();
    if (order.rfsState === 'shipped') return res.json({ ok: true, alreadyShipped: true });

    const force = req.query.force === '1' || req.body?.force === true;
    if (force && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can force-ship orders' });
    }
    if (!force && order.rfsState !== 'loaded') {
      return res.status(400).json({ error: `Cannot ship order in state "${order.rfsState}". All pallets must be loaded first (or ask an admin to force-ship).` });
    }

    // If forcing from a non-loaded state, free any locations still locked to this order.
    if (force && order.rfsState !== 'loaded') {
      for (const p of (order.pallets || [])) {
        if (p.locationCode && p.state !== 'loaded'
            && String(p.locationCode).toLowerCase() !== 'floor') {
          const locRef = db.collection('rfs_locations').doc(locDocId(p.locationCode));
          locRef.update({ currentPalletOrderId: null, currentPalletOrderCode: null, currentPalletNo: null }).catch(() => {});
        }
      }
    }

    await ref.update({
      rfsState: 'shipped',
      shippedAt: Timestamp.now(),
      shippedBy: req.email,
      ...(force ? { forceShippedFrom: order.rfsState, forceShippedReason: req.body?.reason || null } : {}),
    });
    await logEvent({
      type: 'order.shipped',
      actor: req.user,
      subjectType: 'order',
      subjectId: req.params.id,
      summary: `${order.logiwaCode}: ${force ? 'force-' : ''}shipped from ${order.rfsState} with ${(order.bols || []).length} BOL${(order.bols || []).length === 1 ? '' : 's'}`,
      meta: {
        orderCode: order.logiwaCode,
        clientName: order.clientName,
        bolCount: (order.bols || []).length,
        forced: !!force,
        forcedFromState: force ? order.rfsState : null,
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
const NOTIFY_EVENTS = ['order.staged', 'order.dims_complete', 'order.updated', 'pallet.loaded', 'pallet.unloaded', 'bol.uploaded', 'bol.blind_recorded', 'order.shipped', 'po.arrived', 'po.blind_received', 'po.linked', 'sync.run'];
const NOTIFY_CONDITIONS = ['always', 'has_dims', 'has_weight', 'all_dims_weight_complete'];

app.get('/api/rfs/admin/notification-rules', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const snap = await db.collection('rfs_notification_rules').orderBy('createdAt', 'desc').limit(500).get();
    res.json({ rules: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Normalize the multi-client input. Accepts an array `clientNames` or a legacy single string `clientName`.
// Returns a clean string[] (empty = all clients).
function normalizeClientList(body) {
  if (Array.isArray(body.clientNames)) {
    return [...new Set(body.clientNames.map(s => String(s).trim()).filter(Boolean))];
  }
  if (body.clientName) return [String(body.clientName).trim()].filter(Boolean);
  return [];
}

app.post('/api/rfs/admin/notification-rules', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { event, recipients, cc, condition, enabled } = req.body;
    if (!NOTIFY_EVENTS.includes(event)) return res.status(400).json({ error: `event must be one of: ${NOTIFY_EVENTS.join(', ')}` });
    const cond = condition || 'always';
    if (!NOTIFY_CONDITIONS.includes(cond)) return res.status(400).json({ error: `condition must be one of: ${NOTIFY_CONDITIONS.join(', ')}` });
    const recip = Array.isArray(recipients) ? recipients.map(s => String(s).trim()).filter(Boolean) : [];
    if (!recip.length) return res.status(400).json({ error: 'At least one recipient email required' });
    const ccList = Array.isArray(cc) ? cc.map(s => String(s).trim()).filter(Boolean) : [];
    const clientNames = normalizeClientList(req.body);
    const ref = await db.collection('rfs_notification_rules').add({
      event,
      clientNames,           // new multi-client array (empty = all clients)
      clientName: clientNames.length === 1 ? clientNames[0] : null, // legacy mirror, kept for older clients
      recipients: recip,
      cc: ccList,            // optional CC recipients
      condition: cond,
      enabled: enabled !== false,
      createdAt: Timestamp.now(),
      createdBy: req.email,
    });
    const clientSummary = clientNames.length ? clientNames.join(', ') : 'all clients';
    await logEvent({ type: 'notification_rule.created', actor: req.user, subjectType: 'rule', subjectId: ref.id, summary: `${event} · ${clientSummary} → ${recip.length} recipient(s)` });
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
    // Accept clientNames (preferred) or clientName (legacy)
    if (req.body.clientNames !== undefined || req.body.clientName !== undefined) {
      const list = normalizeClientList(req.body);
      updates.clientNames = list;
      updates.clientName = list.length === 1 ? list[0] : null;
    }
    if (req.body.recipients !== undefined) {
      const recip = Array.isArray(req.body.recipients) ? req.body.recipients.map(s => String(s).trim()).filter(Boolean) : [];
      if (!recip.length) return res.status(400).json({ error: 'At least one recipient required' });
      updates.recipients = recip;
    }
    if (req.body.cc !== undefined) {
      updates.cc = Array.isArray(req.body.cc) ? req.body.cc.map(s => String(s).trim()).filter(Boolean) : [];
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
    `, (rule.cc || []).filter(Boolean));
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

// One-shot boot backfill for two notification guards on existing orders.
//
//  1. stagedNotifiedAt — set on any order past awaiting_putaway that doesn't already have it.
//     Without this, runSync's archive/restore cycle could reset rfsState back to
//     awaiting_putaway and trick the next save into re-firing order.staged.
//
//  2. dimsCompleteAt — set on any order whose pallets ALREADY have full L/W/H/weight but
//     where dimsCompleteAt was never recorded (e.g. orders that finished putaway BEFORE
//     the order.dims_complete feature was deployed). Without this, the first Save after
//     deploy (even an Edit-putaway → Save with no changes) trips the
//     `allComplete && !dimsCompleteAt` guard and fires order.dims_complete — which uses
//     the same email template as order.staged, so it looks like a duplicate staged email.
//
// Both writes only touch docs missing the field, so this is idempotent across restarts.
async function backfillNotificationGuards() {
  try {
    const states = ['staged', 'loading', 'loaded', 'shipped', 'archived_externally'];
    const snap = await db.collection('rfs_orders').where('rfsState', 'in', states).get();
    let touchedStaged = 0;
    let touchedDims = 0;
    const batch = db.batch();
    const now = Timestamp.now();
    for (const doc of snap.docs) {
      const o = doc.data();
      const updates = {};
      if (!o.stagedNotifiedAt) {
        updates.stagedNotifiedAt = o.stagedAt || now;
        touchedStaged += 1;
      }
      if (!o.dimsCompleteAt) {
        const pallets = Array.isArray(o.pallets) ? o.pallets : [];
        const allComplete = pallets.length > 0 && pallets.every(p =>
          Number(p.length) > 0 && Number(p.width) > 0 && Number(p.height) > 0 && Number(p.weight) > 0
        );
        if (allComplete) {
          updates.dimsCompleteAt = o.stagedAt || now;
          touchedDims += 1;
        }
      }
      if (Object.keys(updates).length > 0) {
        batch.update(doc.ref, updates);
      }
      // Firestore batch cap = 500 writes. Stop early if we're getting close — a follow-up
      // boot will pick up whatever's left, which is fine because both backfills are idempotent.
      if (touchedStaged + touchedDims >= 400) break;
    }
    if (touchedStaged || touchedDims) {
      await batch.commit();
      console.log(`[boot] backfilled stagedNotifiedAt on ${touchedStaged} order(s), dimsCompleteAt on ${touchedDims} order(s)`);
    }
  } catch (err) {
    console.error('[boot] notification-guard backfill failed:', err.message);
  }
}
backfillNotificationGuards();

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`eshipperplus-rfs listening on :${PORT}`));
