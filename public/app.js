'use strict';

// Guard: if the Firebase compat SDK didn't load (e.g. WebView blocked gstatic.com,
// or the script tag failed for any reason) show a clear message instead of a blank screen.
if (typeof firebase === 'undefined' || !window.FIREBASE_WEB_CONFIG) {
  const status = document.getElementById('boot-status');
  if (status) {
    status.innerHTML = `<strong style="color:#c0392b">Loading failed</strong><br><br>
      The Firebase SDK didn't load. Most common cause on a managed device is the network blocking <code>gstatic.com</code>.<br><br>
      Try opening <code>https://www.gstatic.com/firebasejs/10.7.1/firebase-app-compat.js</code> directly in this device's browser — if that fails too, the device's network/firewall is blocking it.`;
  }
  throw new Error('Firebase SDK or config missing');
}

firebase.initializeApp(window.FIREBASE_WEB_CONFIG);
const fbAuth = firebase.auth();

const state = {
  user: null,
  view: 'scan',
  orders: [],
  selectedOrderId: null,
  scanner: null,
  syncTimer: null,
  lastSyncAt: null,
  // When true, renderOrderDetail forces the putaway form regardless of order state.
  // Lets workers fix dims/weight/locations after the order has been saved.
  editPutaway: false,
};

const AUTO_SYNC_MS = 5 * 60 * 1000;

// ─── helpers ─────────────────────────────────────────────────────────────────
function $(sel) { return document.querySelector(sel); }
function el(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstChild; }
function toast(msg, kind) {
  const host = $('#toast-host');
  const t = el(`<div class="toast ${kind === 'error' ? 'error' : ''}">${escape(msg)}</div>`);
  host.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}
function escape(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }
function fmtDate(d) { if (!d) return '—'; const dt = new Date(d); return isNaN(dt) ? d : dt.toLocaleDateString(); }

async function api(method, path, body, isForm) {
  const token = await fbAuth.currentUser.getIdToken();
  const opts = { method, headers: { Authorization: `Bearer ${token}` } };
  if (body && !isForm) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  } else if (body && isForm) {
    opts.body = body;
  }
  const r = await fetch(path, opts);
  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(json.error || `HTTP ${r.status}`);
  return json;
}

// ─── boot diagnostics ────────────────────────────────────────────────────────
// If we never reach the auth callback within 8s, show a hint so the device
// doesn't sit on a blank screen forever (helps debug WebView / network issues).
const _bootTimer = setTimeout(() => {
  const status = document.getElementById('boot-status');
  if (status && document.getElementById('boot-loader').style.display !== 'none') {
    status.innerHTML = `<strong style="color:#c0392b">Loading failed</strong><br><br>
      Could not initialise authentication. Most common causes on warehouse devices:<br>
      • Android WebView is out of date — update via Play Store<br>
      • Device's network blocks <code>gstatic.com</code> or <code>firebaseapp.com</code><br>
      • No internet connection`;
  }
}, 8000);

function _hideBoot() {
  clearTimeout(_bootTimer);
  const loader = document.getElementById('boot-loader');
  if (loader) loader.style.display = 'none';
}

// ─── auth flow ───────────────────────────────────────────────────────────────
fbAuth.onAuthStateChanged(async (u) => {
  _hideBoot();
  if (!u) {
    $('#login').style.display = '';
    $('#app').style.display = 'none';
    return;
  }
  try {
    const { user } = await api('GET', '/api/me');
    state.user = user;
    $('#login').style.display = 'none';
    $('#app').style.display = '';
    $('#who').textContent = user.displayName || user.email;
    // Tab visibility by role:
    //   worker     → Scan, Queue, Receive PO
    //   supervisor → Scan, Queue, Receive PO, Reports
    //   csm        → Scan, Queue, Receive PO, Reports
    //   admin      → all of the above + admin-only sections inside Reports
    const isReportRole = ['admin', 'supervisor', 'csm'].includes(user.role);
    $('#tab-queue').style.display = ''; // visible to all roles
    $('#tab-admin').style.display = isReportRole ? '' : 'none';
  } catch (e) {
    toast('Auth error: ' + e.message, 'error');
    fbAuth.signOut();
    return;
  }
  // Render and auto-sync are isolated — a render error must not log the user out.
  try { render(); } catch (e) { console.error('render error:', e); toast('UI error: ' + e.message, 'error'); }
  try { startAutoSync(); } catch (e) { console.error('auto-sync error:', e); }
});

function startAutoSync() {
  if (state.syncTimer) clearInterval(state.syncTimer);
  silentSync();
  state.syncTimer = setInterval(silentSync, AUTO_SYNC_MS);
}

async function silentSync() {
  try {
    const r = await api('POST', '/api/rfs/sync');
    state.lastSyncAt = Date.now();
    // If user is on the Queue view, refresh the visible list quietly
    if (state.view === 'queue' && !state.selectedOrderId) renderQueue();
  } catch (e) {
    console.warn('auto-sync failed:', e.message);
  }
}

// Pick up a sign-in that completed via redirect (fallback flow)
fbAuth.getRedirectResult().catch(() => {});

document.getElementById('btn-google').onclick = async () => {
  const provider = new firebase.auth.GoogleAuthProvider();
  try {
    await fbAuth.signInWithPopup(provider);
  } catch (e) {
    if (['auth/popup-closed-by-user', 'auth/popup-blocked', 'auth/cancelled-popup-request'].includes(e.code)) {
      // Popup blocked or dismissed — switch to full-page redirect (works even when popups are off)
      try { await fbAuth.signInWithRedirect(provider); }
      catch (e2) { toast(e2.message, 'error'); }
    } else {
      toast(e.message, 'error');
    }
  }
};
document.getElementById('btn-email').onclick = async () => {
  const email = $('#login-email').value.trim();
  const password = $('#login-password').value;
  if (!email || !password) { toast('Email and password required', 'error'); return; }
  try {
    await fbAuth.signInWithEmailAndPassword(email, password);
  } catch (e) {
    // Firebase 9+ unified "no user" and "wrong password" into auth/invalid-credential.
    // Try to create the account; if it already exists, the create call tells us the password was wrong.
    if (e.code === 'auth/user-not-found' || e.code === 'auth/invalid-credential' || e.code === 'auth/invalid-login-credentials') {
      try {
        await fbAuth.createUserWithEmailAndPassword(email, password);
      } catch (e2) {
        if (e2.code === 'auth/email-already-in-use') toast('Wrong password for that email', 'error');
        else if (e2.code === 'auth/weak-password') toast('Password too weak (min 6 chars)', 'error');
        else if (e2.code === 'auth/operation-not-allowed') toast('Email/password sign-in is disabled. Enable it in Firebase console > Authentication > Sign-in method.', 'error');
        else toast(e2.message, 'error');
      }
    } else {
      toast(e.message, 'error');
    }
  }
};
document.getElementById('btn-signout').onclick = () => fbAuth.signOut();

// ─── tab switching ───────────────────────────────────────────────────────────
document.querySelectorAll('#tabs button').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('#tabs button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    state.view = b.dataset.view;
    state.selectedOrderId = null;
    state.selectedPOId = null;
    state.editPutaway = false;
    stopScanner();
    stopBolStream();
    render();
  };
});

// ─── render ──────────────────────────────────────────────────────────────────
function render() {
  // Admin view gets a wider container (table-heavy); other views stay phone-friendly.
  const v = $('#view');
  if (v) v.classList.toggle('wide', state.view === 'admin');
  if (state.selectedOrderId) return renderOrderDetail();
  if (state.selectedPOId) return renderPOArrival();
  if (state.view === 'scan') return renderScan();
  if (state.view === 'queue') return renderQueue();
  if (state.view === 'receive') return renderReceive();
  if (state.view === 'admin') return renderAdmin();
}

// ─── scan-first flow (worker primary entry) ──────────────────────────────────
function renderScan() {
  const v = $('#view');
  v.innerHTML = `
    <div class="card">
      <h3>Scan order code</h3>
      <div class="meta" style="margin-bottom:8px">Scan the order barcode to start putaway, continue loading, or upload BOL.</div>
      <div class="scanner-wrap"><div id="qr-reader"></div></div>
      <div class="row" style="margin-top:10px">
        <input type="text" id="manual-code" placeholder="…or type the order code" class="grow" />
        <button class="btn" id="btn-manual">Open</button>
      </div>
      <div class="hint" style="margin-top:10px;text-align:center">${state.lastSyncAt ? 'Last synced ' + Math.round((Date.now()-state.lastSyncAt)/1000) + 's ago' : 'Syncing…'}</div>
    </div>
  `;
  openScanner((code) => lookupOrderByCode(code));
  $('#btn-manual').onclick = () => {
    const code = $('#manual-code').value.trim();
    if (code) lookupOrderByCode(code);
  };
  $('#manual-code').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('#btn-manual').click();
  });
}

// ─── queue (read-only list of pending orders) ────────────────────────────────
async function renderQueue() {
  const v = $('#view');
  v.innerHTML = `
    <div class="row">
      <button class="btn secondary grow" id="btn-sync">Refresh now</button>
    </div>
    <div id="filter-host"></div>
    <div id="orders-list"><div class="loader">Loading orders…</div></div>
  `;
  $('#btn-sync').onclick = async () => {
    $('#btn-sync').disabled = true;
    $('#btn-sync').textContent = 'Syncing…';
    try {
      const r = await api('POST', '/api/rfs/sync');
      toast(`Synced ${r.fetched} orders${r.archived ? `, archived ${r.archived}` : ''}`);
      state.lastSyncAt = Date.now();
      await loadOrders();
    } catch (e) { toast(e.message, 'error'); }
    finally { $('#btn-sync').disabled = false; $('#btn-sync').textContent = 'Refresh now'; }
  };
  await loadOrders();
}

async function loadOrders() {
  try {
    const { orders } = await api('GET', '/api/rfs/orders');
    state.orders = orders;
    const filterHost = $('#filter-host');
    if (filterHost) {
      filterHost.innerHTML = filterRowHTML({
        idPrefix: 'q',
        orders,
        includeStateOptions: ['awaiting_putaway', 'staged', 'loading', 'loaded'],
      });
      attachFilterHandlers('q', renderQueueList);
    }
    renderQueueList();
  } catch (e) { toast(e.message, 'error'); }
}

function renderQueueList() {
  const list = $('#orders-list');
  if (!list) return;
  const f = readFilterValues('q');
  let orders = applyFilters(state.orders, f);
  orders.sort((a,b) => (a.expectedShipmentDate||'').localeCompare(b.expectedShipmentDate||''));
  if (!orders.length) {
    list.innerHTML = state.orders.length
      ? '<div class="empty">No orders match the current filter.</div>'
      : '<div class="empty">No active orders. New RFS orders sync from Logiwa automatically every 5 min.</div>';
    return;
  }
  list.innerHTML = '';
  for (const o of orders) {
    const card = el(`
      <div class="card" data-id="${escape(o.logiwaIdentifier)}">
        <div class="row">
          <h3 class="grow">${escape(o.logiwaCode)}</h3>
          <span class="badge ${o.rfsState}">${o.rfsState.replace('_',' ')}</span>
        </div>
        <div class="meta">
          <div>${escape(o.shipmentOrderTypeName || '')}</div>
          <div>${escape(o.clientName || '')} · ${escape(o.customerName || '')}</div>
          <div>Qty: ${o.totalQuantity || 0} · Pallets: ${o.palletsLoaded}/${o.palletCount} loaded · Expected: ${fmtDate(o.expectedShipmentDate)}</div>
        </div>
      </div>
    `);
    card.onclick = () => { state.selectedOrderId = o.logiwaIdentifier; render(); };
    list.appendChild(card);
  }
}

// ─── order detail (used by both Putaway and Pickup tabs) ─────────────────────
async function renderOrderDetail() {
  const v = $('#view');
  v.innerHTML = '<div class="loader">Loading…</div>';
  try {
    const { order } = await api('GET', `/api/rfs/orders/${state.selectedOrderId}`);
    const isAwaiting = order.rfsState === 'awaiting_putaway';
    const isStaged = order.rfsState === 'staged';
    const isLoading = order.rfsState === 'loading';
    const isLoaded = order.rfsState === 'loaded';

    v.innerHTML = `
      <button class="btn secondary" id="btn-back">← Back</button>
      <div class="card" style="margin-top:12px">
        <div class="row">
          <h3 class="grow">${escape(order.logiwaCode)}</h3>
          <span class="badge ${order.rfsState}">${order.rfsState.replace('_',' ')}</span>
        </div>
        <div class="meta">
          <div>${escape(order.shipmentOrderTypeName || '')}</div>
          <div>${escape(order.clientName || '')} · ${escape(order.customerName || '')}</div>
          <div>Qty: ${order.totalQuantity || 0} · Weight: ${order.totalWeight || 0}</div>
          ${order.bolReference ? `<div>BOL ref: ${escape(order.bolReference)}</div>` : ''}
          ${order.proNumber ? `<div>PRO: ${escape(order.proNumber)}</div>` : ''}
          ${order.note ? `<div>Logiwa note: ${escape(order.note)}</div>` : ''}
        </div>
      </div>

      <div class="card">
        <div class="row" style="margin-bottom:6px;align-items:center">
          <h3 class="grow" style="margin:0;font-size:15px">Internal notes</h3>
          <span class="hint" style="font-size:11px">not sent in emails</span>
        </div>
        <textarea id="order-note" rows="3" placeholder="Add a note for the warehouse / CSM team…" style="width:100%;padding:8px;border:1px solid #c4cdd5;border-radius:8px;font-size:14px;font-family:inherit;resize:vertical">${escape(order.internalNote || '')}</textarea>
        <div class="row" style="margin-top:6px;align-items:center">
          <span class="hint grow" id="note-meta">${order.internalNoteUpdatedAt ? 'Last updated ' + fmtTs(order.internalNoteUpdatedAt) + ' by ' + escape(order.internalNoteUpdatedBy || '') : ''}</span>
          <button class="btn secondary" id="btn-save-note" style="padding:6px 14px;min-height:0;font-size:12px">Save note</button>
        </div>
      </div>

      <div id="action-area"></div>
    `;
    $('#btn-back').onclick = () => { state.selectedOrderId = null; state.editPutaway = false; stopScanner(); stopBolStream(); render(); };
    $('#btn-save-note').onclick = async () => {
      const btn = $('#btn-save-note');
      try {
        btn.disabled = true; btn.textContent = 'Saving…';
        await api('PUT', `/api/rfs/orders/${state.selectedOrderId}/note`, { note: $('#order-note').value });
        toast('Note saved');
        $('#note-meta').textContent = `Last updated just now by ${state.user.email}`;
      } catch (e) { toast(e.message, 'error'); }
      finally { btn.disabled = false; btn.textContent = 'Save note'; }
    };

    const area = $('#action-area');
    // If user explicitly opened "Edit putaway details" on a staged/loading/loaded order,
    // force the putaway form so they can fix dims/weight/locations.
    if (isAwaiting || state.editPutaway) renderPutawayForm(area, order);
    else if (isStaged || isLoading) renderLoadingArea(area, order);
    else if (isLoaded) renderBOLUpload(area, order);
    else if (order.rfsState === 'shipped' || order.rfsState === 'archived_externally') {
      const palletRows = (order.pallets || []).map(p => {
        const dims = (p.length || p.width || p.height || p.weight)
          ? `${p.length || '—'} × ${p.width || '—'} × ${p.height || '—'} ${escape(p.dimensionUnit || 'in')} · ${p.weight || '—'} ${escape(p.weightUnit || 'lb')}`
          : '<span style="color:#999">No dims/weight recorded</span>';
        return `
          <div class="pallet-row">
            <div class="row"><span class="palletNo">P${p.palletNo}</span><span class="loc grow">${escape(p.locationCode || '— never placed —')}</span></div>
            <div class="hint" style="margin-top:4px">${dims}</div>
            <div class="hint">Putaway: ${fmtTs(p.stagedAt)} ${p.stagedBy ? '· ' + escape(p.stagedBy) : ''}</div>
            ${p.loadedAt ? `<div class="hint">Loaded: ${fmtTs(p.loadedAt)} ${p.loadedBy ? '· ' + escape(p.loadedBy) : ''}</div>` : ''}
          </div>
        `;
      }).join('');
      // Bridge legacy single-BOL fields for old orders that don't have bols[] yet
      let bols = Array.isArray(order.bols) ? [...order.bols] : [];
      if (!bols.length && order.bolPhotoUrl) {
        bols.push({ photoUrl: order.bolPhotoUrl, uploadedAt: order.bolUploadedAt, uploadedBy: order.bolUploadedBy, truckLabel: null });
      }
      const bolRows = bols.map((b, i) => `
        <div class="pallet-row" style="margin-bottom:6px">
          <div class="row" style="align-items:center;gap:10px">
            <div class="grow">
              <div><strong>BOL ${i + 1}</strong>${b.truckLabel ? ' · ' + escape(b.truckLabel) : ''}</div>
              <div class="hint">${fmtTs(b.uploadedAt)} ${b.uploadedBy ? '· ' + escape(b.uploadedBy) : ''}${b.logiwaError ? ' · <span style="color:#c0392b">Logiwa: ' + escape(b.logiwaError) + '</span>' : ''}</div>
            </div>
            ${b.photoUrl ? `<a href="${escape(b.photoUrl)}" target="_blank" class="btn secondary" style="padding:6px 12px;min-height:0;font-size:12px">View</a>` : ''}
          </div>
        </div>
      `).join('');
      area.innerHTML = `
        <div class="card">
          <h3>${order.rfsState === 'shipped' ? 'Shipped' : 'Archived'}</h3>
          <div class="meta">
            ${order.rfsState === 'shipped'
              ? `Completed by ${escape(order.shippedBy || '')} on ${fmtTs(order.shippedAt)}`
              : `Order is no longer Ready to Ship in Logiwa.${order.archivedReason ? '<br>' + escape(order.archivedReason) : ''}`}
          </div>
        </div>
        ${bols.length ? `<div class="card"><h3>BOLs (${bols.length})</h3>${bolRows}</div>` : ''}
        <div class="card">
          <h3>Pallets</h3>
          ${palletRows || '<div class="empty" style="padding:16px">No pallets recorded.</div>'}
        </div>
      `;
    }
  } catch (e) { toast(e.message, 'error'); }
}

// ─── putaway form ────────────────────────────────────────────────────────────
function renderPutawayForm(area, order) {
  const editing = state.editPutaway && order.rfsState !== 'awaiting_putaway';
  const editingBanner = editing ? `
    <div class="card" style="background:#fff7d6;border:1px solid #f5c542;padding:10px 12px">
      <div class="row" style="align-items:center;gap:10px">
        <strong style="color:#8a6500">Editing pallet details</strong>
        <span class="grow hint" style="color:#8a6500">Order is already <strong>${escape(order.rfsState.replace('_',' '))}</strong>. Changes won't unload any loaded pallets.</span>
        <button class="btn secondary" id="btn-cancel-edit" style="padding:6px 12px;min-height:0;font-size:12px">Cancel</button>
      </div>
    </div>
  ` : '';
  area.innerHTML = `
    ${editingBanner}
    <div class="card">
      <h3>Putaway pallets</h3>
      <label>How many pallets for this order?</label>
      <input type="number" id="pallet-count" min="1" max="50" value="${(order.pallets||[]).length || 1}" inputmode="numeric" />
      <button class="btn full" id="btn-build" style="margin-top:10px">Continue</button>
    </div>
    <div id="pallet-rows"></div>
  `;
  $('#btn-build').onclick = () => buildPalletRows(parseInt($('#pallet-count').value, 10) || 1, order.pallets);
  if ((order.pallets||[]).length) buildPalletRows(order.pallets.length, order.pallets);
  if (editing) {
    $('#btn-cancel-edit').onclick = () => { state.editPutaway = false; render(); };
  }
}

async function buildPalletRows(count, existing) {
  const host = $('#pallet-rows');
  host.innerHTML = '<div class="loader">Loading available locations…</div>';
  let suggestions = [];
  try {
    const r = await api('GET', '/api/rfs/locations/available?limit=200');
    suggestions = r.locations || [];
  } catch (e) { /* fallback to free-text */ }

  // "Floor" is always at the top — pallets on the warehouse floor, no specific rack.
  const dlistOpts = '<option value="Floor"></option>' + suggestions.slice(0, 100).map(l => `<option value="${escape(l.code)}">`).join('');
  host.innerHTML = `
    <datalist id="loc-options">${dlistOpts}</datalist>
    <div class="card">
      <h3>Assign locations + dims/weight</h3>
      <div class="hint" style="margin-bottom:8px">Codes starting with <strong>26-</strong> are prioritized. Type <strong>Floor</strong> for pallets sitting on the warehouse floor. Partial saves are kept.</div>
      <div id="rows"></div>
      <div class="row" style="margin-top:8px">
        <button class="btn secondary" id="btn-add-row" style="flex:0 0 auto">+ Add pallet</button>
        <div class="grow"></div>
      </div>
      <button class="btn full" id="btn-save" style="margin-top:10px">Save</button>
    </div>
  `;

  const rows = $('#rows');
  for (let i = 0; i < count; i++) {
    addPalletRow(rows, i + 1, existing && existing[i]);
  }
  $('#btn-add-row').onclick = () => {
    const next = rows.querySelectorAll('.pallet-row').length + 1;
    addPalletRow(rows, next, null);
  };
  $('#btn-save').onclick = () => savePutaway(rows);
}

function addPalletRow(rows, palletNo, existing) {
  // Two helper buttons:
  //  - P1: "Apply to all below" — fills L/W/H/Wt of every other pallet with P1's values
  //  - P2 and later: "↑ Same as above" — copies dims/weight from the previous pallet
  const helperBtn = palletNo === 1
    ? '<button data-action="apply-all" style="background:transparent;border:1px solid #0d3b66;color:#0d3b66;padding:4px 10px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Apply to all below</button>'
    : '<button data-action="copy-above" style="background:transparent;border:1px solid #0d3b66;color:#0d3b66;padding:4px 10px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">↑ Same as above</button>';

  const row = el(`
    <div class="pallet-row" data-row="${palletNo}">
      <div class="row" style="margin-bottom:6px">
        <span class="palletNo">P${palletNo}</span>
        <input type="text" class="grow" list="loc-options" placeholder="Scan or type location code" value="${escape(existing?.locationCode || '')}" data-pallet="${palletNo}" data-field="locationCode" />
        <button class="btn secondary" data-scan="${palletNo}" style="padding:8px 12px;min-height:0">Scan</button>
      </div>
      <div class="row" style="gap:6px">
        <input type="number" inputmode="decimal" class="grow" placeholder="L" step="0.1" value="${existing?.length ?? ''}" data-pallet="${palletNo}" data-field="length" style="padding:8px;min-width:0" />
        <input type="number" inputmode="decimal" class="grow" placeholder="W" step="0.1" value="${existing?.width ?? ''}" data-pallet="${palletNo}" data-field="width" style="padding:8px;min-width:0" />
        <input type="number" inputmode="decimal" class="grow" placeholder="H" step="0.1" value="${existing?.height ?? ''}" data-pallet="${palletNo}" data-field="height" style="padding:8px;min-width:0" />
        <input type="number" inputmode="decimal" class="grow" placeholder="Wt" step="0.1" value="${existing?.weight ?? ''}" data-pallet="${palletNo}" data-field="weight" style="padding:8px;min-width:0" />
      </div>
      <div class="row" style="margin-top:4px;align-items:center;gap:8px">
        <span class="hint grow">Dims in <strong>${existing?.dimensionUnit || 'in'}</strong> · Weight in <strong>${existing?.weightUnit || 'lb'}</strong>${existing?.state === 'loaded' ? ' · <span style="color:#1f6b1f">loaded</span>' : (existing?.state === 'staged' ? ' · <span style="color:#0d3b66">staged</span>' : '')}</span>
        ${helperBtn}
      </div>
    </div>
  `);
  rows.appendChild(row);

  row.querySelector('button[data-scan]').onclick = () => openScanner((code) => {
    const inp = row.querySelector('input[data-field="locationCode"]');
    if (inp) inp.value = code.trim();
  });

  const helper = row.querySelector('button[data-action]');
  if (helper) {
    helper.onclick = () => {
      if (helper.dataset.action === 'apply-all') applyPalletDimsToAll(row);
      else if (helper.dataset.action === 'copy-above') copyPalletDimsFromAbove(row);
    };
  }
}

// Copy L/W/H/Wt from this row into every other pallet row (skips locationCode).
function applyPalletDimsToAll(sourceRow) {
  const fields = ['length', 'width', 'height', 'weight'];
  const values = {};
  fields.forEach(f => { values[f] = sourceRow.querySelector(`input[data-field="${f}"]`)?.value || ''; });
  let copied = 0;
  document.querySelectorAll('.pallet-row').forEach(r => {
    if (r === sourceRow) return;
    fields.forEach(f => {
      const inp = r.querySelector(`input[data-field="${f}"]`);
      if (inp) inp.value = values[f];
    });
    copied += 1;
  });
  toast(`Applied to ${copied} pallet${copied === 1 ? '' : 's'}`);
}

// Copy L/W/H/Wt from the previous pallet row into this one.
function copyPalletDimsFromAbove(targetRow) {
  let prev = targetRow.previousElementSibling;
  while (prev && !prev.classList?.contains('pallet-row')) prev = prev.previousElementSibling;
  if (!prev) { toast('No pallet above', 'error'); return; }
  ['length', 'width', 'height', 'weight'].forEach(f => {
    const src = prev.querySelector(`input[data-field="${f}"]`);
    const dst = targetRow.querySelector(`input[data-field="${f}"]`);
    if (src && dst) dst.value = src.value;
  });
}

async function savePutaway(rows) {
  const palletEls = rows.querySelectorAll('.pallet-row');
  const pallets = [];
  for (const r of palletEls) {
    const palletNo = parseInt(r.dataset.row, 10);
    const get = (f) => r.querySelector(`input[data-field="${f}"]`)?.value?.trim() || '';
    pallets.push({
      palletNo,
      locationCode: get('locationCode'),
      length: get('length'),
      width: get('width'),
      height: get('height'),
      weight: get('weight'),
    });
  }
  const btn = $('#btn-save');
  try {
    btn.disabled = true;
    btn.textContent = 'Saving…';
    await api('POST', `/api/rfs/orders/${state.selectedOrderId}/putaway`, { pallets });
    const filled = pallets.filter(p => p.locationCode).length;
    if (filled === pallets.length) toast(`All ${pallets.length} pallets staged — ready for pickup`);
    else toast(`Saved. ${filled}/${pallets.length} pallets placed.`);
    state.editPutaway = false;
    render();
  } catch (e) { toast(e.message, 'error'); }
  finally { btn.disabled = false; btn.textContent = 'Save'; }
}

// ─── loading area (driver pickup) ────────────────────────────────────────────
function renderLoadingArea(area, order) {
  area.innerHTML = `
    <div class="card">
      <div class="row" style="margin-bottom:8px;align-items:center">
        <h3 class="grow" style="margin:0">Pallet locations</h3>
        <button class="btn secondary" id="btn-edit-putaway" style="padding:6px 12px;min-height:0;font-size:12px">Edit putaway details</button>
      </div>
      <div id="pallets"></div>
    </div>
  `;
  $('#btn-edit-putaway').onclick = () => { state.editPutaway = true; render(); };

  const host = $('#pallets');
  for (const p of (order.pallets || [])) {
    const dimsLine = (p.length || p.width || p.height || p.weight)
      ? `<div class="hint" style="margin-top:4px">Dims: ${p.length || '—'} × ${p.width || '—'} × ${p.height || '—'} ${escape(p.dimensionUnit || 'in')} · Weight: ${p.weight || '—'} ${escape(p.weightUnit || 'lb')}</div>`
      : '<div class="hint" style="margin-top:4px;color:#999">No dims/weight recorded</div>';
    let action;
    if (p.state === 'loaded') {
      action = `<button class="btn secondary" data-unload="${p.palletNo}" style="padding:8px 14px;min-height:0">Mark unloaded</button>`;
    } else if (p.locationCode) {
      action = `<button class="btn" data-load="${p.palletNo}" style="padding:8px 14px;min-height:0">Mark loaded</button>`;
    } else {
      action = '<span class="badge awaiting">pending</span>';
    }
    const r = el(`
      <div class="pallet-row">
        <div class="row">
          <span class="palletNo">P${p.palletNo}</span>
          <span class="loc grow">${escape(p.locationCode || '— not yet placed —')}${p.state === 'loaded' ? ' <span class="badge loaded" style="margin-left:6px">loaded</span>' : ''}</span>
          ${action}
        </div>
        ${dimsLine}
      </div>
    `);
    host.appendChild(r);
  }
  host.querySelectorAll('button[data-load]').forEach(b => {
    b.onclick = async () => {
      try {
        b.disabled = true;
        await api('POST', `/api/rfs/orders/${state.selectedOrderId}/load-pallet`, { palletNo: parseInt(b.dataset.load, 10) });
        render();
      } catch (e) { toast(e.message, 'error'); b.disabled = false; }
    };
  });
  host.querySelectorAll('button[data-unload]').forEach(b => {
    b.onclick = async () => {
      const palletNo = b.dataset.unload;
      if (!confirm(`Mark pallet P${palletNo} as unloaded? It'll go back to the staged list.`)) return;
      try {
        b.disabled = true;
        await api('POST', `/api/rfs/orders/${state.selectedOrderId}/unload-pallet`, { palletNo: parseInt(palletNo, 10) });
        toast(`P${palletNo} unloaded`);
        render();
      } catch (e) { toast(e.message, 'error'); b.disabled = false; }
    };
  });
}

// ─── BOL upload ──────────────────────────────────────────────────────────────
function renderBOLUpload(area, order) {
  // Build the list of uploaded BOLs. Bridge legacy single-BOL fields into the new array
  // so older orders display correctly without a migration.
  let bols = Array.isArray(order.bols) ? [...order.bols] : [];
  if (!bols.length && order.bolPhotoUrl) {
    bols.push({
      photoUrl: order.bolPhotoUrl,
      uploadedAt: order.bolUploadedAt,
      uploadedBy: order.bolUploadedBy,
      truckLabel: null,
      logiwaError: order.logiwaUploadError || null,
    });
  }

  const bolsHtml = bols.length ? bols.map((b, i) => `
    <div class="pallet-row" style="margin-bottom:6px">
      <div class="row" style="align-items:center;gap:10px">
        <div class="grow">
          <div><strong>BOL ${i + 1}</strong>${b.truckLabel ? ' · ' + escape(b.truckLabel) : ''}</div>
          <div class="hint" style="margin-top:2px">${fmtTs(b.uploadedAt)} · ${escape(b.uploadedBy || '')}${b.logiwaError ? ' · <span style="color:#c0392b">Logiwa: ' + escape(b.logiwaError) + '</span>' : ' · <span style="color:#1f6b1f">in Logiwa</span>'}</div>
        </div>
        ${b.photoUrl ? `<a href="${escape(b.photoUrl)}" target="_blank" class="btn secondary" style="padding:6px 12px;min-height:0;font-size:12px">View</a>` : ''}
      </div>
    </div>
  `).join('') : '<div class="meta">No BOL uploaded yet.</div>';

  area.innerHTML = `
    ${bols.length ? `
      <div class="card">
        <h3>Uploaded BOLs (${bols.length})</h3>
        ${bolsHtml}
      </div>
    ` : ''}

    <div class="card">
      <div class="row" style="margin-bottom:8px;align-items:center">
        <h3 class="grow" style="margin:0">${bols.length ? 'Upload another BOL' : 'Upload BOL'}</h3>
        <button class="btn secondary" id="btn-edit-putaway-bol" style="padding:6px 12px;min-height:0;font-size:12px">Edit putaway details</button>
      </div>
      <div class="meta" style="margin-bottom:8px">All pallets loaded. Snap a photo of the signed BOL — one per truck. The order stays "loaded" until you tap <strong>Mark order shipped</strong> below.</div>

      <label>Truck / driver label (optional)</label>
      <input type="text" id="bol-truck" placeholder="e.g. Truck 1, Maersk #12345" style="margin-bottom:10px" />

      <div id="bol-cam-area">
        <video id="bol-video" style="width:100%;max-height:75vh;border-radius:8px;background:#000;object-fit:contain;display:block" playsinline autoplay muted></video>
        <div id="bol-cam-status" class="hint" style="text-align:center;margin:6px 0">Starting camera…</div>
        <button class="btn full" id="btn-snap" style="margin-top:6px">Capture photo</button>
        <div style="text-align:center;margin:10px 0;color:#888;font-size:13px">— or —</div>
        <label class="btn secondary full" for="bol-file" style="cursor:pointer">Choose file from device</label>
        <input type="file" id="bol-file" accept="image/*" capture="environment" style="display:none" />
      </div>
      <canvas id="bol-canvas" style="display:none"></canvas>
      <div id="bol-preview-area" style="display:none">
        <img id="bol-preview" style="max-width:100%;border-radius:8px;margin-top:10px" />
        <button class="btn secondary full" id="btn-retake" style="margin-top:8px">Retake</button>
      </div>
      <button class="btn full" id="btn-upload-bol" style="margin-top:10px" disabled>Upload BOL</button>
    </div>

    <div class="card" style="background:#f4f9f4;border:1px solid #c8e6c8">
      <h3 style="margin-top:0;color:#1f6b1f">Done loading this order?</h3>
      <div class="meta" style="margin-bottom:8px">Tap below to mark the order shipped. ${bols.length === 0 ? 'You can mark shipped even without a BOL on file (upload one later).' : 'You can still upload additional BOLs after shipping if needed.'}</div>
      <button class="btn full" id="btn-mark-shipped" style="background:#1f6b1f">Mark order shipped</button>
    </div>
  `;

  // Edit-putaway button is at the top of the BOL screen — same flow as on the loading screen.
  $('#btn-edit-putaway-bol')?.addEventListener('click', () => { state.editPutaway = true; stopBolStream(); render(); });

  let capturedBlob = null;
  const video = $('#bol-video');
  const canvas = $('#bol-canvas');
  const preview = $('#bol-preview');
  const status = $('#bol-cam-status');
  const camArea = $('#bol-cam-area');
  const previewArea = $('#bol-preview-area');
  const fileInp = $('#bol-file');
  const btnSnap = $('#btn-snap');
  const btnRetake = $('#btn-retake');
  const btnUpload = $('#btn-upload-bol');

  async function startCam() {
    try {
      // Request the highest resolution the camera can give us so the BOL is legible.
      // The browser will downgrade gracefully if the device can't deliver this.
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1920 },
          height: { ideal: 1080 },
        },
        audio: false,
      });
      state.bolStream = stream;
      video.srcObject = stream;
      status.textContent = 'Position the BOL in frame and tap Capture.';
    } catch (err) {
      video.style.display = 'none';
      btnSnap.style.display = 'none';
      status.textContent = 'Camera unavailable — use "Choose file from device" instead.';
    }
  }

  startCam();

  function showPreview(blob) {
    capturedBlob = blob;
    preview.src = URL.createObjectURL(blob);
    camArea.style.display = 'none';
    previewArea.style.display = '';
    btnUpload.disabled = false;
    stopBolStream();
  }

  btnSnap.onclick = () => {
    if (!video.videoWidth) { toast('Camera not ready yet', 'error'); return; }
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob((blob) => { if (blob) showPreview(blob); }, 'image/jpeg', 0.9);
  };

  btnRetake.onclick = () => {
    capturedBlob = null;
    preview.src = '';
    previewArea.style.display = 'none';
    camArea.style.display = '';
    btnUpload.disabled = true;
    fileInp.value = '';
    startCam();
  };

  fileInp.onchange = () => {
    const f = fileInp.files?.[0];
    if (f) showPreview(f);
  };

  btnUpload.onclick = async () => {
    if (!capturedBlob) return;
    const fd = new FormData();
    const ext = capturedBlob.type === 'image/png' ? 'png' : 'jpg';
    const filename = capturedBlob.name || `bol-${Date.now()}.${ext}`;
    fd.append('bol', capturedBlob, filename);
    const truckLabel = $('#bol-truck')?.value?.trim();
    if (truckLabel) fd.append('truckLabel', truckLabel);
    try {
      btnUpload.disabled = true;
      btnUpload.textContent = 'Uploading…';
      const r = await api('POST', `/api/rfs/orders/${state.selectedOrderId}/bol`, fd, true);
      if (r.logiwaError) toast('BOL saved, but Logiwa: ' + r.logiwaError, 'error');
      else toast(`BOL ${r.bolCount} uploaded`);
      // Stay on the order — user may want to upload more BOLs or click Mark shipped.
      render();
    } catch (e) {
      toast(e.message, 'error');
      btnUpload.disabled = false;
      btnUpload.textContent = 'Upload BOL';
    }
  };

  // Explicit ship action — separate from BOL upload so an order can collect multiple BOLs first.
  $('#btn-mark-shipped')?.addEventListener('click', async () => {
    if (!confirm(`Mark order ${order.logiwaCode} as shipped? It'll disappear from the active list.`)) return;
    const btn = $('#btn-mark-shipped');
    try {
      btn.disabled = true; btn.textContent = 'Shipping…';
      await api('POST', `/api/rfs/orders/${state.selectedOrderId}/ship`);
      toast('Order shipped');
      stopBolStream();
      state.selectedOrderId = null;
      render();
    } catch (e) {
      toast(e.message, 'error');
      btn.disabled = false;
      btn.textContent = 'Mark order shipped';
    }
  });
}

function stopBolStream() {
  if (state.bolStream) {
    try { state.bolStream.getTracks().forEach(t => t.stop()); } catch {}
    state.bolStream = null;
  }
}

async function lookupOrderByCode(code) {
  // First try as an order code; if not found, fall back to a location lookup.
  const trimmed = String(code).trim();
  try {
    const { order } = await api('GET', `/api/rfs/orders/by-code/${encodeURIComponent(trimmed)}`);
    stopScanner();
    state.selectedOrderId = order.logiwaIdentifier;
    render();
    return;
  } catch (e) {
    // 404 from order lookup → try location
    if (!/not found/i.test(e.message)) { toast(e.message, 'error'); return; }
  }
  try {
    const data = await api('GET', `/api/rfs/locations/${encodeURIComponent(trimmed)}`);
    stopScanner();
    renderLocationDetail(data);
  } catch (e) {
    toast(`No order or location found for "${trimmed}"`, 'error');
  }
}

function renderLocationDetail({ location, currentOrder, currentPallet }) {
  state.view = 'scan';
  state.selectedOrderId = null;
  const v = $('#view');
  const dims = currentPallet && (currentPallet.length || currentPallet.width || currentPallet.height || currentPallet.weight)
    ? `${currentPallet.length || '—'} × ${currentPallet.width || '—'} × ${currentPallet.height || '—'} ${escape(currentPallet.dimensionUnit || 'in')} · ${currentPallet.weight || '—'} ${escape(currentPallet.weightUnit || 'lb')}`
    : null;
  v.innerHTML = `
    <button class="btn secondary" id="btn-back-scan">← Back to scan</button>
    <div class="card" style="margin-top:12px">
      <h3>Location ${escape(location.code)}</h3>
      <div class="meta">
        Zone: ${escape(location.zone || '—')} · Group: ${escape(location.group || '—')}<br>
        Barcode: <span style="font-family:ui-monospace,monospace">${escape(location.locationBarcode || location.code)}</span>
        ${location.lockLocation ? '<br><span style="color:#c0392b">Locked</span>' : ''}
        ${location.preventAllocation ? '<br><span style="color:#c0392b">Prevent allocation</span>' : ''}
      </div>
    </div>
    ${currentOrder ? `
      <div class="card">
        <h3>Currently holding</h3>
        <div class="row" style="margin-bottom:6px">
          <strong class="grow">${escape(currentOrder.logiwaCode)}</strong>
          <span class="badge ${currentOrder.rfsState}">${escape(currentOrder.rfsState.replace('_',' '))}</span>
        </div>
        <div class="meta">
          ${escape(currentOrder.shipmentOrderTypeName || '')}<br>
          Client: <strong>${escape(currentOrder.clientName || '—')}</strong><br>
          Customer: ${escape(currentOrder.customerName || '—')}<br>
          Pallet: <strong>P${location.currentPalletNo}</strong>${dims ? '<br>Dims/weight: ' + dims : ''}<br>
          Expected ship: ${fmtDate(currentOrder.expectedShipmentDate)}
        </div>
        <button class="btn full" id="btn-open-order" style="margin-top:10px">Open order</button>
      </div>
    ` : `
      <div class="card">
        <h3>Empty</h3>
        <div class="meta">No RFS pallet currently staged here. Has inventory in Logiwa: <strong>${location.hasInventory ? 'Yes' : 'No'}</strong></div>
      </div>
    `}
  `;
  $('#btn-back-scan').onclick = () => { render(); };
  if (currentOrder) $('#btn-open-order').onclick = () => { state.selectedOrderId = currentOrder.logiwaIdentifier; render(); };
}

// ─── scanner (html5-qrcode) ──────────────────────────────────────────────────
// openScanner works in two contexts:
//  - When a `#qr-reader` div exists on the page (Scan tab, Receive PO tab) — use that inline.
//  - Otherwise — create a full-screen modal with a fresh `#qr-reader` so any "Scan" button
//    in the app (putaway location input, etc.) can open the camera on demand.
function openScanner(onResult) {
  stopScanner();
  let target = document.getElementById('qr-reader');
  let modal = null;

  if (!target) {
    modal = el(`
      <div id="scan-modal" style="position:fixed;inset:0;background:#000;z-index:1500;display:flex;flex-direction:column">
        <div style="padding:14px 16px;color:#fff;display:flex;align-items:center;justify-content:space-between;background:#0d3b66">
          <strong style="font-size:15px">Scan barcode</strong>
          <button id="scan-close-btn" style="background:transparent;border:none;color:#fff;font-size:28px;cursor:pointer;line-height:1">×</button>
        </div>
        <div id="qr-reader" style="flex:1;background:#000;width:100%"></div>
        <div style="padding:14px 16px;text-align:center;color:#fff;font-size:13px;opacity:0.85">Position the barcode in the frame…</div>
      </div>
    `);
    document.body.appendChild(modal);
    target = document.getElementById('qr-reader');
    state.scanModal = modal;
    modal.querySelector('#scan-close-btn').onclick = () => stopScanner();
  }

  if (typeof Html5Qrcode === 'undefined') {
    target.innerHTML = '<div class="empty" style="background:#fff;border-radius:8px;margin:16px">Camera scanner library unavailable. Type the code instead.</div>';
    return;
  }

  try {
    const scanner = new Html5Qrcode('qr-reader');
    state.scanner = scanner;
    scanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 280, height: 180 } },
      (decoded) => { stopScanner(); onResult(decoded); },
      () => {}
    ).catch(err => {
      target.innerHTML = `<div class="empty" style="background:#fff;border-radius:8px;margin:16px">Camera not available: ${escape(err.message || err)}. Type the code instead.</div>`;
    });
  } catch (e) {
    target.innerHTML = `<div class="empty" style="background:#fff;border-radius:8px;margin:16px">Scanner error: ${escape(e.message)}. Type the code instead.</div>`;
  }
}

function stopScanner() {
  if (state.scanner) {
    try { state.scanner.stop().catch(() => {}).finally(() => { state.scanner = null; }); }
    catch { state.scanner = null; }
  }
  if (state.scanModal) {
    try { state.scanModal.remove(); } catch {}
    state.scanModal = null;
  }
}

// ─── reports (with sub-tabs) ─────────────────────────────────────────────────
const REPORT_SUBTABS = [
  { id: 'orders',        label: 'Orders',        roles: ['admin','supervisor','csm'] },
  { id: 'pos',           label: 'POs',           roles: ['admin','supervisor','csm'] },
  { id: 'activity',      label: 'Activity',      roles: ['admin','supervisor','csm'] },
  { id: 'users',         label: 'Users',         roles: ['admin'] },
  { id: 'notifications', label: 'Notifications', roles: ['admin'] },
  { id: 'locations',     label: 'Locations',     roles: ['admin'] },
];

async function renderAdmin() {
  const v = $('#view');
  const role = state.user?.role;
  const tabs = REPORT_SUBTABS.filter(t => t.roles.includes(role));
  if (!state.reportsTab || !tabs.find(t => t.id === state.reportsTab)) {
    state.reportsTab = tabs[0]?.id || 'orders';
  }
  v.innerHTML = `
    <div style="background:#fff;border:1px solid #e8eaed;border-radius:10px;padding:4px;display:flex;gap:2px;margin-bottom:14px;overflow-x:auto">
      ${tabs.map(t => `
        <button class="reports-subtab${state.reportsTab === t.id ? ' active' : ''}" data-rsub="${t.id}"
          style="flex:1;min-width:90px;padding:10px 12px;border:none;background:${state.reportsTab === t.id ? '#0d3b66' : 'transparent'};color:${state.reportsTab === t.id ? '#fff' : '#0d3b66'};font-weight:600;border-radius:8px;cursor:pointer;font-size:14px">
          ${t.label}
        </button>
      `).join('')}
    </div>
    <div id="reports-content"></div>
  `;
  v.querySelectorAll('button[data-rsub]').forEach(b => {
    b.onclick = () => { state.reportsTab = b.dataset.rsub; renderAdmin(); };
  });
  await renderReportsContent();
}

async function renderReportsContent() {
  const host = $('#reports-content');
  if (!host) return;
  const tab = state.reportsTab;

  if (tab === 'orders') {
    host.innerHTML = `
      <div class="card">
        <h3>Orders report</h3>
        <div class="row" style="margin-bottom:8px;flex-wrap:wrap;gap:6px">
          <label style="margin:0;flex:0 0 auto">Show last</label>
          <select id="hist-days" style="width:auto">
            <option value="7">7 days</option>
            <option value="30" selected>30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
          </select>
          <button class="btn secondary" id="btn-export" style="padding:8px 12px;min-height:0">Export CSV</button>
        </div>
        <div id="hist-filter-host"></div>
        <div id="history-table"><div class="loader">Loading…</div></div>
      </div>
    `;
    $('#hist-days').onchange = () => loadAdminHistory();
    $('#btn-export').onclick = () => exportHistoryCSV();
    await loadAdminHistory();

  } else if (tab === 'pos') {
    host.innerHTML = `
      <div class="card">
        <h3>POs report</h3>
        <div class="row" style="margin-bottom:8px;flex-wrap:wrap;gap:6px">
          <label style="margin:0;flex:0 0 auto">Show last</label>
          <select id="po-days" style="width:auto">
            <option value="7">7 days</option>
            <option value="30" selected>30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
          </select>
          <button class="btn secondary" id="btn-po-export" style="padding:8px 12px;min-height:0">Export CSV</button>
        </div>
        <div id="po-filter-host"></div>
        <div id="po-receipts"><div class="loader">Loading…</div></div>
      </div>
    `;
    $('#po-days').onchange = () => loadAdminPOReceipts();
    $('#btn-po-export').onclick = () => exportPOReceiptsCSV();
    loadAdminPOReceipts();

  } else if (tab === 'activity') {
    host.innerHTML = `
      <div class="card">
        <h3>Activity log</h3>
        <div class="row" style="margin-bottom:8px;flex-wrap:wrap;gap:6px">
          <label style="margin:0;flex:0 0 auto">Show last</label>
          <select id="ev-days" style="width:auto">
            <option value="1">24 hours</option>
            <option value="7" selected>7 days</option>
            <option value="30">30 days</option>
          </select>
          <select id="ev-type" style="width:auto">
            <option value="">All event types</option>
            <option value="sync.run">Logiwa sync</option>
            <option value="order.staged">Putaway</option>
            <option value="pallet.loaded">Pallet loaded</option>
            <option value="bol.uploaded">BOL uploaded</option>
            <option value="po.arrived">PO received</option>
            <option value="po.blind_received">Blind receipt</option>
            <option value="user.created">User created</option>
            <option value="user.invited">User invited</option>
            <option value="user.role_changed">Role changed</option>
            <option value="user.disabled">User disabled</option>
            <option value="user.enabled">User enabled</option>
          </select>
          <button class="btn secondary" id="btn-ev-refresh" style="padding:8px 12px;min-height:0">Refresh</button>
        </div>
        <div id="events-list"><div class="loader">Loading…</div></div>
      </div>
    `;
    $('#ev-days').onchange = () => loadEventsLog();
    $('#ev-type').onchange = () => loadEventsLog();
    $('#btn-ev-refresh').onclick = () => loadEventsLog();
    loadEventsLog();

  } else if (tab === 'users') {
    renderUsersSection(host);

  } else if (tab === 'notifications') {
    renderNotificationsSection(host);

  } else if (tab === 'locations') {
    host.innerHTML = `
      <div class="card">
        <h3>Locations</h3>
        <div id="loc-summary" class="meta">Loading…</div>
      </div>
    `;
    try {
      const r = await api('GET', '/api/rfs/locations');
      const empty = r.locations.filter(l => !l.hasInventory && !l.preventAllocation && !l.lockLocation && !l.currentPalletOrderId).length;
      const occupied = r.locations.filter(l => l.currentPalletOrderId).length;
      $('#loc-summary').innerHTML = `
        Total: <strong>${r.count}</strong><br>
        Available now: <strong>${empty}</strong><br>
        Holding RFS pallets: <strong>${occupied}</strong><br>
        <span class="hint">Re-import the Logiwa Warehouse Location Report via <code>npm run import-locations &lt;path-to-xlsx&gt;</code> to refresh.</span>
      `;
    } catch (e) { $('#loc-summary').textContent = 'Failed to load: ' + e.message; }
  }
}

// ─── Users sub-tab ───────────────────────────────────────────────────────────
let _adminUsers = [];

async function renderUsersSection(host) {
  host.innerHTML = `
    <div class="card">
      <h3>Add user</h3>
      <div class="filter-grid" style="margin-bottom:8px">
        <input type="email" id="inv-email" placeholder="Email" />
        <input type="text" id="inv-name" placeholder="Display name (optional)" />
        <input type="password" id="inv-password" placeholder="Password (≥ 6 chars, optional)" />
        <select id="inv-role">
          <option value="worker">Worker</option>
          <option value="csm">CSM</option>
          <option value="supervisor">Supervisor</option>
          <option value="admin">Admin</option>
        </select>
        <button class="btn" id="btn-invite">Save</button>
      </div>
      <div class="hint">If you set a password, the account is created immediately and the user can sign in with email + password. If you leave password blank, an invite is stored and the role is applied on their first Google / email sign-in.</div>
    </div>

    <div class="card">
      <h3>All users <span id="users-count" class="hint" style="font-weight:400"></span></h3>
      <div id="users-list"><div class="loader">Loading…</div></div>
    </div>
  `;
  $('#btn-invite').onclick = saveInvite;
  await loadUsersList();
}

async function saveInvite() {
  const email = $('#inv-email').value.trim();
  const role = $('#inv-role').value;
  const password = $('#inv-password').value;
  const displayName = $('#inv-name').value.trim();
  if (!email) { toast('Email required', 'error'); return; }
  try {
    $('#btn-invite').disabled = true;
    const r = await api('POST', '/api/rfs/invites', { email, role, password: password || undefined, displayName: displayName || undefined });
    toast(r.mode === 'created' ? `User created — ${email} can sign in now` : `Invite saved for ${email}`);
    $('#inv-email').value = '';
    $('#inv-name').value = '';
    $('#inv-password').value = '';
    await loadUsersList();
  } catch (e) { toast(e.message, 'error'); }
  finally { $('#btn-invite').disabled = false; }
}

async function loadUsersList() {
  const host = $('#users-list');
  if (!host) return;
  try {
    const { users } = await api('GET', '/api/rfs/admin/users');
    _adminUsers = users;
    $('#users-count').textContent = `(${users.length})`;
    if (!users.length) { host.innerHTML = '<div class="empty" style="padding:16px">No users yet.</div>'; return; }
    host.innerHTML = `
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="text-align:left;background:#f7f9fb">
              <th style="padding:8px">Email</th>
              <th style="padding:8px">Name</th>
              <th style="padding:8px">Role</th>
              <th style="padding:8px">Status</th>
              <th style="padding:8px">Last seen</th>
              <th style="padding:8px">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${users.map(u => {
              const isSelf = u.uid && u.uid === state.user.uid;
              const statusBadge = u.status === 'invited'
                ? '<span class="badge awaiting">invited</span>'
                : (u.disabled ? '<span class="badge" style="background:#fde2e2;color:#a32020">disabled</span>' : '<span class="badge loaded">active</span>');
              return `
                <tr style="border-top:1px solid #e8eaed">
                  <td style="padding:8px">${escape(u.email)}${isSelf ? ' <span class="hint">(you)</span>' : ''}</td>
                  <td style="padding:8px">${escape(u.displayName || '—')}</td>
                  <td style="padding:8px">
                    ${u.status === 'invited' || isSelf
                      ? `<span class="badge ${u.role}">${escape(u.role)}</span>`
                      : `<select data-role-uid="${escape(u.uid)}" style="padding:4px;font-size:12px">
                          ${['worker','csm','supervisor','admin'].map(r => `<option value="${r}"${u.role === r ? ' selected' : ''}>${r}</option>`).join('')}
                        </select>`}
                  </td>
                  <td style="padding:8px">${statusBadge}</td>
                  <td style="padding:8px">${u.lastSeen ? fmtTs(u.lastSeen) : '—'}</td>
                  <td style="padding:8px">${actionsFor(u, isSelf)}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
    // Wire role-change selects
    host.querySelectorAll('select[data-role-uid]').forEach(sel => {
      sel.onchange = async () => {
        try {
          await api('PUT', `/api/rfs/admin/users/${sel.dataset.roleUid}/role`, { role: sel.value });
          toast('Role updated');
          loadUsersList();
        } catch (e) { toast(e.message, 'error'); loadUsersList(); }
      };
    });
    // Wire action buttons
    host.querySelectorAll('button[data-action]').forEach(b => {
      b.onclick = () => handleUserAction(b.dataset.action, b.dataset.uid, b.dataset.email);
    });
  } catch (e) { host.innerHTML = `<div class="empty">Failed: ${escape(e.message)}</div>`; }
}

function actionsFor(u, isSelf) {
  if (isSelf) return '<span class="hint">—</span>';
  if (u.status === 'invited') {
    return `<button class="btn secondary" data-action="cancel-invite" data-email="${escape(u.email)}" style="padding:4px 10px;min-height:0;font-size:12px">Cancel invite</button>`;
  }
  const toggleLabel = u.disabled ? 'Enable' : 'Disable';
  return `<button class="btn secondary" data-action="toggle-disabled" data-uid="${escape(u.uid)}" data-disabled="${u.disabled}" style="padding:4px 10px;min-height:0;font-size:12px">${toggleLabel}</button>`;
}

async function handleUserAction(action, uid, email) {
  try {
    if (action === 'cancel-invite') {
      if (!confirm(`Cancel invite for ${email}?`)) return;
      await api('DELETE', `/api/rfs/admin/invites/${encodeURIComponent(email)}`);
      toast('Invite cancelled');
    } else if (action === 'toggle-disabled') {
      const target = _adminUsers.find(u => u.uid === uid);
      const willDisable = !target?.disabled;
      if (willDisable && !confirm(`Disable ${target?.email}? They won't be able to sign in until you re-enable.`)) return;
      await api('PUT', `/api/rfs/admin/users/${uid}/disabled`, { disabled: willDisable });
      toast(willDisable ? 'User disabled' : 'User enabled');
    }
    loadUsersList();
  } catch (e) { toast(e.message, 'error'); }
}

// ─── Notifications sub-tab ───────────────────────────────────────────────────
const NOTIFY_EVENT_OPTIONS = [
  { v: 'order.staged',       label: 'Order putaway done' },
  { v: 'pallet.loaded',      label: 'Pallet loaded' },
  { v: 'pallet.unloaded',    label: 'Pallet unloaded' },
  { v: 'bol.uploaded',       label: 'BOL uploaded' },
  { v: 'order.shipped',      label: 'Order shipped' },
  { v: 'po.arrived',         label: 'PO received' },
  { v: 'po.blind_received',  label: 'Blind receipt (no PO)' },
  { v: 'po.linked',          label: 'Blind receipt linked to PO' },
  { v: 'sync.run',           label: 'Logiwa sync ran' },
];
const NOTIFY_CONDITION_OPTIONS = [
  { v: 'always',     label: 'Every time' },
  { v: 'has_dims',   label: 'Only if dims captured' },
  { v: 'has_weight', label: 'Only if weight captured' },
];

let _notifyRules = [];

async function renderNotificationsSection(host) {
  host.innerHTML = `
    <div class="card">
      <h3>Notification rules</h3>
      <div class="meta" style="margin-bottom:8px">When an event fires, every matching rule sends an email. Add a rule per client + event combo. Requires SMTP_USER + SMTP_PASS env vars to be configured on the server.</div>

      <div class="filter-grid" style="margin-bottom:8px">
        <select id="nr-event">
          ${NOTIFY_EVENT_OPTIONS.map(o => `<option value="${o.v}">${escape(o.label)}</option>`).join('')}
        </select>
        <input type="text" id="nr-client" list="nr-client-list" placeholder="Client (blank = all clients)" />
        <datalist id="nr-client-list"></datalist>
        <select id="nr-condition">
          ${NOTIFY_CONDITION_OPTIONS.map(o => `<option value="${o.v}">${escape(o.label)}</option>`).join('')}
        </select>
        <input type="text" id="nr-recipients" placeholder="Recipients — comma-separated emails" />
        <button class="btn" id="nr-add">Add rule</button>
      </div>

      <div id="nr-list"><div class="loader">Loading…</div></div>
    </div>
  `;

  // Populate client autocomplete from order + PO data
  api('GET', '/api/rfs/clients').then(({ clients }) => {
    const dl = $('#nr-client-list');
    if (dl && Array.isArray(clients)) dl.innerHTML = clients.map(c => `<option value="${escape(c)}"></option>`).join('');
  }).catch(() => {});

  $('#nr-add').onclick = saveNotificationRule;
  await loadNotificationRules();
}

async function saveNotificationRule() {
  const event = $('#nr-event').value;
  const clientName = $('#nr-client').value.trim() || null;
  const condition = $('#nr-condition').value;
  const recipients = $('#nr-recipients').value.split(',').map(s => s.trim()).filter(Boolean);
  if (!recipients.length) { toast('Enter at least one recipient email', 'error'); return; }
  try {
    $('#nr-add').disabled = true;
    await api('POST', '/api/rfs/admin/notification-rules', { event, clientName, condition, recipients, enabled: true });
    toast('Rule added');
    $('#nr-client').value = '';
    $('#nr-recipients').value = '';
    await loadNotificationRules();
  } catch (e) { toast(e.message, 'error'); }
  finally { $('#nr-add').disabled = false; }
}

async function loadNotificationRules() {
  const host = $('#nr-list');
  if (!host) return;
  try {
    const { rules } = await api('GET', '/api/rfs/admin/notification-rules');
    _notifyRules = rules;
    if (!rules.length) { host.innerHTML = '<div class="empty" style="padding:16px">No notification rules yet.</div>'; return; }
    host.innerHTML = `
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="text-align:left;background:#f7f9fb">
              <th style="padding:8px">Event</th>
              <th style="padding:8px">Client</th>
              <th style="padding:8px">Condition</th>
              <th style="padding:8px">Recipients</th>
              <th style="padding:8px">Status</th>
              <th style="padding:8px">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${rules.map(r => {
              const evtLabel = NOTIFY_EVENT_OPTIONS.find(o => o.v === r.event)?.label || r.event;
              const condLabel = NOTIFY_CONDITION_OPTIONS.find(o => o.v === r.condition)?.label || r.condition;
              return `
                <tr style="border-top:1px solid #e8eaed">
                  <td style="padding:8px"><strong>${escape(evtLabel)}</strong><br><span class="hint">${escape(r.event)}</span></td>
                  <td style="padding:8px">${escape(r.clientName || 'All clients')}</td>
                  <td style="padding:8px">${escape(condLabel)}</td>
                  <td style="padding:8px">${(r.recipients || []).map(e => `<div>${escape(e)}</div>`).join('')}</td>
                  <td style="padding:8px">${r.enabled ? '<span class="badge loaded">enabled</span>' : '<span class="badge" style="background:#eee;color:#888">disabled</span>'}</td>
                  <td style="padding:8px">
                    <button class="btn secondary" data-nr-action="toggle" data-id="${escape(r.id)}" style="padding:4px 8px;min-height:0;font-size:12px">${r.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn secondary" data-nr-action="test" data-id="${escape(r.id)}" style="padding:4px 8px;min-height:0;font-size:12px">Test</button>
                    <button class="btn danger" data-nr-action="delete" data-id="${escape(r.id)}" style="padding:4px 8px;min-height:0;font-size:12px">Delete</button>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
    host.querySelectorAll('button[data-nr-action]').forEach(b => {
      b.onclick = () => handleNotifyRuleAction(b.dataset.nrAction, b.dataset.id);
    });
  } catch (e) { host.innerHTML = `<div class="empty">Failed: ${escape(e.message)}</div>`; }
}

async function handleNotifyRuleAction(action, id) {
  const rule = _notifyRules.find(r => r.id === id);
  if (!rule) return;
  try {
    if (action === 'toggle') {
      await api('PUT', `/api/rfs/admin/notification-rules/${id}`, { enabled: !rule.enabled });
      toast(rule.enabled ? 'Disabled' : 'Enabled');
    } else if (action === 'test') {
      const r = await api('POST', `/api/rfs/admin/notification-rules/${id}/test`);
      if (r.result?.error) toast('SMTP error: ' + r.result.error, 'error');
      else if (r.result?.skipped) toast('SMTP not configured on server', 'error');
      else toast('Test email sent');
    } else if (action === 'delete') {
      if (!confirm('Delete this rule?')) return;
      await api('DELETE', `/api/rfs/admin/notification-rules/${id}`);
      toast('Rule deleted');
    }
    await loadNotificationRules();
  } catch (e) { toast(e.message, 'error'); }
}

function tsToMs(t) {
  if (!t) return null;
  if (t._seconds) return t._seconds * 1000;
  if (typeof t === 'number') return t;
  const p = Date.parse(t);
  return isNaN(p) ? null : p;
}
function fmtTs(t) {
  const ms = tsToMs(t);
  if (!ms) return '—';
  return new Date(ms).toLocaleString();
}
function fmtDuration(ms) {
  if (ms == null || isNaN(ms) || ms < 0) return '—';
  const m = Math.floor(ms / 60000);
  if (m < 1) return '< 1m';
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  if (h < 24) return `${h}h ${mm}m`;
  const d = Math.floor(h / 24);
  const hh = h % 24;
  return `${d}d ${hh}h`;
}
function computeWait(o) {
  const start = tsToMs(o.firstStagedAt);
  if (!start) return null;
  const end = tsToMs(o.lastLoadedAt);
  if (end) return { ms: end - start, ongoing: false };
  return { ms: Date.now() - start, ongoing: true };
}

// ─── filter helpers (shared by Queue + Admin) ────────────────────────────────
function uniqSorted(arr) { return [...new Set(arr.filter(Boolean))].sort(); }

function applyFilters(orders, f) {
  return orders.filter(o => {
    if (f.code && !(o.logiwaCode || '').toLowerCase().includes(f.code.toLowerCase())) return false;
    if (f.state && o.rfsState !== f.state) return false;
    if (f.type && o.shipmentOrderTypeName !== f.type) return false;
    if (f.client && o.clientName !== f.client) return false;
    if (f.loadedFrom) {
      const ms = tsToMs(o.lastLoadedAt);
      if (!ms || ms < new Date(f.loadedFrom).getTime()) return false;
    }
    if (f.loadedTo) {
      const ms = tsToMs(o.lastLoadedAt);
      const end = new Date(f.loadedTo).getTime() + 24 * 60 * 60 * 1000; // include the whole day
      if (!ms || ms > end) return false;
    }
    if (f.minWaitHours) {
      const w = computeWait(o);
      const hrs = w ? w.ms / 3600000 : 0;
      if (hrs < parseFloat(f.minWaitHours)) return false;
    }
    return true;
  });
}

const ORDER_TYPES = ['D2B Order - SPD', 'D2B Order - LTL/FTL'];

function filterRowHTML(opts) {
  const { idPrefix, orders, includeStateOptions, includeLoadedDate, includeWaitThreshold } = opts;
  const clients = uniqSorted(orders.map(o => o.clientName));
  return `
    <div class="card" style="padding:10px 12px">
      <div class="filter-grid">
        <input type="text" id="${idPrefix}-code" placeholder="Order code…" style="padding:8px" />
        <select id="${idPrefix}-state" style="padding:8px">
          <option value="">All states</option>
          ${includeStateOptions.map(s => `<option value="${s}">${s.replace('_',' ')}</option>`).join('')}
        </select>
        <select id="${idPrefix}-type" style="padding:8px">
          <option value="">All types</option>
          ${ORDER_TYPES.map(t => `<option value="${escape(t)}">${escape(t.replace('D2B Order - ',''))}</option>`).join('')}
        </select>
        <select id="${idPrefix}-client" style="padding:8px">
          <option value="">All clients</option>
          ${clients.map(c => `<option value="${escape(c)}">${escape(c)}</option>`).join('')}
        </select>
        ${includeLoadedDate ? `
          <input type="date" id="${idPrefix}-loaded-from" title="Loaded from" style="padding:8px" />
          <input type="date" id="${idPrefix}-loaded-to" title="Loaded to" style="padding:8px" />
        ` : ''}
        ${includeWaitThreshold ? `
          <input type="number" id="${idPrefix}-wait" placeholder="Min wait hrs" min="0" step="0.5" style="padding:8px" />
        ` : ''}
        <button class="btn secondary" id="${idPrefix}-clear" style="padding:8px 12px;min-height:0">Clear</button>
      </div>
    </div>
  `;
}

function readFilterValues(idPrefix) {
  const v = (id) => document.getElementById(`${idPrefix}-${id}`)?.value?.trim() || '';
  return {
    code: v('code'),
    state: v('state'),
    type: v('type'),
    client: v('client'),
    loadedFrom: v('loaded-from'),
    loadedTo: v('loaded-to'),
    minWaitHours: v('wait'),
  };
}

function attachFilterHandlers(idPrefix, onChange) {
  const ids = ['code', 'state', 'type', 'client', 'loaded-from', 'loaded-to', 'wait'];
  for (const id of ids) {
    const inp = document.getElementById(`${idPrefix}-${id}`);
    if (!inp) continue;
    inp.addEventListener(inp.tagName === 'SELECT' || inp.type === 'date' ? 'change' : 'input', onChange);
  }
  document.getElementById(`${idPrefix}-clear`)?.addEventListener('click', () => {
    for (const id of ids) {
      const inp = document.getElementById(`${idPrefix}-${id}`);
      if (inp) inp.value = '';
    }
    onChange();
  });
}

let _adminOrders = [];

async function loadAdminHistory() {
  const host = $('#history-table');
  if (!host) return;
  host.innerHTML = '<div class="loader">Loading…</div>';
  try {
    const days = $('#hist-days').value;
    const { orders } = await api('GET', `/api/rfs/admin/orders?days=${days}`);
    _adminOrders = orders;
    const filterHost = $('#hist-filter-host');
    if (filterHost && !filterHost.dataset.wired) {
      filterHost.innerHTML = filterRowHTML({
        idPrefix: 'h',
        orders,
        includeStateOptions: ['awaiting_putaway', 'staged', 'loading', 'loaded', 'shipped'],
        includeLoadedDate: true,
        includeWaitThreshold: true,
      });
      attachFilterHandlers('h', renderAdminHistoryTable);
      filterHost.dataset.wired = '1';
    } else if (filterHost) {
      // refresh the client dropdown options without losing current filter values
      const sel = document.getElementById('h-client');
      if (sel) {
        const cur = sel.value;
        const clients = uniqSorted(orders.map(o => o.clientName));
        sel.innerHTML = '<option value="">All clients</option>' + clients.map(c => `<option value="${escape(c)}">${escape(c)}</option>`).join('');
        sel.value = cur;
      }
    }
    renderAdminHistoryTable();
  } catch (e) {
    host.innerHTML = `<div class="empty">Failed to load: ${escape(e.message)}</div>`;
  }
}

let _adminPOs = [];

async function loadAdminPOReceipts() {
  const host = $('#po-receipts');
  if (!host) return;
  host.innerHTML = '<div class="loader">Loading…</div>';
  try {
    const days = $('#po-days')?.value || '30';
    const { pos } = await api('GET', `/api/rfs/admin/pos?days=${days}`);
    _adminPOs = pos;
    const filterHost = $('#po-filter-host');
    if (filterHost && !filterHost.dataset.wired) {
      const clients = uniqSorted(pos.map(p => p.clientName));
      filterHost.innerHTML = `
        <div class="card" style="padding:10px 12px">
          <div class="filter-grid">
            <input type="text" id="p-code" placeholder="PO code…" style="padding:8px" />
            <select id="p-client" style="padding:8px">
              <option value="">All clients</option>
              ${clients.map(c => `<option value="${escape(c)}">${escape(c)}</option>`).join('')}
            </select>
            <select id="p-source" style="padding:8px">
              <option value="">All sources</option>
              <option value="logiwa">Logiwa PO</option>
              <option value="blind">No PO (blind)</option>
            </select>
            <select id="p-type" style="padding:8px">
              <option value="">All types</option>
              <option value="pallets">Pallets</option>
              <option value="boxes">Boxes</option>
              <option value="container">Container</option>
            </select>
            <input type="date" id="p-from" title="Arrived from" style="padding:8px" />
            <input type="date" id="p-to" title="Arrived to" style="padding:8px" />
            <button class="btn secondary" id="p-clear" style="padding:8px 12px;min-height:0">Clear</button>
          </div>
        </div>
      `;
      ['p-code','p-client','p-source','p-type','p-from','p-to'].forEach(id => {
        const inp = document.getElementById(id);
        if (inp) inp.addEventListener(inp.tagName === 'SELECT' || inp.type === 'date' ? 'change' : 'input', renderPOReceiptsTable);
      });
      $('#p-clear').onclick = () => {
        ['p-code','p-client','p-source','p-type','p-from','p-to'].forEach(id => { const e = document.getElementById(id); if (e) e.value = ''; });
        renderPOReceiptsTable();
      };
      filterHost.dataset.wired = '1';
    } else if (filterHost) {
      const sel = $('#p-client');
      if (sel) {
        const cur = sel.value;
        const clients = uniqSorted(pos.map(p => p.clientName));
        sel.innerHTML = '<option value="">All clients</option>' + clients.map(c => `<option value="${escape(c)}">${escape(c)}</option>`).join('');
        sel.value = cur;
      }
    }
    renderPOReceiptsTable();
  } catch (e) { host.innerHTML = `<div class="empty">Failed: ${escape(e.message)}</div>`; }
}

function applyPOFilters(rows) {
  const v = (id) => document.getElementById(id)?.value?.trim() || '';
  const code = v('p-code').toLowerCase();
  const client = v('p-client');
  const source = v('p-source');
  const type = v('p-type');
  const from = v('p-from');
  const to = v('p-to');
  return rows.filter(p => {
    if (code && !(p.logiwaCode || '').toLowerCase().includes(code) && !(p.isBlind && '(no po)'.includes(code))) return false;
    if (client && p.clientName !== client) return false;
    if (source === 'logiwa' && p.isBlind) return false;
    if (source === 'blind' && !p.isBlind) return false;
    if (type && p.receiptType !== type) return false;
    if (from || to) {
      const ms = tsToMs(p.arrivedAt);
      if (!ms) return false;
      if (from && ms < new Date(from).getTime()) return false;
      if (to && ms > new Date(to).getTime() + 24 * 60 * 60 * 1000) return false;
    }
    return true;
  });
}

let _filteredPOs = [];

function renderPOReceiptsTable() {
  const host = $('#po-receipts');
  if (!host) return;
  const pos = applyPOFilters(_adminPOs);
  _filteredPOs = pos;
  if (!pos.length) {
    host.innerHTML = _adminPOs.length
      ? '<div class="empty" style="padding:16px">No POs match the current filter.</div>'
      : '<div class="empty" style="padding:16px">No PO receipts in this window.</div>';
    return;
  }
  host.innerHTML = `
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="text-align:left;background:#f7f9fb">
              <th style="padding:8px">PO</th>
              <th style="padding:8px">Vendor</th>
              <th style="padding:8px">Client</th>
              <th style="padding:8px">Received as</th>
              <th style="padding:8px">Arrived</th>
              <th style="padding:8px">By</th>
              <th style="padding:8px">POD</th>
              <th style="padding:8px">Logiwa</th>
            </tr>
          </thead>
          <tbody>
            ${pos.map((p, idx) => `
              <tr style="border-top:1px solid #e8eaed;cursor:pointer" data-po-idx="${idx}">
                <td style="padding:8px;font-family:ui-monospace,monospace">${p.isBlind ? '<span class="hint">(no PO)</span>' : escape(p.logiwaCode)}</td>
                <td style="padding:8px">${escape(p.vendorDisplayName || '—')}</td>
                <td style="padding:8px">${escape(p.clientName || '—')}</td>
                <td style="padding:8px">${p.count || ''} ${escape(p.receiptType || '')}</td>
                <td style="padding:8px">${fmtTs(p.arrivedAt)}</td>
                <td style="padding:8px">${escape(p.arrivedBy || '')}</td>
                <td style="padding:8px">${p.podPhotoUrl ? `<a href="${escape(p.podPhotoUrl)}" target="_blank" onclick="event.stopPropagation()">view</a>` : '—'}</td>
                <td style="padding:8px">${p.isBlind ? '<span class="hint">no PO</span>' : (p.logiwaError ? '<span style="color:#c0392b">err</span>' : '<span style="color:#1f6b1f">ok</span>')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  // Row click → edit modal
  host.querySelectorAll('tr[data-po-idx]').forEach(tr => {
    tr.onclick = () => openPOEditModal(_filteredPOs[parseInt(tr.dataset.poIdx, 10)]);
  });
}

function openPOEditModal(po) {
  if (!po) return;
  // The server uses the Firestore doc id as :id for edit/link.
  // For Logiwa-linked POs the doc id equals the logiwa identifier; for blind receipts
  // it's an auto-generated id stored on the doc itself. The admin endpoint returns it as `id`.
  const docId = po.id || po.logiwaIdentifier;
  const existing = document.getElementById('po-edit-modal');
  if (existing) existing.remove();
  const modal = el(`
    <div id="po-edit-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:200;padding:16px">
      <div class="card" style="max-width:520px;width:100%;max-height:90vh;overflow-y:auto;margin:0">
        <div class="row" style="margin-bottom:8px">
          <h3 class="grow" style="margin:0">Edit receipt — ${escape(po.isBlind ? '(no PO)' : po.logiwaCode)}</h3>
          <button id="po-edit-close" style="background:none;border:none;font-size:24px;cursor:pointer;color:#888">×</button>
        </div>
        <div class="meta" style="margin-bottom:10px">
          Arrived ${fmtTs(po.arrivedAt)} by ${escape(po.arrivedBy || '—')}
          ${po.editedAt ? `<br>Last edited ${fmtTs(po.editedAt)} by ${escape(po.editedBy || '')}` : ''}
        </div>

        <label>Client</label>
        <input type="text" id="ed-client" value="${escape(po.clientName || '')}" />
        <label>Vendor / sender</label>
        <input type="text" id="ed-vendor" value="${escape(po.vendorDisplayName || '')}" />
        <label>Type received</label>
        <select id="ed-type">
          <option value="boxes"${po.receiptType === 'boxes' ? ' selected' : ''}>Boxes</option>
          <option value="pallets"${po.receiptType === 'pallets' ? ' selected' : ''}>Pallets</option>
          <option value="container"${po.receiptType === 'container' ? ' selected' : ''}>Container</option>
        </select>
        <label>Count</label>
        <input type="number" id="ed-count" min="1" step="1" value="${po.count || ''}" />
        <label>Notes</label>
        <input type="text" id="ed-note" value="${escape(po.receiveNote || '')}" />

        <button class="btn full" id="po-edit-save" style="margin-top:10px">Save changes</button>

        ${po.isBlind ? `
          <hr style="margin:18px 0;border:none;border-top:1px solid #e8eaed">
          <h3 style="font-size:15px;margin-bottom:4px">Link to a Logiwa PO</h3>
          <div class="meta" style="margin-bottom:8px">If the PO has now been created in Logiwa, paste its code here. The POD will be attached to it and the arrival date set in Logiwa.</div>
          <label>Logiwa PO code</label>
          <input type="text" id="ed-link-code" placeholder="e.g. TO4175" />
          <button class="btn full" id="po-edit-link" style="margin-top:10px;background:#1f6b1f">Link to Logiwa PO</button>
        ` : `
          <hr style="margin:18px 0;border:none;border-top:1px solid #e8eaed">
          <div class="meta">Linked to Logiwa PO <strong>${escape(po.logiwaCode)}</strong>${po.linkedAt ? ` on ${fmtTs(po.linkedAt)}` : ''}</div>
          ${po.logiwaError ? `<div style="color:#c0392b;margin-top:6px;font-size:13px">Last Logiwa sync error: ${escape(po.logiwaError)}</div>` : ''}
        `}
      </div>
    </div>
  `);
  document.body.appendChild(modal);

  const close = () => modal.remove();
  $('#po-edit-close').onclick = close;
  modal.onclick = (e) => { if (e.target === modal) close(); };

  $('#po-edit-save').onclick = async () => {
    try {
      $('#po-edit-save').disabled = true;
      await api('PUT', `/api/rfs/pos/${docId}/edit`, {
        clientName: $('#ed-client').value.trim(),
        vendorName: $('#ed-vendor').value.trim(),
        receiptType: $('#ed-type').value,
        count: $('#ed-count').value,
        note: $('#ed-note').value.trim(),
      });
      toast('Receipt updated');
      close();
      await loadAdminPOReceipts();
    } catch (e) { toast(e.message, 'error'); $('#po-edit-save').disabled = false; }
  };

  if (po.isBlind) {
    $('#po-edit-link').onclick = async () => {
      const code = $('#ed-link-code').value.trim();
      if (!code) { toast('PO code required', 'error'); return; }
      try {
        $('#po-edit-link').disabled = true;
        $('#po-edit-link').textContent = 'Linking + uploading POD…';
        const r = await api('POST', `/api/rfs/pos/${docId}/link-logiwa`, { logiwaCode: code });
        if (r.logiwaError) toast('Linked, but Logiwa: ' + r.logiwaError, 'error');
        else toast(`Linked to Logiwa PO ${r.logiwaCode}`);
        close();
        await loadAdminPOReceipts();
      } catch (e) {
        toast(e.message, 'error');
        $('#po-edit-link').disabled = false;
        $('#po-edit-link').textContent = 'Link to Logiwa PO';
      }
    };
  }
}

async function loadEventsLog() {
  const host = $('#events-list');
  if (!host) return;
  host.innerHTML = '<div class="loader">Loading…</div>';
  try {
    const days = $('#ev-days').value;
    const type = $('#ev-type').value;
    const url = `/api/rfs/admin/events?days=${days}${type ? '&type=' + encodeURIComponent(type) : ''}`;
    const { events } = await api('GET', url);
    if (!events.length) { host.innerHTML = '<div class="empty" style="padding:16px">No events in this window.</div>'; return; }
    host.innerHTML = `
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="text-align:left;background:#f7f9fb">
              <th style="padding:8px">When</th>
              <th style="padding:8px">Type</th>
              <th style="padding:8px">Who</th>
              <th style="padding:8px">Summary</th>
            </tr>
          </thead>
          <tbody>
            ${events.map(e => `
              <tr style="border-top:1px solid #e8eaed">
                <td style="padding:8px;white-space:nowrap">${fmtTs(e.at)}</td>
                <td style="padding:8px"><span class="badge" style="background:#eef;color:#0d3b66">${escape(e.type)}</span></td>
                <td style="padding:8px">${escape(e.actor?.email || '—')}</td>
                <td style="padding:8px">${escape(e.summary || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    host.innerHTML = `<div class="empty">Failed: ${escape(err.message)}</div>`;
  }
}

function exportPOReceiptsCSV() {
  if (!_adminPOs.length) { toast('No PO data to export', 'error'); return; }
  const rows = applyPOFilters(_adminPOs);
  if (!rows.length) { toast('No POs match the current filter', 'error'); return; }
  const header = ['PO code', 'Source', 'Vendor', 'Client', 'Receipt type', 'Count', 'Arrived at', 'Arrived by', 'Note', 'Logiwa status', 'POD URL'];
  const lines = [header];
  for (const p of rows) {
    lines.push([
      p.isBlind ? '(no PO)' : (p.logiwaCode || ''),
      p.isBlind ? 'blind' : 'logiwa',
      p.vendorDisplayName || '',
      p.clientName || '',
      p.receiptType || '',
      p.count ?? '',
      fmtTs(p.arrivedAt),
      p.arrivedBy || '',
      p.receiveNote || '',
      p.isBlind ? 'no PO' : (p.logiwaError ? `err: ${p.logiwaError}` : 'ok'),
      p.podPhotoUrl || '',
    ]);
  }
  const csv = lines.map(r => r.map(v => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `rfs-po-receipts-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
}

function renderAdminHistoryTable() {
  const host = $('#history-table');
  if (!host) return;
  const f = readFilterValues('h');
  const orders = applyFilters(_adminOrders, f);
  if (!orders.length) {
    host.innerHTML = _adminOrders.length
      ? '<div class="empty">No orders match the current filter.</div>'
      : '<div class="empty">No orders in this window.</div>';
    return;
  }
  host.innerHTML = `
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="text-align:left;background:#f7f9fb">
              <th style="padding:8px">Order</th>
              <th style="padding:8px">Type</th>
              <th style="padding:8px">Client</th>
              <th style="padding:8px">State</th>
              <th style="padding:8px">Wait</th>
              <th style="padding:8px">Pallets</th>
              <th style="padding:8px">Total wt</th>
              <th style="padding:8px">Putaway</th>
              <th style="padding:8px">Picked up</th>
              <th style="padding:8px">BOL uploaded</th>
            </tr>
          </thead>
          <tbody>
            ${orders.map(o => {
              const pallets = o.pallets || [];
              const totalWt = pallets.reduce((s, p) => s + (Number(p.weight) || 0), 0);
              const wUnit = pallets.find(p => p.weightUnit)?.weightUnit || 'lb';
              const palletDetail = pallets.length
                ? pallets.map(p => {
                    const d = (p.length || p.width || p.height) ? `${p.length || '—'}×${p.width || '—'}×${p.height || '—'} ${escape(p.dimensionUnit || 'in')}` : '';
                    const w = p.weight ? `${p.weight} ${escape(p.weightUnit || 'lb')}` : '';
                    return `P${p.palletNo}${p.locationCode ? ' @ ' + escape(p.locationCode) : ''}${d ? ' · ' + d : ''}${w ? ' · ' + w : ''}`;
                  }).join('  |  ')
                : '';
              const wait = computeWait(o);
              const waitCell = wait
                ? (wait.ongoing
                    ? `<span style="color:#c0392b;font-weight:600">${fmtDuration(wait.ms)}</span><br><span class="hint">sitting</span>`
                    : `${fmtDuration(wait.ms)}`)
                : '—';
              return `
                <tr style="border-top:1px solid #e8eaed;cursor:pointer" data-id="${escape(o.logiwaIdentifier)}">
                  <td style="padding:8px;font-family:ui-monospace,monospace">${escape(o.logiwaCode)}</td>
                  <td style="padding:8px">${escape((o.shipmentOrderTypeName || '').replace('D2B Order - ', ''))}</td>
                  <td style="padding:8px">${escape(o.clientName || '—')}</td>
                  <td style="padding:8px"><span class="badge ${o.rfsState}">${o.rfsState.replace('_',' ')}</span></td>
                  <td style="padding:8px">${waitCell}</td>
                  <td style="padding:8px">${o.palletsLoaded}/${o.palletCount}</td>
                  <td style="padding:8px">${totalWt ? totalWt + ' ' + escape(wUnit) : '—'}</td>
                  <td style="padding:8px">${fmtTs(o.firstStagedAt)}<br><span class="hint">${escape(o.stagedBy || '')}</span></td>
                  <td style="padding:8px">${fmtTs(o.lastLoadedAt)}<br><span class="hint">${escape(o.loadedBy || '')}</span></td>
                  <td style="padding:8px">${fmtTs(o.bolUploadedAt)}<br><span class="hint">${escape(o.bolUploadedBy || '')}</span></td>
                </tr>
                ${palletDetail ? `<tr style="border-top:1px dashed #e8eaed" data-id="${escape(o.logiwaIdentifier)}" style="cursor:pointer"><td colspan="10" style="padding:4px 8px 10px;font-size:12px;color:#666">${palletDetail}</td></tr>` : ''}
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
    host.querySelectorAll('tr[data-id]').forEach(tr => {
      tr.onclick = () => { state.selectedOrderId = tr.dataset.id; render(); };
    });
}

function exportHistoryCSV() {
  if (!_adminOrders.length) { toast('No data to export', 'error'); return; }
  // One row per pallet, so CSM can pivot on dims/weight
  const rows = [['Order', 'Type', 'Client', 'Customer', 'State', 'Pallet#', 'Location', 'L', 'W', 'H', 'Dim unit', 'Weight', 'Weight unit', 'Pallet state', 'Staged at', 'Staged by', 'Loaded at', 'Loaded by', 'Wait', 'Wait minutes', 'BOL uploaded', 'BOL by', 'Shipped at']];
  for (const o of _adminOrders) {
    const wait = computeWait(o);
    const waitText = wait ? `${fmtDuration(wait.ms)}${wait.ongoing ? ' (sitting)' : ''}` : '';
    const waitMinutes = wait ? Math.round(wait.ms / 60000) : '';
    const pallets = o.pallets || [];
    if (!pallets.length) {
      rows.push([o.logiwaCode, o.shipmentOrderTypeName, o.clientName, o.customerName, o.rfsState, '', '', '', '', '', '', '', '', '', '', '', '', '', waitText, waitMinutes, fmtTs(o.bolUploadedAt), o.bolUploadedBy || '', fmtTs(o.shippedAt)]);
      continue;
    }
    for (const p of pallets) {
      rows.push([
        o.logiwaCode, o.shipmentOrderTypeName, o.clientName, o.customerName, o.rfsState,
        p.palletNo, p.locationCode || '',
        p.length ?? '', p.width ?? '', p.height ?? '', p.dimensionUnit || '',
        p.weight ?? '', p.weightUnit || '',
        p.state || '',
        fmtTs(p.stagedAt), p.stagedBy || '',
        fmtTs(p.loadedAt), p.loadedBy || '',
        waitText, waitMinutes,
        fmtTs(o.bolUploadedAt), o.bolUploadedBy || '',
        fmtTs(o.shippedAt),
      ]);
    }
  }
  const csv = rows.map(r => r.map(v => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `rfs-history-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
}

// ─── Receive PO ──────────────────────────────────────────────────────────────
let _selectedPO = null;

function renderReceive() {
  const v = $('#view');
  v.innerHTML = `
    <div class="card">
      <h3>Scan PO code</h3>
      <div class="meta" style="margin-bottom:8px">Scan or type the PO code to start receiving.</div>
      <div class="scanner-wrap"><div id="qr-reader"></div></div>
      <div class="row" style="margin-top:10px">
        <input type="text" id="po-manual" placeholder="…or type the PO code" class="grow" />
        <button class="btn" id="btn-po-open">Open</button>
      </div>
    </div>
    <div class="card">
      <div class="row">
        <h3 class="grow" style="margin:0">Pending POs · eShipper+</h3>
        <button class="btn secondary" id="btn-pending-refresh" style="padding:6px 10px;min-height:0;font-size:12px">Refresh</button>
      </div>
      <div class="row" style="margin-top:8px">
        <select id="pending-client" style="padding:8px;flex:1 1 auto">
          <option value="">All clients</option>
        </select>
      </div>
      <div id="pending-list" style="margin-top:10px"><div class="loader">Loading…</div></div>
    </div>
    <div class="card">
      <h3>No PO yet?</h3>
      <div class="meta" style="margin-bottom:8px">Use this if a shipment arrived before a PO was created in Logiwa. The arrival is recorded in this app only.</div>
      <button class="btn secondary full" id="btn-blind">Record arrival without PO</button>
    </div>
  `;
  openScanner((code) => lookupPOByCode(code));
  $('#btn-po-open').onclick = () => {
    const c = $('#po-manual').value.trim();
    if (c) lookupPOByCode(c);
  };
  $('#po-manual').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#btn-po-open').click(); });
  $('#btn-blind').onclick = () => { stopScanner(); renderBlindReceipt(); };
  $('#btn-pending-refresh').onclick = () => loadPendingPOs();
  $('#pending-client').onchange = () => renderPendingList();
  loadPendingPOs();
}

let _pendingPOs = [];

async function loadPendingPOs() {
  const host = $('#pending-list');
  if (host) host.innerHTML = '<div class="loader">Loading…</div>';
  try {
    const { pos, clients } = await api('GET', '/api/rfs/pos/pending');
    _pendingPOs = pos;
    const sel = $('#pending-client');
    if (sel) {
      const cur = sel.value;
      sel.innerHTML = '<option value="">All clients</option>' + (clients || []).map(c => `<option value="${escape(c)}">${escape(c)}</option>`).join('');
      sel.value = cur;
    }
    renderPendingList();
  } catch (e) {
    if (host) host.innerHTML = `<div class="empty">Failed: ${escape(e.message)}</div>`;
  }
}

function renderPendingList() {
  const host = $('#pending-list');
  if (!host) return;
  const clientFilter = $('#pending-client')?.value || '';
  const list = clientFilter ? _pendingPOs.filter(p => p.clientName === clientFilter) : _pendingPOs;
  if (!list.length) {
    host.innerHTML = `<div class="empty" style="padding:16px">${_pendingPOs.length ? 'No pending POs for this client.' : 'No pending POs.'}</div>`;
    return;
  }
  host.innerHTML = list.map(p => `
    <div class="card" style="padding:10px 12px;margin-bottom:6px;cursor:pointer" data-code="${escape(p.code)}">
      <div class="row">
        <div class="grow">
          <div style="font-family:ui-monospace,monospace;font-weight:600">${escape(p.code)}</div>
          <div class="hint" style="margin-top:2px">${escape(p.clientName || '—')} · ${escape(p.vendorDisplayName || '—')}${p.purchaseOrderTypeName ? ' · ' + escape(p.purchaseOrderTypeName) : ''}</div>
          <div class="hint">Planned arrival: ${fmtDate(p.plannedArrivalDate)} · Qty: ${p.totalQuantity || 0}</div>
        </div>
        <div style="font-size:12px;color:#0d3b66">Open →</div>
      </div>
    </div>
  `).join('');
  host.querySelectorAll('[data-code]').forEach(el => {
    el.onclick = () => lookupPOByCode(el.dataset.code);
  });
}

async function lookupPOByCode(code) {
  const trimmed = String(code).trim();
  try {
    const { po } = await api('GET', `/api/rfs/pos/by-code/${encodeURIComponent(trimmed)}`);
    stopScanner();
    _selectedPO = po;
    state.selectedPOId = po.logiwaIdentifier;
    render();
  } catch (e) { toast(e.message, 'error'); }
}

function renderPOArrival() {
  const v = $('#view');
  const po = _selectedPO;
  if (!po) { state.selectedPOId = null; render(); return; }
  const isArrived = po.state === 'arrived';
  v.innerHTML = `
    <button class="btn secondary" id="btn-back-po">← Back</button>
    <div class="card" style="margin-top:12px">
      <div class="row"><h3 class="grow">${escape(po.logiwaCode)}</h3>${isArrived ? '<span class="badge loaded">arrived</span>' : '<span class="badge awaiting">pending</span>'}</div>
      <div class="meta">
        ${escape(po.purchaseOrderTypeName || '')}<br>
        Vendor: <strong>${escape(po.vendorDisplayName || '—')}</strong><br>
        Client: ${escape(po.clientName || '—')}<br>
        Status: ${escape(po.logiwaStatusName || '—')}<br>
        Planned arrival: ${fmtDate(po.plannedArrivalDate)}<br>
        Total qty (Logiwa): ${po.totalQuantity || 0}
        ${po.actualArrivalDate ? `<br>Actual arrival (Logiwa): ${fmtTs(po.actualArrivalDate)}` : ''}
      </div>
    </div>
    <div id="po-action-area"></div>
  `;
  $('#btn-back-po').onclick = () => {
    state.selectedPOId = null;
    _selectedPO = null;
    stopBolStream();
    render();
  };
  const area = $('#po-action-area');
  if (isArrived) {
    area.innerHTML = `
      <div class="card">
        <h3>Already received</h3>
        <div class="meta">
          Received as <strong>${po.count} ${escape(po.receiptType)}</strong> on ${fmtTs(po.arrivedAt)} by ${escape(po.arrivedBy || '')}.
          ${po.receiveNote ? '<br>Note: ' + escape(po.receiveNote) : ''}
          ${po.logiwaError ? '<br><span style="color:#c0392b">Logiwa sync issue: ' + escape(po.logiwaError) + '</span>' : ''}
        </div>
        ${po.podPhotoUrl ? `<a href="${escape(po.podPhotoUrl)}" target="_blank" class="btn full" style="margin-top:10px">View POD photo</a>` : ''}
      </div>
    `;
  } else {
    renderPOReceiveForm(area, po);
  }
}

function renderPOReceiveForm(area, po) {
  area.innerHTML = `
    <div class="card">
      <h3>Receipt details</h3>
      <label>Type received</label>
      <select id="po-type">
        <option value="">— pick one —</option>
        <option value="boxes">Boxes</option>
        <option value="pallets">Pallets</option>
        <option value="container">Container</option>
      </select>
      <label>Count</label>
      <input type="number" id="po-count" min="1" step="1" inputmode="numeric" placeholder="e.g. 2" />
      <label>Notes (optional)</label>
      <input type="text" id="po-note" placeholder="Damage, missing items, etc." />
    </div>
    <div class="card">
      <h3>POD photo</h3>
      <div class="meta" style="margin-bottom:8px">Snap a photo of the signed POD. It uploads to Logiwa under Other Documents and stamps the arrival date.</div>
      <div id="pod-cam-area">
        <video id="pod-video" style="width:100%;max-height:75vh;border-radius:8px;background:#000;object-fit:contain;display:block" playsinline autoplay muted></video>
        <div id="pod-cam-status" class="hint" style="text-align:center;margin:6px 0">Starting camera…</div>
        <button class="btn full" id="btn-pod-snap" style="margin-top:6px">Capture photo</button>
        <div style="text-align:center;margin:10px 0;color:#888;font-size:13px">— or —</div>
        <label class="btn secondary full" for="pod-file" style="cursor:pointer">Choose file from device</label>
        <input type="file" id="pod-file" accept="image/*" capture="environment" style="display:none" />
      </div>
      <canvas id="pod-canvas" style="display:none"></canvas>
      <div id="pod-preview-area" style="display:none">
        <img id="pod-preview" style="max-width:100%;border-radius:8px;margin-top:10px" />
        <button class="btn secondary full" id="btn-pod-retake" style="margin-top:8px">Retake</button>
      </div>
      <button class="btn full" id="btn-pod-submit" style="margin-top:10px" disabled>Submit receipt</button>
    </div>
  `;

  let blob = null;
  const video = $('#pod-video'), canvas = $('#pod-canvas'), preview = $('#pod-preview');
  const status = $('#pod-cam-status'), camArea = $('#pod-cam-area'), previewArea = $('#pod-preview-area');
  const fileInp = $('#pod-file'), btnSnap = $('#btn-pod-snap'), btnRetake = $('#btn-pod-retake'), btnSubmit = $('#btn-pod-submit');

  async function startCam() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1920 },
          height: { ideal: 1080 },
        },
        audio: false,
      });
      state.bolStream = stream;
      video.srcObject = stream;
      status.textContent = 'Frame the POD and tap Capture.';
    } catch (err) {
      video.style.display = 'none';
      btnSnap.style.display = 'none';
      status.textContent = 'Camera unavailable — use "Choose file from device".';
    }
  }
  startCam();

  function showPreview(b) {
    blob = b;
    preview.src = URL.createObjectURL(b);
    camArea.style.display = 'none';
    previewArea.style.display = '';
    btnSubmit.disabled = false;
    stopBolStream();
  }
  btnSnap.onclick = () => {
    if (!video.videoWidth) { toast('Camera not ready', 'error'); return; }
    canvas.width = video.videoWidth; canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob((b) => { if (b) showPreview(b); }, 'image/jpeg', 0.9);
  };
  btnRetake.onclick = () => {
    blob = null; preview.src = ''; previewArea.style.display = 'none';
    camArea.style.display = ''; btnSubmit.disabled = true; fileInp.value = '';
    startCam();
  };
  fileInp.onchange = () => { const f = fileInp.files?.[0]; if (f) showPreview(f); };

  btnSubmit.onclick = async () => {
    const receiptType = $('#po-type').value;
    const count = $('#po-count').value;
    const note = $('#po-note').value.trim();
    if (!receiptType) { toast('Pick a type', 'error'); return; }
    if (!count || parseFloat(count) <= 0) { toast('Enter a count', 'error'); return; }
    if (!blob) { toast('POD photo required', 'error'); return; }
    const fd = new FormData();
    fd.append('pod', blob, blob.name || `pod-${Date.now()}.jpg`);
    fd.append('receiptType', receiptType);
    fd.append('count', count);
    if (note) fd.append('note', note);
    try {
      btnSubmit.disabled = true;
      btnSubmit.textContent = 'Submitting…';
      const r = await api('POST', `/api/rfs/pos/${state.selectedPOId}/arrive`, fd, true);
      if (r.logiwaError) toast('Saved locally, but Logiwa: ' + r.logiwaError, 'error');
      else toast('PO received — POD pushed to Logiwa');
      _selectedPO = null;
      state.selectedPOId = null;
      render();
    } catch (e) {
      toast(e.message, 'error');
      btnSubmit.disabled = false;
      btnSubmit.textContent = 'Submit receipt';
    }
  };
}

// ─── Blind receipt (no Logiwa PO) ────────────────────────────────────────────
async function renderBlindReceipt() {
  const v = $('#view');
  v.innerHTML = `
    <button class="btn secondary" id="btn-back-blind">← Back</button>
    <div class="card" style="margin-top:12px">
      <h3>Record arrival without PO</h3>
      <div class="meta" style="margin-bottom:8px">No Logiwa interaction — this is recorded only in the app's history. Use if the shipment arrived before a PO was created.</div>
    </div>
    <div class="card">
      <h3>Receipt details</h3>
      <label>Type received</label>
      <select id="b-type">
        <option value="">— pick one —</option>
        <option value="boxes">Boxes</option>
        <option value="pallets">Pallets</option>
        <option value="container">Container</option>
      </select>
      <label>Count</label>
      <input type="number" id="b-count" min="1" step="1" inputmode="numeric" placeholder="e.g. 2" />
      <label>Client (optional)</label>
      <input type="text" id="b-client" list="b-client-list" placeholder="Type or pick — leave blank if unknown" />
      <datalist id="b-client-list"></datalist>
      <label>Vendor / sender (optional)</label>
      <input type="text" id="b-vendor" placeholder="Carrier, vendor, or sender name" />
      <label>Notes (optional)</label>
      <input type="text" id="b-note" placeholder="Damage, missing items, etc." />
    </div>
    <div class="card">
      <h3>POD photo</h3>
      <div id="b-cam-area">
        <video id="b-video" style="width:100%;max-height:75vh;border-radius:8px;background:#000;object-fit:contain;display:block" playsinline autoplay muted></video>
        <div id="b-cam-status" class="hint" style="text-align:center;margin:6px 0">Starting camera…</div>
        <button class="btn full" id="btn-b-snap" style="margin-top:6px">Capture photo</button>
        <div style="text-align:center;margin:10px 0;color:#888;font-size:13px">— or —</div>
        <label class="btn secondary full" for="b-file" style="cursor:pointer">Choose file from device</label>
        <input type="file" id="b-file" accept="image/*" capture="environment" style="display:none" />
      </div>
      <canvas id="b-canvas" style="display:none"></canvas>
      <div id="b-preview-area" style="display:none">
        <img id="b-preview" style="max-width:100%;border-radius:8px;margin-top:10px" />
        <button class="btn secondary full" id="btn-b-retake" style="margin-top:8px">Retake</button>
      </div>
      <button class="btn full" id="btn-b-submit" style="margin-top:10px" disabled>Submit receipt</button>
    </div>
  `;

  $('#btn-back-blind').onclick = () => { stopBolStream(); render(); };

  // Populate client autocomplete from the server (best-effort)
  api('GET', '/api/rfs/clients').then(({ clients }) => {
    const dl = $('#b-client-list');
    if (dl && Array.isArray(clients)) {
      dl.innerHTML = clients.map(c => `<option value="${escape(c)}"></option>`).join('');
    }
  }).catch(() => {});

  let blob = null;
  const video = $('#b-video'), canvas = $('#b-canvas'), preview = $('#b-preview');
  const status = $('#b-cam-status'), camArea = $('#b-cam-area'), previewArea = $('#b-preview-area');
  const fileInp = $('#b-file'), btnSnap = $('#btn-b-snap'), btnRetake = $('#btn-b-retake'), btnSubmit = $('#btn-b-submit');

  async function startCam() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1920 },
          height: { ideal: 1080 },
        },
        audio: false,
      });
      state.bolStream = stream;
      video.srcObject = stream;
      status.textContent = 'Frame the POD and tap Capture.';
    } catch (err) {
      video.style.display = 'none';
      btnSnap.style.display = 'none';
      status.textContent = 'Camera unavailable — use "Choose file from device".';
    }
  }
  startCam();

  function showPreview(b) {
    blob = b;
    preview.src = URL.createObjectURL(b);
    camArea.style.display = 'none';
    previewArea.style.display = '';
    btnSubmit.disabled = false;
    stopBolStream();
  }
  btnSnap.onclick = () => {
    if (!video.videoWidth) { toast('Camera not ready', 'error'); return; }
    canvas.width = video.videoWidth; canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob((b) => { if (b) showPreview(b); }, 'image/jpeg', 0.9);
  };
  btnRetake.onclick = () => {
    blob = null; preview.src = ''; previewArea.style.display = 'none';
    camArea.style.display = ''; btnSubmit.disabled = true; fileInp.value = '';
    startCam();
  };
  fileInp.onchange = () => { const f = fileInp.files?.[0]; if (f) showPreview(f); };

  btnSubmit.onclick = async () => {
    const receiptType = $('#b-type').value;
    const count = $('#b-count').value;
    const clientName = $('#b-client').value.trim();
    const vendorName = $('#b-vendor').value.trim();
    const note = $('#b-note').value.trim();
    if (!receiptType) { toast('Pick a type', 'error'); return; }
    if (!count || parseFloat(count) <= 0) { toast('Enter a count', 'error'); return; }
    if (!blob) { toast('POD photo required', 'error'); return; }
    const fd = new FormData();
    fd.append('pod', blob, blob.name || `pod-${Date.now()}.jpg`);
    fd.append('receiptType', receiptType);
    fd.append('count', count);
    if (clientName) fd.append('clientName', clientName);
    if (vendorName) fd.append('vendorName', vendorName);
    if (note) fd.append('note', note);
    try {
      btnSubmit.disabled = true;
      btnSubmit.textContent = 'Submitting…';
      await api('POST', '/api/rfs/blind-receipt', fd, true);
      toast('Arrival recorded');
      stopBolStream();
      state.view = 'receive';
      render();
    } catch (e) {
      toast(e.message, 'error');
      btnSubmit.disabled = false;
      btnSubmit.textContent = 'Submit receipt';
    }
  };
}
