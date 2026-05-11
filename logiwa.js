'use strict';

const fetch = require('node-fetch');
const FormData = require('form-data');

const BASE = 'https://myapi.logiwa.com';
const STATUS_READY_TO_SHIP = 16;
// Logiwa DocumentType enum: 1=CarrierLabel, 2=GiftNote, 3=PackingInstruction,
// 4=PackingDocument, 5=BillOfLading, 6=External, 7=Invoice, 8=KitInstructions, 9=Retailer
const DOCUMENT_TYPE_CARRIER_LABEL = 1;
const DOCUMENT_TYPE_BOL = 5;
const ORDER_TYPES = ['D2B Order - SPD', 'D2B Order - LTL/FTL'];

let _token = null;
let _tokenAt = 0;
const TOKEN_TTL_MS = 25 * 60 * 1000;

function creds() {
  const email = process.env.LOGIWA_EMAIL;
  const password = process.env.LOGIWA_PASSWORD;
  if (!email || !password) throw new Error('LOGIWA_EMAIL and LOGIWA_PASSWORD must be set');
  return { email, password };
}

async function getToken(force = false) {
  if (!force && _token && (Date.now() - _tokenAt) < TOKEN_TTL_MS) return _token;
  const { email, password } = creds();
  const r = await fetch(`${BASE}/v3.1/Authorize/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!r.ok) throw new Error(`Logiwa auth failed: ${r.status} ${await r.text()}`);
  const j = await r.json();
  if (!j.token) throw new Error('Logiwa auth: no token in response');
  _token = j.token;
  _tokenAt = Date.now();
  return _token;
}

async function authedFetch(method, path, { query, body, formData, headers = {} } = {}) {
  const url = new URL(BASE + path);
  if (query) for (const [k, v] of Object.entries(query)) url.searchParams.append(k, v);

  const send = async (token) => {
    const opts = { method, headers: { Authorization: `Bearer ${token}`, ...headers } };
    if (body) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    } else if (formData) {
      Object.assign(opts.headers, formData.getHeaders());
      opts.body = formData;
    }
    return fetch(url.toString(), opts);
  };

  let token = await getToken();
  let res = await send(token);
  if (res.status === 401) {
    token = await getToken(true);
    res = await send(token);
  }
  return res;
}

// LQL syntax: {fieldName}.{operator}={value}
async function listShipmentOrdersByStatusAndType({ status = STATUS_READY_TO_SHIP, type, warehouseIdentifier, page = 0, size = 200 }) {
  const query = { 'Status.eq': String(status) };
  if (type) query['ShipmentOrderTypeName.eq'] = type;
  if (warehouseIdentifier) query['WarehouseIdentifier.eq'] = warehouseIdentifier;

  const path = `/v3.1/ShipmentOrder/list/i/${page}/s/${size}`;
  const res = await authedFetch('GET', path, { query });
  if (!res.ok) throw new Error(`listShipmentOrders failed: ${res.status} ${await res.text()}`);
  return res.json();
}

async function listAllReadyToShipOrders({ warehouseIdentifier } = {}) {
  const all = [];
  for (const type of ORDER_TYPES) {
    let page = 0;
    const size = 200;
    while (true) {
      const r = await listShipmentOrdersByStatusAndType({ type, warehouseIdentifier, page, size });
      const data = r.data || [];
      all.push(...data);
      const total = r.totalCount || 0;
      if ((page + 1) * size >= total || data.length === 0) break;
      page += 1;
    }
  }
  return all;
}

async function uploadShipmentDocument({ shipmentOrderIdentifier, shipmentOrderCode, fileName, buffer, mimeType = 'image/jpeg', trackingNumber, documentType = DOCUMENT_TYPE_CARRIER_LABEL }) {
  if (!shipmentOrderIdentifier && !shipmentOrderCode) {
    throw new Error('uploadShipmentDocument requires shipmentOrderIdentifier or shipmentOrderCode');
  }
  const fd = new FormData();
  if (shipmentOrderIdentifier) fd.append('ShipmentOrderIdentifier', shipmentOrderIdentifier);
  if (shipmentOrderCode) fd.append('ShipmentOrderCode', shipmentOrderCode);
  fd.append('DocumentType', String(documentType));
  fd.append('FileName', fileName);
  if (trackingNumber) fd.append('TrackingNumber', String(trackingNumber));
  fd.append('DocumentBase', buffer, { filename: fileName, contentType: mimeType });

  const res = await authedFetch('POST', '/v3.1/ShipmentOrder/document', { formData: fd });
  const text = await res.text();
  if (!res.ok) throw new Error(`uploadShipmentDocument failed: ${res.status} ${text}`);
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

// ─── Purchase Orders ─────────────────────────────────────────────────────────
const DOCUMENT_TYPE_EXTERNAL = 6; // "Other Documents" slot in Logiwa UI

async function findPurchaseOrderByCode(code, { warehouseIdentifier } = {}) {
  const query = { 'Code.eq': String(code) };
  if (warehouseIdentifier) query['WarehouseIdentifier.eq'] = warehouseIdentifier;
  const res = await authedFetch('GET', '/v3.1/PurchaseOrder/list/i/0/s/10', { query });
  const text = await res.text();
  if (!res.ok) throw new Error(`PO lookup failed: ${res.status} ${text}`);
  const j = JSON.parse(text);
  const data = j.data || [];
  return data[0] || null;
}

// Logiwa Pending PO status id = 1 (verified via /v3.1/Helper/purchaseorderstatustypes)
const PO_STATUS_PENDING = 1;

async function listPendingPurchaseOrders({ warehouseIdentifier, statusIds = [PO_STATUS_PENDING] } = {}) {
  const all = [];
  const size = 200;
  let page = 0;
  // The list endpoint supports `Status.in=1,2,3` for multi-status filtering
  const statusParam = statusIds.join(',');
  while (true) {
    const query = { 'Status.in': statusParam };
    if (warehouseIdentifier) query['WarehouseIdentifier.eq'] = warehouseIdentifier;
    const res = await authedFetch('GET', `/v3.1/PurchaseOrder/list/i/${page}/s/${size}`, { query });
    const text = await res.text();
    if (!res.ok) throw new Error(`listPendingPurchaseOrders failed: ${res.status} ${text}`);
    const j = JSON.parse(text);
    const data = j.data || [];
    all.push(...data);
    const total = j.totalCount || 0;
    if ((page + 1) * size >= total || data.length === 0) break;
    page += 1;
  }
  return all;
}

async function getPurchaseOrderDetail(identifier) {
  // NOTE: Logiwa's /detail endpoint only returns line items + totals (discount, subTotal,
  // total, currencyCode, purchaseOrderStatus, purchaseOrderLineList). Use findPurchaseOrderByCode
  // for the full PO metadata (code, vendor, type, etc.).
  const res = await authedFetch('GET', `/v3.1/PurchaseOrder/detail/${identifier}`);
  const text = await res.text();
  if (!res.ok) throw new Error(`PO detail failed: ${res.status} ${text}`);
  return JSON.parse(text);
}

let _currencyMap = null;
async function getCurrencyIdMap() {
  if (_currencyMap) return _currencyMap;
  const res = await authedFetch('GET', '/v3.1/Helper/currencytypes');
  const text = await res.text();
  if (!res.ok) throw new Error(`getCurrencyIdMap failed: ${res.status} ${text}`);
  const arr = JSON.parse(text);
  const map = {};
  for (const c of arr) map[c.code] = parseInt(c.id, 10);
  _currencyMap = map;
  return map;
}

async function uploadPurchaseOrderDocument({ purchaseOrderIdentifier, purchaseOrderCode, fileName, buffer, mimeType = 'application/pdf', documentType = DOCUMENT_TYPE_EXTERNAL }) {
  if (!purchaseOrderIdentifier && !purchaseOrderCode) {
    throw new Error('uploadPurchaseOrderDocument requires purchaseOrderIdentifier or purchaseOrderCode');
  }
  const fd = new FormData();
  if (purchaseOrderIdentifier) fd.append('PurchaseOrderIdentifier', purchaseOrderIdentifier);
  if (purchaseOrderCode) fd.append('PurchaseOrderCode', purchaseOrderCode);
  fd.append('DocumentType', String(documentType));
  fd.append('FileName', fileName);
  fd.append('DocumentBase', buffer, { filename: fileName, contentType: mimeType });

  const res = await authedFetch('POST', '/v3.1/PurchaseOrder/document', { formData: fd });
  const text = await res.text();
  if (!res.ok) throw new Error(`uploadPurchaseOrderDocument failed: ${res.status} ${text}`);
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

// PUT /v3.1/PurchaseOrder/update is a full PUT; caller passes the merged body.
async function updatePurchaseOrder(body) {
  const res = await authedFetch('PUT', '/v3.1/PurchaseOrder/update', { body });
  const text = await res.text();
  if (!res.ok) throw new Error(`updatePurchaseOrder failed: ${res.status} ${text}`);
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

module.exports = {
  getToken,
  listAllReadyToShipOrders,
  listShipmentOrdersByStatusAndType,
  uploadShipmentDocument,
  findPurchaseOrderByCode,
  listPendingPurchaseOrders,
  getPurchaseOrderDetail,
  getCurrencyIdMap,
  uploadPurchaseOrderDocument,
  updatePurchaseOrder,
  STATUS_READY_TO_SHIP,
  DOCUMENT_TYPE_CARRIER_LABEL,
  DOCUMENT_TYPE_BOL,
  DOCUMENT_TYPE_EXTERNAL,
  ORDER_TYPES,
};
