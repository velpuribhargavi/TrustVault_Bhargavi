'use strict';
/*
 * TrustVault single-page UI.
 *
 * Security rules for this file (checked by tests/test_http_hardening.py):
 *  - DOM is built with createElement/textContent only. No HTML strings, ever,
 *    so a document called "<img src=x onerror=alert(1)>" is just text.
 *  - Every state-changing request carries the X-CSRF-Token header.
 *  - The UI hides buttons for convenience only; the server decides every time.
 *  - Share-link tokens live only in memory and travel in the X-Link-Token
 *    header - never in a URL the server sees, never in localStorage.
 *
 * Colours: cerulean = action / allowed, neon rose = danger / denied / expired,
 * everything else neutral. All colours are CSS variables in style.css.
 */

const state = {
  user: null, csrf: null, meta: null, directory: null,
  session: null,           // { idle_timeout_seconds, warning_seconds, expires_at }
  lastActivity: Date.now(),// last request the server counted as activity
  serverOffset: 0,         // server clock minus browser clock, in ms
  links: {},               // document id -> { token, expires_at } opened through a share link
  timers: [],              // countdown intervals of the current page
  notice: null,            // message for the sign-in page
  lastDocId: null,         // the document a "no access" answer was about (for Request access)
};

// ------------------------------------------------------------------ helpers
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// Small line icons, built as DOM nodes (no markup strings).
const ICONS = {
  shield: ['M12 3l7 3v5c0 4.4-3 8.3-7 10-4-1.7-7-5.6-7-10V6z'],
  lock: ['M7 11V8a5 5 0 0 1 10 0v3', 'M5 11h14v10H5z', 'M12 15v2'],
  eye: ['M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z', 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z'],
  download: ['M12 4v11', 'M7 10l5 5 5-5', 'M5 20h14'],
  clock: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z', 'M12 7v5l3 2'],
  alert: ['M12 3l10 18H2z', 'M12 10v5', 'M12 18v.01'],
  link: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
  file: ['M6 3h8l4 4v14H6z', 'M14 3v4h4'],
  check: ['M5 12.5l4.5 4.5L19 7.5'],
  phone: ['M8 2h8a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z', 'M11 18h2'],
  monitor: ['M3 4h18v12H3z', 'M8 20h8', 'M12 16v4'],
  x: ['M6 6l12 12', 'M18 6L6 18'],
};
function icon(name, cls) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
  svg.setAttribute('aria-hidden', 'true');
  for (const d of ICONS[name] || []) {
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('d', d);
    svg.append(p);
  }
  return svg;
}

class ApiError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code || null; }
}

function describe(data, status) {
  if (data && typeof data.detail === 'string') {
    if (data.problems && data.problems.length) {
      return data.detail + ': ' + data.problems.map(p => `${p.field} ${p.problem}`).join('; ');
    }
    return data.detail;
  }
  return `Request failed (${status})`;
}

const serverNow = () => Date.now() + state.serverOffset;
function syncClock(serverTime) {
  const t = Date.parse(serverTime || '');
  if (!Number.isNaN(t)) state.serverOffset = t - Date.now();
}

// The share link (if any) this browser holds for a document, while it is valid.
function linkFor(docId) {
  const l = state.links[docId];
  if (!l) return null;
  if (Date.parse(l.expires_at) <= serverNow()) { delete state.links[docId]; return null; }
  return l.token;
}

async function rawFetch(method, url, body, opts = {}) {
  const headers = {};
  if (method !== 'GET' && state.csrf) headers['X-CSRF-Token'] = state.csrf;
  if (opts.link) headers['X-Link-Token'] = opts.link;
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch(url, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  if (res.status !== 401) state.lastActivity = Date.now();  // the server restarted its idle timer
  return res;
}

async function handleError(res, data, opts) {
  if (res.status === 401 && !opts.quiet401) {
    if (data && data.code === 'session_expired') sessionExpired(true);
    else { forgetUser(); rememberReturn(); if (location.hash !== '#/login') location.hash = '#/login'; }
    throw new ApiError(401, 'Please sign in.', data && data.code);
  }
  throw new ApiError(res.status, describe(data, res.status), data && data.code);
}

async function api(method, url, body, opts = {}) {
  const res = await rawFetch(method, url, body, opts);
  let data = null;
  if ((res.headers.get('content-type') || '').includes('application/json')) data = await res.json();
  if (!res.ok) await handleError(res, data, opts);
  if (data && data.server_time) syncClock(data.server_time);
  return data;
}

// The file name a response asks to be saved under.
function fileNameOf(res, fallback = 'download') {
  const cd = res.headers.get('content-disposition') || '';
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  const plain = /filename="([^"]+)"/i.exec(cd);
  try { return star ? decodeURIComponent(star[1]) : plain ? plain[1] : fallback; } catch (_) { return fallback; }
}

function saveBlob(blob, name) {
  const href = URL.createObjectURL(blob);
  const a = h('a', { href, download: name, class: 'hidden' });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 10000);
}

// Fetch a file with the session (and link) and save it - so a refusal shows
// the "no access" page instead of a raw error, and a link token never sits in a URL.
async function downloadFile(url, link) {
  try {
    const res = await rawFetch('GET', url, undefined, { link });
    if (!res.ok) {
      let data = null;
      try { data = await res.json(); } catch (_) { /* not JSON */ }
      await handleError(res, data, {});
    }
    saveBlob(await res.blob(), fileNameOf(res));
    toast('Download started');
  } catch (e) { reportError(e); }
}

function toast(message, isError = false) {
  const box = document.getElementById('toast');
  const t = h('div', { class: 't' + (isError ? ' err' : '') }, message);
  box.append(t);
  setTimeout(() => t.remove(), isError ? 7000 : 3500);
}

function reportError(e) {
  if (e instanceof ApiError && e.code === 'no_access') { renderDenied(); return; }
  if (!(e instanceof ApiError && e.status === 401)) toast(e.message || 'Something went wrong', true);
}

async function attempt(fn, okMessage) {
  try {
    const r = await fn();
    if (okMessage) toast(okMessage);
    return r;
  } catch (e) {
    reportError(e);
    return undefined;
  }
}

const fmtDate = s => (s ? new Date(s).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—');
const fmtDay = s => (s ? new Date(s).toLocaleDateString([], { dateStyle: 'medium' }) : '—');
const fmtTime = s => (s ? new Date(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—');
function fmtSize(n) {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}
function fmtLeft(ms) {
  if (ms <= 0) return '0:00';
  const s = Math.floor(ms / 1000);
  if (s < 3600) return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')} min`;
  const d = Math.floor(s / 86400);
  return `${d} day${d === 1 ? '' : 's'}`;
}

// Badge tones: "ok" (cerulean), "bad" (neon rose), anything else neutral.
const TONE = {
  allowed: 'ok', active: 'ok', info: 'neutral',
  denied: 'bad', error: 'bad', critical: 'bad', high: 'bad', medium: 'bad', expired: 'bad', revoked: 'bad',
  inactive: 'bad', deleted: 'bad', locked: 'bad', destroyed: 'bad', trash: 'bad', dead: 'bad',
};
const badge = (text, tone) => h('span', { class: 'badge ' + (tone || TONE[text] || 'neutral') }, text);
const roleBadge = role => h('span', { class: 'badge role role-' + role }, role);
const LEVELS = [
  ['view', 'View only', 'Open it in the browser (watermarked). Cannot download or change it.'],
  ['download', 'View + download', 'Can also download the original file.'],
  ['edit', 'Edit', 'Can also upload new versions and change name, category and description.'],
];
const levelLabel = p => (p === 'owner' ? 'Owner' : (LEVELS.find(l => l[0] === p) || [p, p])[1]);
const permBadge = p => badge(levelLabel(p), 'ok');

// Classification labels. A label never opens a document to anyone; it changes defaults and marking.
const LABEL_INFO = {
  public: ['Public', 'Public: fine to share widely - still only with the people the owner names.'],
  internal: ['Internal', 'Internal: for people inside the company (the default).'],
  confidential: ['Confidential', 'Confidential: every page is marked CONFIDENTIAL; new access is View only for 1 hour unless the owner chooses more.'],
};
const labelBadge = c => h('span', { class: 'badge label label-' + c, title: (LABEL_INFO[c] || [c, ''])[1] }, (LABEL_INFO[c] || [c])[0]);
function labelSelect(value) {
  return h('select', { name: 'classification' },
    Object.entries(LABEL_INFO).map(([v, [name]]) => h('option', { value: v, selected: v === value }, name)));
}
const REQUEST_TONE = { pending: 'neutral', approved: 'ok', denied: 'bad', withdrawn: 'neutral', expired: 'bad' };

// A TrustVault link (…#/doc/<id>) or a bare document id -> the id.
function docIdFrom(text) {
  const t = (text || '').trim();
  const m = /#\/doc\/([A-Za-z0-9_-]{10,64})/.exec(t);
  if (m) return m[1];
  return /^[A-Za-z0-9_-]{10,64}$/.test(t) ? t : null;
}

// "Request access": the same answer whether or not the document exists.
function requestAccessForm(fixedDocId, { permission = 'view', onSent } = {}) {
  const idInput = fixedDocId ? null : h('input', { required: true, maxlength: 300, placeholder: 'Paste the link someone sent you, or the document id' });
  const level = h('select', null, LEVELS.map(([v, label]) => h('option', { value: v, selected: v === permission }, label)));
  const note = h('textarea', { maxlength: 500, placeholder: 'Why you need it (optional). The owner sees this.' });
  const out = h('div', { 'aria-live': 'polite' });
  const send = h('button', { class: 'primary', type: 'submit' }, 'Send request');
  const form = h('form', { class: 'stack request-form', onsubmit: async (e) => {
    e.preventDefault();
    const docId = fixedDocId || docIdFrom(idInput.value);
    if (!docId) { toast('That is not a TrustVault link or document id', true); return; }
    send.disabled = true;
    const r = await attempt(() => api('POST', '/api/access-requests', { document_id: docId, permission: level.value, note: note.value }));
    send.disabled = false;
    if (!r) return;
    form.classList.add('hidden');
    out.replaceChildren(h('div', { class: 'callout info stack' }, h('strong', null, 'Request sent'),
      h('span', null, String(r.message || '').replace(/^Request sent\.\s*/, '')),
      h('div', null, h('a', { href: '#/documents' }, 'See my requests'))));
    if (onSent) onSent(r);
  } },
    idInput ? field('Document link or id', idInput) : null,
    field('Access you need', level), field('Note for the owner', note), h('div', null, send));
  return h('div', null, form, out);
}
const enc = encodeURIComponent;

// A live "ends in 4:59" label. Turns rose in the last minute; calls onEnd once at zero.
function countdown(expiresAt, { prefix = 'ends in ', ended = 'Expired', onEnd, warnBelow = 60000 } = {}) {
  const el = h('span', { class: 'countdown' });
  let done = false;
  function tick() {
    const left = Date.parse(expiresAt) - serverNow();
    if (left <= 0) {
      el.textContent = ended;
      el.className = 'countdown over';
      if (!done) { done = true; if (onEnd) onEnd(); }
      return;
    }
    el.textContent = prefix + fmtLeft(left);
    el.className = 'countdown' + (left < warnBelow ? ' low' : '');
  }
  tick();
  state.timers.push(setInterval(tick, 1000));
  return el;
}

function clearTimers() { state.timers.forEach(clearInterval); state.timers = []; }

function table(headers, rows, emptyText) {
  // Each cell carries its column name, so on a phone the rows can stack as cards.
  for (const tr of rows) {
    if (tr.classList.contains('detail-row')) continue;
    [...tr.children].forEach((td, i) => { if (headers[i]) td.setAttribute('data-label', headers[i]); });
  }
  return h('div', { class: 'table-wrap' },
    h('table', null,
      h('thead', null, h('tr', null, headers.map(x => h('th', { scope: 'col' }, x)))),
      h('tbody', null, rows.length ? rows : h('tr', null, h('td', { class: 'empty', colspan: headers.length }, emptyText || 'Nothing here yet.')))));
}

function field(label, input) { return h('label', null, h('span', { class: 'label' }, label), input); }

function categorySelect(value, includeAny) {
  const cats = (state.meta && state.meta.categories) || [];
  return h('select', { name: 'category' },
    includeAny ? h('option', { value: '' }, 'Any category') : null,
    cats.map(c => h('option', { value: c, selected: c === value }, c)));
}

// "Details" disclosure: raw JSON, internal ids and hashes live here, not in columns.
function more(summary, ...content) {
  return h('details', { class: 'more' }, h('summary', null, summary), h('div', { class: 'more-body' }, content));
}

function loadingPanel(text = 'Loading…') {
  return h('section', { class: 'panel state-panel', role: 'status' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), text);
}

function errorPanel(retry) {
  return h('section', { class: 'panel state-panel' },
    h('p', null, 'This page could not be loaded.'),
    retry ? h('button', { type: 'button', onclick: retry }, 'Try again') : null);
}

// -------------------------------------------------- return-to-page, sign-out
function storage() { try { return window.sessionStorage; } catch (_) { return null; } }

function rememberReturn() {
  const here = location.hash;
  if (!here || !here.startsWith('#/') || here === '#/login' || here === '#/denied') return;
  try { const s = storage(); if (s) s.setItem('tv.returnTo', here); } catch (_) { /* private mode */ }
}

function takeReturn() {
  try {
    const s = storage();
    const v = s ? s.getItem('tv.returnTo') : null;
    if (s) s.removeItem('tv.returnTo');
    // Only ever an in-app route: no open redirect.
    return v && /^#\/[A-Za-z0-9/_.~%-]*$/.test(v) && v !== '#/login' ? v : null;
  } catch (_) { return null; }
}

function forgetUser() {
  state.user = null; state.csrf = null; state.session = null; state.directory = null; state.links = {};
  hideIdleWarning();
}

// fromServer: the server already ended the session (and recorded it). Otherwise
// this browser's own timer ran out first: tell the server to end it now, so a
// later request cannot quietly revive it, and so the expiry is recorded.
function sessionExpired(fromServer = false, reason = 'idle') {
  if (!fromServer && state.user) {
    rawFetch('POST', '/api/auth/logout', { reason }).catch(() => {});
  }
  rememberReturn();
  forgetUser();
  state.notice = `You were signed out after ${state.meta ? state.meta.session_idle_minutes : 15} minutes without activity ` +
    '(or at the end of your sign-in period). Sign in again to go back to where you were.';
  if (location.hash === '#/login') renderLogin(); else location.hash = '#/login';
}

// ---------------------------------------------------- idle sign-out warning
const SAFETY_MS = 20000;  // the server may count the idle timer from up to 15 s earlier
let idleBox = null;

function hideIdleWarning() { if (idleBox) { idleBox.remove(); idleBox = null; } }

function showIdleWarning(kind, msLeft) {
  if (!idleBox) {
    const text = h('p', { class: 'idle-text' });
    const stay = h('button', { class: 'primary', type: 'button', onclick: async () => {
      const r = await attempt(() => api('POST', '/api/auth/keepalive'));
      if (r) { state.session = r.session; hideIdleWarning(); toast('You are still signed in'); }
    } }, 'Stay signed in');
    const out = h('button', { type: 'button', onclick: () => { hideIdleWarning(); logout(); } }, 'Sign out now');
    idleBox = h('div', { class: 'modal-backdrop' },
      h('div', { class: 'modal', role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'idle-title', 'aria-describedby': 'idle-text' },
        h('div', { class: 'modal-icon', 'aria-hidden': 'true' }, icon('clock')),
        h('h2', { id: 'idle-title' }, 'Are you still there?'), text, h('div', { class: 'actions' }, out, stay)));
    text.id = 'idle-text';
    document.body.append(idleBox);
    stay.focus();
  }
  const text = idleBox.querySelector('.idle-text');
  const stay = idleBox.querySelector('button.primary');
  if (kind === 'max') {
    text.textContent = `Your sign-in reaches its ${state.meta ? state.meta.session_max_hours : 8}-hour limit in ${fmtLeft(msLeft)}. ` +
      'Save what you are doing; you will need to sign in again.';
    stay.classList.add('hidden');
  } else {
    text.textContent = `For your security you will be signed out in ${fmtLeft(msLeft)} because nothing has happened for a while.`;
    stay.classList.remove('hidden');
  }
}

function idleTick() {
  if (!state.user || !state.session) { hideIdleWarning(); return; }
  const s = state.session;
  const idleLeft = state.lastActivity + s.idle_timeout_seconds * 1000 - SAFETY_MS - Date.now();
  const maxLeft = Date.parse(s.expires_at) - serverNow();
  if (idleLeft <= 0 || maxLeft <= 0) { sessionExpired(false, maxLeft <= 0 ? 'max_lifetime' : 'idle'); return; }
  const warn = s.warning_seconds * 1000;
  if (maxLeft <= warn) showIdleWarning('max', maxLeft);
  else if (idleLeft <= warn) showIdleWarning('idle', idleLeft);
  else hideIdleWarning();
}
setInterval(idleTick, 1000);

// ------------------------------------------------------------------- shell
const app = () => document.getElementById('app');

function brand() {
  return h('div', { class: 'brand' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, icon('shield')), 'TrustVault');
}

function shell(active, ...content) {
  const u = state.user;
  const links = [['#/documents', 'Documents', 'documents']];
  if (u.role === 'owner') links.push(['#/upload', 'Upload', 'upload'], ['#/trash', 'Trash', 'trash']);
  if (u.role === 'admin') {
    links.splice(0, 1);
    links.push(['#/admin', 'Overview', 'admin'], ['#/admin/users', 'Users', 'users'],
      ['#/admin/audit', 'Audit trail', 'audit'], ['#/admin/documents', 'Access review', 'access']);
  }
  links.push(['#/account', 'Account', 'account']);
  const page = h('div', { class: 'app-frame' },
    h('header', { class: 'topbar' },
      brand(),
      h('nav', { 'aria-label': 'Main' }, links.map(([href, text, key]) =>
        h('a', {
          href, class: key === active ? 'active' : '', 'aria-current': key === active ? 'page' : null,
          // Clicking the page you are on reloads it (new requests, new shares): the hash does not change, so no hashchange.
          onclick: (e) => { if (location.hash === href) { e.preventDefault(); route(); } },
        }, text))),
      h('div', { class: 'whoami' },
        h('span', { class: 'who-name' }, u.display_name), roleBadge(u.role), u.is_external ? badge('external') : null,
        h('button', { class: 'small ghost', type: 'button', onclick: logout }, 'Sign out'))),
    h('main', { class: 'page', id: 'main' }, content));
  app().replaceChildren(page);
}

async function logout() {
  await attempt(() => api('POST', '/api/auth/logout'));
  forgetUser();
  location.hash = '#/login';
}

// ----------------------------------------------------------- no access page
function renderDenied() {
  clearTimers();
  const signedIn = !!state.user;
  const isAdmin = signedIn && state.user.role === 'admin';
  const card = h('section', { class: 'denied-card', role: 'alert' },
    h('div', { class: 'denied-mark', 'aria-hidden': 'true' }, icon('lock')),
    h('h1', null, "You don't have access to this file."),
    h('p', { class: 'muted' }, isAdmin ? 'Administrators never open documents.' : 'If you need it, ask the person who owns it.'),
    h('div', { class: 'actions' },
      h('a', { class: 'btn' + (signedIn && !isAdmin ? '' : ' primary'), href: isAdmin ? '#/admin' : '#/documents' },
        isAdmin ? 'Go to overview' : 'Go to my documents'),
      signedIn && !isAdmin ? h('button', { type: 'button', class: 'primary', onclick: () => {
        askBox.classList.toggle('hidden');
        const first = askBox.querySelector('input, select');
        if (first) first.focus();
      } }, 'Request access') : null));
  // The id the refusal was about, if it came from a document page. Asking gives
  // the same answer whether or not the document exists, so nothing is revealed here.
  const docId = state.lastDocId;
  const askBox = h('div', { class: 'denied-ask hidden' },
    signedIn && !isAdmin ? requestAccessForm(docId) : null);
  card.append(askBox);
  if (signedIn) shell('documents', card);
  else app().replaceChildren(h('main', { class: 'page' }, card));
  if (location.hash !== '#/denied') history.replaceState(null, '', '#/denied');
}

// ------------------------------------------------------------------- login
// Shared by sign-in and the Account page: the QR code, the key, and the codes.
function setupKeyBlock(offer) {
  return h('div', { class: 'enrol' },
    offer.qr ? h('img', { class: 'qr', src: offer.qr, width: 200, height: 200, alt: 'QR code to scan with your authenticator app' }) : null,
    h('div', { class: 'enrol-key' },
      h('div', { class: 'muted small-help' }, 'Can’t scan? In the app choose “Enter a setup key” and type:'),
      h('div', { class: 'secret setup-key' }, offer.secret_grouped),
      h('div', { class: 'muted small-help' }, `Account: ${offer.account} · Time-based · ${offer.digits} digits`)));
}

function codeInput(label = 'Code from your authenticator app') {
  const input = h('input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', required: true,
    minlength: 6, maxlength: 12, class: 'code-input', spellcheck: 'false' });
  return [field(label, input), input];
}

function backupCodesBlock(codes, who) {
  const text = `TrustVault backup codes for ${who}\nEach code signs you in once, if you lose your phone.\n\n${codes.join('\n')}\n`;
  return h('div', { class: 'stack' },
    h('ol', { class: 'backup-codes' }, codes.map(c => h('li', null, c))),
    h('div', { class: 'actions' },
      h('button', { type: 'button', onclick: () => saveBlob(new Blob([text], { type: 'text/plain' }), `trustvault-backup-codes-${who}.txt`) },
        icon('download'), 'Download as a text file')));
}

function renderLogin() {
  clearTimers();
  const card = h('div', { class: 'login-card' });
  const notice = state.notice ? h('p', { class: 'callout info' }, state.notice) : null;

  function signedIn(r) {
    state.user = r.user; state.csrf = r.csrf_token; state.session = r.session; state.notice = null;
    state.lastActivity = Date.now();
    syncClock(r.session && r.session.server_time);
    if (typeof r.backup_codes_left === 'number') {
      toast(`Signed in with a backup code. ${r.backup_codes_left} left` + (r.backup_codes_left <= 2 ? ' - make new ones on the Account page.' : '.'), r.backup_codes_left <= 2);
    }
    location.hash = takeReturn() || (r.user.role === 'admin' ? '#/admin' : '#/documents');  // hashchange re-renders
  }

  function passwordStep(message) {
    const msg = h('p', { class: 'error', role: 'alert' }, message || '');
    const user = h('input', { name: 'username', autocomplete: 'username', required: true, maxlength: 64 });
    const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
    const submit = h('button', { class: 'primary block', type: 'submit' }, 'Sign in');
    const form = h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      msg.textContent = '';
      submit.disabled = true;
      try {
        const r = await api('POST', '/api/auth/login', { username: user.value, password: pass.value }, { quiet401: true });
        pass.value = '';
        if (r.two_factor === 'verify') codeStep(r, user.value);
        else if (r.two_factor === 'enroll') enrolStep(r);
        else signedIn(r);
      } catch (err) { msg.textContent = err.message; pass.value = ''; pass.focus(); } finally { submit.disabled = false; }
    } }, h('h1', null, 'Sign in'), notice, field('Username', user), field('Password', pass), msg, submit);
    card.replaceChildren(form);
    user.focus();
  }

  // After a refused code: start again if the attempt has ended, otherwise try again.
  function codeRefused(err, msg, input) {
    if (err instanceof ApiError && err.code === 'sign_in_expired') { passwordStep(err.message); return; }
    msg.textContent = err.message; input.value = ''; input.focus();
  }

  function codeStep(ch, username) {
    const msg = h('p', { class: 'error', role: 'alert' });
    const [label, input] = codeInput();
    let backup = false;
    const hint = h('p', { class: 'muted' }, 'Open your authenticator app and enter the 6-digit code for TrustVault.');
    const toggle = h('button', { type: 'button', class: 'linkish', onclick: () => {
      backup = !backup;
      label.querySelector('.label').textContent = backup ? 'Backup code (xxxx-xxxx)' : 'Code from your authenticator app';
      input.setAttribute('inputmode', backup ? 'text' : 'numeric');
      hint.textContent = backup ? 'Each backup code works once. Use one if you do not have your phone.'
        : 'Open your authenticator app and enter the 6-digit code for TrustVault.';
      toggle.textContent = backup ? 'Use the app instead' : 'Use a backup code instead';
      input.value = ''; input.focus();
    } }, 'Use a backup code instead');
    const submit = h('button', { class: 'primary block', type: 'submit' }, 'Verify');
    const form = h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      msg.textContent = '';
      submit.disabled = true;
      try {
        signedIn(await api('POST', '/api/auth/login/verify', { challenge: ch.challenge, code: input.value.trim() }, { quiet401: true }));
      } catch (err) { codeRefused(err, msg, input); } finally { submit.disabled = false; }
    } },
      h('div', { class: 'step-mark', 'aria-hidden': 'true' }, icon('shield')),
      h('h1', null, 'Two-step sign-in'),
      h('p', null, 'Password accepted for ', h('strong', null, username), '.'), hint,
      label, msg, submit,
      h('div', { class: 'login-links' }, toggle,
        h('button', { type: 'button', class: 'linkish', onclick: () => passwordStep() }, 'Start again')),
      h('p', { class: 'muted small-help' }, 'This step ', countdown(ch.expires_at, { prefix: 'expires in ', ended: 'has expired - start again' }), '.'));
    card.replaceChildren(form);
    input.focus();
  }

  function enrolStep(ch) {
    const msg = h('p', { class: 'error', role: 'alert' });
    const [label, input] = codeInput('The 6-digit code the app now shows');
    const submit = h('button', { class: 'primary block', type: 'submit' }, 'Turn on and sign in');
    const form = h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      msg.textContent = '';
      submit.disabled = true;
      try {
        const r = await api('POST', '/api/auth/login/enroll', { challenge: ch.challenge, code: input.value.trim() }, { quiet401: true });
        backupStep(r);
      } catch (err) { codeRefused(err, msg, input); } finally { submit.disabled = false; }
    } },
      h('div', { class: 'step-mark', 'aria-hidden': 'true' }, icon('shield')),
      h('h1', null, 'Set up two-step sign-in'),
      h('p', null, 'Administrators and owners sign in with their password ', h('em', null, 'and'),
        ' a code from their phone. It takes a minute, once:'),
      h('ol', { class: 'steps' },
        h('li', null, 'Install an authenticator app - Google Authenticator, Microsoft Authenticator, 1Password or Authy.'),
        h('li', null, 'Add an account by scanning this QR code.'),
        h('li', null, 'Type the 6-digit code it shows.')),
      setupKeyBlock(ch), label, msg, submit,
      h('div', { class: 'login-links' }, h('button', { type: 'button', class: 'linkish', onclick: () => passwordStep() }, 'Cancel')),
      h('p', { class: 'muted small-help' }, 'This set-up ', countdown(ch.expires_at, { prefix: 'expires in ', ended: 'has expired - start again' }), '.'));
    card.replaceChildren(form);
    input.focus();
  }

  function backupStep(r) {
    const saved = h('input', { type: 'checkbox' });
    const go = h('button', { class: 'primary block', type: 'button', disabled: true, onclick: () => signedIn(r) }, 'Continue');
    saved.addEventListener('change', () => { go.disabled = !saved.checked; });
    card.replaceChildren(h('div', { class: 'stack' },
      h('div', { class: 'step-mark ok', 'aria-hidden': 'true' }, icon('check')),
      h('h1', null, 'Two-step sign-in is on'),
      h('p', null, 'Save these backup codes somewhere safe. If you lose your phone, each one signs you in once. ',
        h('strong', null, 'They are shown only now.')),
      backupCodesBlock(r.backup_codes, r.user.username),
      h('label', { class: 'check' }, saved, h('span', null, 'I have saved these codes')), go));
  }

  app().replaceChildren(h('div', { class: 'login-wrap' },
    h('section', { class: 'login-side' },
      brand(),
      h('h1', null, 'The wrong person can never read the file.'),
      h('ul', { class: 'promises' },
        h('li', null, icon('lock'), 'Shared with named people only, for a limited time, checked by the server on every request.'),
        h('li', null, icon('eye'), 'Every open, download and refusal is written to a tamper-evident audit trail.'),
        h('li', null, icon('clock'), 'Revoking access works on the very next click.'))),
    h('section', { class: 'login-form' }, card)));
  passwordStep();
}

// ---------------------------------------------------------------- documents
async function renderDocuments() {
  const results = h('div', null, loadingPanel('Loading documents…'));
  const q = h('input', { name: 'q', placeholder: 'Name contains…', maxlength: 200, type: 'search' });
  const owner = h('input', { name: 'owner', placeholder: 'Owner username', maxlength: 64 });
  const cat = categorySelect('', true);
  const from = h('input', { type: 'date', name: 'date_from' });
  const to = h('input', { type: 'date', name: 'date_to' });
  const scope = h('select', { name: 'scope' }, h('option', { value: 'all' }, 'All I can access'),
    h('option', { value: 'mine' }, 'Owned by me'), h('option', { value: 'shared' }, 'Shared with me'));
  let page = 1;

  async function load() {
    const p = new URLSearchParams({ page: String(page), page_size: '20', scope: scope.value });
    if (q.value.trim()) p.set('q', q.value.trim());
    if (owner.value.trim()) p.set('owner', owner.value.trim());
    if (cat.value) p.set('category', cat.value);
    if (from.value) p.set('date_from', from.value);
    if (to.value) p.set('date_to', to.value);
    const data = await attempt(() => api('GET', '/api/documents?' + p.toString()));
    if (!data) { results.replaceChildren(errorPanel(load)); return; }
    clearTimers();
    const rows = data.items.map(d => h('tr', { class: 'clickable', tabindex: '0',
      onclick: () => { location.hash = '#/doc/' + enc(d.id); },
      onkeydown: (e) => { if (e.key === 'Enter') location.hash = '#/doc/' + enc(d.id); } },
      h('td', null, h('div', { class: 'cell-title' }, icon('file'), h('strong', null, d.name)),
        h('div', { class: 'cell-sub' }, labelBadge(d.classification), badge(d.category, 'neutral'),
          d.description ? h('span', { class: 'muted' }, d.description.slice(0, 80)) : null)),
      h('td', null, d.owner.display_name || d.owner.username),
      h('td', { class: 'num' }, fmtDay(d.created_at)),
      h('td', { class: 'num' }, fmtSize(d.current_version.size_bytes)),
      h('td', null, permBadge(d.my_permission),
        d.my_access_expires_at ? h('div', { class: 'small-help' }, countdown(d.my_access_expires_at, { ended: 'Expired' })) : null)));
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    results.replaceChildren(
      table(['Name', 'Owner', 'Uploaded', 'Size', 'My access'], rows,
        state.user.role === 'owner'
          ? 'No documents yet. Upload one - only you can see it until you share it.'
          : 'Nothing has been shared with you yet. You only ever see documents someone has given you.'),
      h('div', { class: 'pager' }, h('span', { class: 'muted num' }, `${data.total} document(s) · page ${page} of ${pages}`),
        h('button', { class: 'small', disabled: page <= 1, onclick: () => { page--; load(); } }, '‹ Prev'),
        h('button', { class: 'small', disabled: page >= pages, onclick: () => { page++; load(); } }, 'Next ›')));
  }

  const form = h('form', { class: 'inline filters', onsubmit: (e) => { e.preventDefault(); page = 1; load(); } },
    field('Name', q), field('Owner', owner), field('Category', cat), field('From', from), field('To', to),
    field('Show', scope), h('button', { class: 'primary', type: 'submit' }, 'Search'));
  const waiting = h('div');
  const requestsArea = h('div');
  shell('documents',
    h('div', { class: 'page-head' }, h('h1', null, 'Documents'),
      state.user.role === 'owner' ? h('a', { class: 'btn primary', href: '#/upload' }, '+ Upload') : null),
    waiting,
    h('section', { class: 'panel' }, form),
    h('section', { class: 'panel flush' }, results),
    requestsArea);
  load();
  loadRequestPanels(waiting, requestsArea);
}

// Requests waiting for the owner's answer: approve (level + duration) or deny (optional reason).
function decisionRows(items, onDone) {
  return items.map(r => {
    const level = h('select', { class: 'compact', 'aria-label': `Access for ${r.requester.display_name}` },
      LEVELS.map(([v, label]) => h('option', { value: v, selected: v === r.default_permission }, label)));
    const minutes = h('select', { class: 'compact', 'aria-label': 'For how long' },
      DURATIONS.map(([m, t]) => h('option', { value: m, selected: m === r.default_minutes }, t)));
    return h('tr', null,
      h('td', null, h('strong', null, r.requester.display_name), h('div', { class: 'cell-sub' },
        h('span', { class: 'muted' }, r.requester.username), r.requester.is_external ? badge('external', 'neutral') : null,
        r.requester.is_active ? null : badge('inactive'))),
      h('td', null, h('a', { href: '#/doc/' + enc(r.document_id) }, r.document_name), h('div', { class: 'cell-sub' },
        labelBadge(r.classification), r.in_trash ? badge('in trash', 'bad') : null)),
      h('td', null, permBadge(r.permission), r.note ? h('div', { class: 'request-note' }, '“' + r.note + '”') : null,
        h('div', { class: 'muted small-help num' }, fmtDate(r.created_at))),
      h('td', null, h('div', { class: 'row-actions' }, level, minutes,
        h('button', { class: 'small primary', type: 'button', onclick: async () => {
          if (await attempt(() => api('POST', `/api/access-requests/${enc(r.id)}/approve`,
            { permission: level.value, duration_minutes: Number(minutes.value) }), `Access given to ${r.requester.display_name}`)) onDone();
        } }, 'Approve'),
        h('button', { class: 'small danger', type: 'button', onclick: async () => {
          const why = window.prompt(`Deny ${r.requester.display_name}'s request? Optional reason - they will see it:`, '');
          if (why === null) return;
          if (await attempt(() => api('POST', `/api/access-requests/${enc(r.id)}/deny`, { reason: why }), 'Request denied')) onDone();
        } }, 'Deny'))));
  });
}

function waitingPanel(items, onDone, title = 'Requests waiting for you') {
  return h('section', { class: 'panel requests-waiting' },
    h('div', { class: 'panel-head' }, h('h2', null, title, ' ', badge(String(items.length), 'bad'))),
    h('p', { class: 'muted small-help' }, 'You choose the level and for how long. Confidential documents start at View only for 1 hour.'),
    table(['Person', 'Document', 'Asked for', 'Your answer'], decisionRows(items, onDone)));
}

async function loadRequestPanels(waiting, area) {
  if (state.user.role === 'admin') return;
  const reload = () => loadRequestPanels(waiting, area);
  const [inc, mine, ended] = await Promise.all([
    state.user.role === 'owner' ? attempt(() => api('GET', '/api/access-requests/incoming')) : Promise.resolve({ items: [] }),
    attempt(() => api('GET', '/api/access-requests/mine')),
    attempt(() => api('GET', '/api/access-requests/ended'))]);
  if (!inc || !mine || !ended) return;
  waiting.replaceChildren(inc.items.length ? waitingPanel(inc.items, reload) : '');
  const mineRows = mine.items.map(r => h('tr', null,
    h('td', null, r.document_name
      ? h('a', { href: '#/doc/' + enc(r.document_id) }, r.document_name)
      : h('span', null, h('span', { class: 'mono' }, r.document_id.slice(0, 8) + '…'),
          h('div', { class: 'muted small-help' }, 'The name appears once the owner says yes'))),
    h('td', null, permBadge(r.permission)),
    h('td', null, badge(r.status, REQUEST_TONE[r.status]),
      r.status === 'approved' ? h('div', { class: 'small-help' }, levelLabel(r.granted_permission), ' · ',
        countdown(r.grant_expires_at, { prefix: 'ends in ', ended: 'ended' })) : null,
      r.owner_reason ? h('div', { class: 'request-note' }, '“' + r.owner_reason + '”') : null),
    h('td', { class: 'num' }, fmtDate(r.created_at)),
    h('td', { class: 'right' }, r.status === 'pending' ? h('button', { class: 'small', type: 'button', onclick: async () => {
      if (await attempt(() => api('POST', `/api/access-requests/${enc(r.id)}/withdraw`), 'Request withdrawn')) reload();
    } }, 'Withdraw') : null)));
  const endedRows = ended.items.map(d => h('tr', null,
    h('td', null, h('strong', null, d.name), h('div', { class: 'cell-sub' }, labelBadge(d.classification),
      h('span', { class: 'muted' }, `owner: ${d.owner}`))),
    h('td', null, permBadge(d.permission)),
    h('td', { class: 'num' }, fmtDate(d.expires_at)),
    h('td', { class: 'right' }, d.request_pending ? badge('asked', 'neutral') : h('button', { class: 'small', type: 'button', onclick: async () => {
      if (await attempt(() => api('POST', '/api/access-requests', { document_id: d.id, permission: d.permission, note: '' }), 'Request sent')) reload();
    } }, 'Ask again'))));
  area.replaceChildren(h('div', { class: 'grid two section-gap' },
    // No requests yet: just the form, no empty table.
    mine.items.length ? h('section', { class: 'panel' }, h('h2', null, 'My requests'),
      table(['Document', 'Asked for', 'Status', 'Sent', ''], mineRows)) : null,
    h('section', { class: 'panel' }, h('h2', null, 'Ask for access'),
      h('p', { class: 'muted small-help' }, 'Someone sent you a link you cannot open? Paste it here and the owner will be asked.'),
      requestAccessForm(null, { onSent: reload }),
      ended.items.length ? [h('h3', { class: 'section-gap' }, 'Access that has ended'),
        table(['Document', 'You had', 'Ended', ''], endedRows)] : null)));
}

function renderUpload() {
  const file = h('input', { type: 'file', name: 'file', required: true, class: 'file-input',
    accept: ((state.meta && state.meta.allowed_extensions) || []).map(x => '.' + x).join(',') });
  const name = h('input', { name: 'name', maxlength: 200, placeholder: 'Defaults to the file name' });
  const desc = h('textarea', { name: 'description', maxlength: 1000 });
  const cat = categorySelect('general');
  const label = labelSelect((state.meta && state.meta.default_classification) || 'internal');
  const labelHelp = h('p', { class: 'muted small-help' }, LABEL_INFO[label.value][1]);
  label.addEventListener('change', () => { labelHelp.textContent = LABEL_INFO[label.value][1]; });
  const submit = h('button', { class: 'primary', type: 'submit' }, 'Upload');
  const form = h('form', { class: 'stack', onsubmit: async (e) => {
    e.preventDefault();
    if (!file.files.length) return;
    const fd = new FormData();
    fd.append('file', file.files[0]);
    fd.append('category', cat.value);
    fd.append('name', name.value);
    fd.append('description', desc.value);
    fd.append('classification', label.value);
    submit.disabled = true;
    submit.textContent = 'Uploading…';
    const r = await attempt(() => api('POST', '/api/documents', fd), 'Uploaded and encrypted');
    submit.disabled = false;
    submit.textContent = 'Upload';
    if (r) location.hash = '#/doc/' + enc(r.id);
  } },
    field('File', file), field('Display name', name), field('Category', cat),
    field('Classification', label), labelHelp, field('Description', desc),
    h('p', { class: 'muted small-help' }, `Allowed: ${((state.meta && state.meta.allowed_extensions) || []).join(', ')} · up to ${fmtSize(state.meta ? state.meta.max_upload_bytes : 0)}. `,
      'Files are checked (type, macros, scripts) and encrypted before they are stored. Only you can see a new document until you share it.'),
    h('div', null, submit));
  shell('upload', h('div', { class: 'page-head' }, h('h1', null, 'Upload a document')), h('section', { class: 'panel narrow' }, form));
}

async function renderTrash() {
  shell('trash', h('div', { class: 'page-head' }, h('h1', null, 'Trash')), loadingPanel());
  const data = await attempt(() => api('GET', '/api/documents/trash'));
  if (!data) { shell('trash', h('div', { class: 'page-head' }, h('h1', null, 'Trash')), errorPanel(renderTrash)); return; }
  const rows = data.items.map(d => h('tr', null,
    h('td', null, h('a', { href: '#/doc/' + enc(d.id) }, d.name)),
    h('td', { class: 'num' }, fmtDate(d.deleted_at)),
    h('td', { class: 'right' }, h('button', { class: 'small', onclick: async () => {
      if (await attempt(() => api('POST', `/api/documents/${enc(d.id)}/restore`), 'Restored')) renderTrash();
    } }, 'Restore'))));
  shell('trash', h('div', { class: 'page-head' }, h('h1', null, 'Trash')),
    h('p', { class: 'muted lead' }, 'Nobody you shared these with can open them, and every share link to them has stopped working. They are destroyed automatically when the retention period ends.'),
    h('section', { class: 'panel flush' }, table(['Name', 'Deleted', ''], rows, 'The trash is empty.')));
}

// ----------------------------------------------------- opening a share link
async function renderLinkOpen(token) {
  if (!(await ensureSession())) {
    rememberReturn();   // after sign-in, come straight back to this link
    state.notice = 'Sign in to open the document that was shared with you. The link only works for the person it was made for.';
    location.hash = '#/login';
    return;
  }
  if (!state.meta) state.meta = await attempt(() => api('GET', '/api/meta'));
  app().replaceChildren(h('main', { class: 'page' }, loadingPanel('Opening link…')));
  const r = await attempt(() => api('POST', '/api/links/open', { token }));
  if (!r) return;  // refused: attempt() has shown the no-access page
  state.links[r.document_id] = { token, expires_at: r.expires_at };
  // Take the token out of the address bar and history; it stays in memory only.
  history.replaceState(null, '', '#/doc/' + enc(r.document_id));
  renderDocument(r.document_id);
}

// ----------------------------------------------------------- one document
async function renderDocument(id) {
  state.lastDocId = id;
  shell('documents', loadingPanel('Opening document…'));
  const link = linkFor(id);
  const doc = await attempt(() => api('GET', '/api/documents/' + enc(id), undefined, { link }));
  if (!doc) return;  // refused -> no-access page, or a toast for other errors
  clearTimers();
  const perm = doc.my_permission;
  const isOwner = perm === 'owner';
  const canEdit = perm === 'owner' || perm === 'edit';
  const canDownload = perm !== 'view';
  const trashed = !!doc.deleted_at;
  const current = doc.versions[0];
  const viewer = h('div');
  const actions = h('div', { class: 'actions' });
  const viaLink = doc.access_via === 'link';
  const dl = url => downloadFile(url, viaLink ? link : null);

  if (!trashed) {
    actions.append(h('button', { class: 'primary', type: 'button', onclick: () => openViewer(doc, viewer, viaLink ? link : null) }, icon('eye'), 'View'));
    if (canDownload) actions.append(h('button', { type: 'button', onclick: () => dl(`/api/documents/${enc(doc.id)}/download`) }, icon('download'), 'Download'));
  }
  // When access runs out, ask the server again: it refuses, and the no-access page shows.
  const accessLine = doc.access_expires_at
    ? h('p', { class: 'callout ' + (viaLink ? 'info' : 'neutral') }, icon('clock'),
        h('span', null, viaLink ? 'Opened through a share link made for you. It ' : 'Your access ',
          countdown(doc.access_expires_at, { prefix: 'ends in ', ended: 'has ended', onEnd: () => setTimeout(() => renderDocument(doc.id), 400) }),
          '.'))
    : null;

  const head = h('section', { class: 'panel' },
    h('div', { class: 'doc-head' },
      h('div', null, h('h1', null, doc.name),
        h('div', { class: 'sub' }, labelBadge(doc.classification), badge(doc.category, 'neutral'), h('span', null, 'Owner: ', doc.owner.display_name),
          h('span', { class: 'sep', 'aria-hidden': 'true' }, '·'), h('span', null, 'Your access'), permBadge(perm),
          viaLink ? badge('via link', 'neutral') : null,
          trashed ? badge('in trash', 'bad') : null)),
      actions),
    accessLine,
    perm === 'view' ? h('p', { class: 'callout neutral' },
      'View only: read it here; it cannot be downloaded. Every page you open is watermarked with your name and recorded.') : null,
    doc.classification === 'confidential' ? h('p', { class: 'callout danger' }, icon('lock'),
      h('span', { class: 'grow' }, 'Confidential: every page is marked CONFIDENTIAL with the name of the person viewing it.')) : null,
    doc.description ? h('p', { class: 'doc-desc' }, doc.description) : null,
    more('File details',
      h('dl', { class: 'meta' },
        h('dt', null, 'File'), h('dd', null, current ? `${current.original_filename} (${fmtSize(current.size_bytes)})` : '—'),
        h('dt', null, 'Version'), h('dd', null, current ? `v${current.version_no}` : '—'),
        h('dt', null, 'Created'), h('dd', { class: 'num' }, fmtDate(doc.created_at)),
        h('dt', null, 'Updated'), h('dd', { class: 'num' }, fmtDate(doc.updated_at)),
        h('dt', null, 'SHA-256'), h('dd', { class: 'mono' }, current ? current.sha256 : '—'))));

  const versions = h('section', { class: 'panel' }, h('h2', null, 'Versions'),
    table(['', 'Uploaded by', 'When', 'Size', ''], doc.versions.map(v => h('tr', null,
      h('td', { class: 'num' }, 'v' + v.version_no), h('td', null, v.uploaded_by), h('td', { class: 'num' }, fmtDate(v.created_at)),
      h('td', { class: 'num' }, fmtSize(v.size_bytes)),
      h('td', { class: 'right' }, trashed || !canDownload ? null : h('button', { class: 'small', type: 'button',
        onclick: () => dl(`/api/documents/${enc(doc.id)}/versions/${enc(v.id)}/download`) }, icon('download'), 'Download'))))));

  const left = [head, viewer, versions];
  const right = [];

  if (canEdit && !trashed) {
    const name = h('input', { value: doc.name, maxlength: 200 });
    const cat = categorySelect(doc.category);
    const desc = h('textarea', { maxlength: 1000 }, doc.description);
    const file = h('input', { type: 'file', class: 'file-input' });
    right.push(h('section', { class: 'panel' }, h('h2', null, 'Edit'),
      h('form', { class: 'stack', onsubmit: async (e) => {
        e.preventDefault();
        if (await attempt(() => api('PATCH', '/api/documents/' + enc(doc.id), { name: name.value, category: cat.value, description: desc.value }), 'Saved')) renderDocument(doc.id);
      } }, field('Name', name), field('Category', cat), field('Description', desc),
      h('div', null, h('button', { class: 'primary', type: 'submit' }, 'Save details'))),
      h('form', { class: 'stack section-gap', onsubmit: async (e) => {
        e.preventDefault();
        if (!file.files.length) return;
        const fd = new FormData(); fd.append('file', file.files[0]);
        if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/versions`, fd), 'New version uploaded')) renderDocument(doc.id);
      } }, h('h3', null, 'Upload a new version'), file, h('div', null, h('button', { type: 'submit' }, 'Upload version')))));
  }

  if (isOwner && !trashed) {
    const [grants, people, inc] = await Promise.all([
      attempt(() => api('GET', `/api/documents/${enc(doc.id)}/grants`)), loadDirectory(),
      attempt(() => api('GET', '/api/access-requests/incoming'))]);
    const items = grants ? grants.items : [];
    const here = inc ? inc.items.filter(r => r.document_id === doc.id) : [];
    if (here.length) right.push(waitingPanel(here, () => renderDocument(doc.id), 'Asking for access'));
    right.push(sharingPanel(doc, items, people));
    right.push(await linksPanel(doc, items));
    left.push(await activityPanel(doc));
    const label = labelSelect(doc.classification);
    const labelHelp = h('p', { class: 'muted small-help' }, LABEL_INFO[doc.classification][1]);
    label.addEventListener('change', () => { labelHelp.textContent = LABEL_INFO[label.value][1]; });
    right.push(h('section', { class: 'panel' }, h('h2', null, 'Classification'),
      h('form', { class: 'inline', onsubmit: async (e) => {
        e.preventDefault();
        if (label.value === doc.classification) return;
        if (label.value === 'confidential' && !window.confirm('Make it Confidential? Every outstanding share link to it stops working.')) return;
        if (await attempt(() => api('PUT', `/api/documents/${enc(doc.id)}/classification`, { classification: label.value }),
          'Classification changed')) renderDocument(doc.id);
      } }, field('Label', label), h('button', { type: 'submit' }, 'Save')), labelHelp));
  }
  if (isOwner) {
    right.push(h('section', { class: 'panel danger-zone' }, h('h2', null, trashed ? 'In the trash' : 'Danger zone'),
      trashed
        ? h('div', { class: 'stack' },
            h('p', { class: 'muted' }, 'Nobody you shared this with can open it while it is in the trash.'),
            h('div', { class: 'actions' }, h('button', { onclick: async () => {
              if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/restore`), 'Restored')) renderDocument(doc.id);
            } }, 'Restore'),
            h('button', { class: 'danger', onclick: async () => {
              if (!window.confirm('Destroy this document permanently? Its encryption keys are erased and it cannot be recovered.')) return;
              if (await attempt(() => api('DELETE', `/api/documents/${enc(doc.id)}/purge`), 'Destroyed')) location.hash = '#/trash';
            } }, 'Destroy permanently')))
        : h('div', { class: 'stack' },
            h('p', { class: 'muted' }, 'Moving to the trash stops every grant and share link immediately. You can restore it until retention runs out.'),
            h('div', null, h('button', { class: 'danger', onclick: async () => {
              if (!window.confirm('Move this document to the trash?')) return;
              if (await attempt(() => api('DELETE', '/api/documents/' + enc(doc.id)), 'Moved to trash')) location.hash = '#/documents';
            } }, 'Move to trash')))));
  }
  shell('documents', h('div', { class: 'grid two' }, h('div', { class: 'col' }, left), h('div', { class: 'col' }, right)));
}

async function openViewer(doc, box, link) {
  box.replaceChildren(loadingPanel('Rendering…'));
  const p = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/preview`, undefined, { link }));
  if (!p) { box.replaceChildren(); return; }
  const close = h('button', { class: 'small', type: 'button', onclick: () => box.replaceChildren() }, 'Close');
  const head = h('div', { class: 'panel-head' },
    h('h2', null, `Viewing v${p.version_no}`), close);
  const mark = h('p', { class: 'watermark-line' }, p.watermark);
  if (p.kind === 'text') {
    box.replaceChildren(h('section', { class: 'panel viewer' }, head, mark,
      h('pre', { class: 'doc-text' }, p.text || '(no text)'),
      p.truncated ? h('p', { class: 'muted' }, 'Preview truncated.') : null));
    return;
  }
  let page = 1;
  let objectUrl = null;
  const img = h('img', { class: 'page-img', alt: 'Rendered page', draggable: 'false' });
  const label = h('span', { class: 'muted num' });
  const prev = h('button', { class: 'small', type: 'button' }, '‹ Prev');
  const next = h('button', { class: 'small', type: 'button' }, 'Next ›');
  async function show() {
    label.textContent = `Page ${page} of ${p.pages}`;
    prev.disabled = page <= 1;
    next.disabled = page >= p.pages;
    // Fetched (not an <img src> URL) so the session - and a link token, if any - go in headers.
    const res = await rawFetch('GET', `/api/documents/${enc(doc.id)}/preview/pages/${page}`, undefined, { link });
    if (!res.ok) {
      let data = null;
      try { data = await res.json(); } catch (_) { /* not JSON */ }
      try { await handleError(res, data, {}); } catch (e) { reportError(e); }
      return;
    }
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    objectUrl = URL.createObjectURL(await res.blob());
    img.src = objectUrl;
  }
  prev.addEventListener('click', () => { if (page > 1) { page--; show(); } });
  next.addEventListener('click', () => { if (page < p.pages) { page++; show(); } });
  img.addEventListener('contextmenu', e => e.preventDefault());
  box.replaceChildren(h('section', { class: 'panel viewer' }, head, mark,
    h('div', { class: 'pager' }, label, prev, next), img));
  show();
}

async function loadDirectory() {
  if (!state.directory) {
    const d = await attempt(() => api('GET', '/api/users/directory'));
    state.directory = d ? d.items : [];
  }
  return state.directory;
}

function personSelect(people, placeholder = 'Choose a person…') {
  return h('select', { required: true }, h('option', { value: '' }, placeholder),
    people.map(p => h('option', { value: p.username }, `${p.display_name} (${p.username})${p.is_external ? ' — external' : ''}`)));
}

// Durations an owner can pick (spec: 5 min, 30 min, 1 hour, 1 day, 7 days or custom).
// The default comes from the server (DEFAULT_GRANT_MINUTES).
const DURATIONS = [[5, '5 minutes'], [30, '30 minutes'], [60, '1 hour'], [1440, '1 day'], [10080, '7 days']];

function sharingPanel(doc, grants, people) {
  const rows = grants.map(g => {
    const add = h('select', { class: 'compact', 'aria-label': `Add time for ${g.display_name}` },
      [[30, '+30 min'], [60, '+1 hour'], [1440, '+1 day'], [10080, '+7 days']].map(([m, t]) => h('option', { value: m }, t)));
    return h('tr', { class: g.expired ? 'expired-row' : '' },
      h('td', null, h('div', null, g.display_name), h('div', { class: 'cell-sub' },
        g.is_external ? badge('external', 'neutral') : null, !g.is_active ? badge('inactive') : null,
        g.source === 'suggestion' ? badge('suggested', 'neutral') : null),
        h('div', { class: 'row-actions grant-actions' },
        add, h('button', { class: 'small', type: 'button', onclick: async () => {
          if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/grants/${enc(g.id)}/extend`, { minutes: Number(add.value) }),
            `Access extended for ${g.display_name}`)) renderDocument(doc.id);
        } }, g.expired ? 'Renew' : 'Extend'),
        h('button', { class: 'small danger', type: 'button', onclick: async () => {
          if (await attempt(() => api('DELETE', `/api/documents/${enc(doc.id)}/grants/${enc(g.id)}`), `Access removed for ${g.display_name}`)) renderDocument(doc.id);
        } }, 'Revoke'))),
      h('td', null, permBadge(g.permission)),
      h('td', { class: 'num' }, g.expired ? badge('expired') : countdown(g.expires_at, { prefix: '', ended: 'Expired' })));
  });
  const person = personSelect(people);
  const perm = h('select', null, LEVELS.map(([v, label, help]) => h('option', { value: v, title: help }, label)));
  const permHelp = h('p', { class: 'muted small-help' }, LEVELS[0][2]);
  perm.addEventListener('change', () => { permHelp.textContent = (LEVELS.find(l => l[0] === perm.value) || LEVELS[0])[2]; });
  // Confidential: View only (the first level) for 1 hour unless the owner picks more.
  const defaultMinutes = doc.classification === 'confidential'
    ? ((state.meta && state.meta.confidential_grant_minutes) || 60)
    : ((state.meta && state.meta.default_grant_minutes) || 30);
  const duration = h('select', null,
    DURATIONS.map(([m, t]) => h('option', { value: m, selected: m === defaultMinutes }, t)),
    h('option', { value: 'custom' }, 'Custom…'));
  const until = h('input', { type: 'datetime-local', class: 'hidden', 'aria-label': 'Access ends at' });
  const untilField = field('Ends at', until);
  untilField.classList.add('hidden');
  duration.addEventListener('change', () => {
    const custom = duration.value === 'custom';
    until.classList.toggle('hidden', !custom);
    untilField.classList.toggle('hidden', !custom);
  });
  const form = h('form', { class: 'inline', onsubmit: async (e) => {
    e.preventDefault();
    if (!person.value) return;
    const body = { username: person.value, permission: perm.value };
    if (duration.value === 'custom') {
      if (!until.value) { toast('Pick when the access should end', true); return; }
      body.expires_at = new Date(until.value).toISOString();
    } else body.duration_minutes = Number(duration.value);
    if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/grants`, body), 'Access granted')) renderDocument(doc.id);
  } }, field('Person', person), field('Access', perm), field('For how long', duration), untilField,
  h('button', { class: 'primary', type: 'submit' }, 'Grant'), permHelp);

  const suggestBox = h('div');
  const suggestBtn = h('button', { class: 'small', type: 'button', onclick: async () => {
    const r = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/suggestions`));
    if (!r) return;
    if (!r.items.length) { suggestBox.replaceChildren(h('p', { class: 'muted' }, 'No suggestions: nothing in your own sharing history points to anyone.')); return; }
    suggestBox.replaceChildren(h('p', { class: 'callout neutral' }, r.note), ...r.items.map(s => h('div', { class: 'alert-item' },
      h('strong', null, s.display_name), ' ', s.is_external ? badge('external', 'neutral') : null, ' ', permBadge('view'),
      h('ul', { class: 'reasons' }, s.reasons.map(x => h('li', null, x))),
      h('div', { class: 'actions' },
        h('button', { class: 'small primary', onclick: async () => {
          if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/grants`, { username: s.username, permission: 'view', suggestion_id: s.suggestion_id }), `View access granted to ${s.display_name}`)) renderDocument(doc.id);
        } }, 'Confirm: grant view'),
        h('button', { class: 'small', onclick: async (e) => {
          if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/suggestions/${enc(s.suggestion_id)}/dismiss`))) e.target.closest('.alert-item').remove();
        } }, 'Dismiss')))));
  } }, '✦ Suggest people');

  return h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Who has access'), suggestBtn),
    suggestBox,
    table(['Person', 'Access', 'Time left'], rows, 'Only you can see this document.'),
    h('h3', { class: 'section-gap' }, 'Give someone access'), form);
}

async function linksPanel(doc, grants) {
  const ttl = (state.meta && state.meta.link_ttl_seconds) || 300;
  const minutes = Math.round(ttl / 60);
  const data = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/links`));
  const reveal = h('div');
  // A link only works for someone who already has live access, at most at their level.
  const holders = grants.filter(g => !g.expired && g.is_active);
  const rows = (data ? data.items : []).map(l => h('tr', null,
    h('td', null, l.recipient), h('td', null, permBadge(l.permission)),
    h('td', { class: 'num' }, l.status === 'active' ? countdown(l.expires_at, { prefix: '', ended: 'Expired' }) : badge(l.status === 'revoked' ? 'revoked' : 'expired')),
    h('td', null, l.opened ? 'Yes' : 'Not yet')));
  const person = h('select', { required: true }, h('option', { value: '' }, holders.length ? 'Choose a person…' : 'Give someone access first'),
    holders.map(g => h('option', { value: g.username }, `${g.display_name} (${levelLabel(g.permission)})`)));
  const level = h('select', null);
  function fillLevels() {
    const g = holders.find(x => x.username === person.value);
    const allowed = !g || g.permission === 'view' ? [['view', 'View only']] : [['view', 'View only'], ['download', 'View + download']];
    level.replaceChildren(...allowed.map(([v, t]) => h('option', { value: v }, t)));
  }
  person.addEventListener('change', fillLevels);
  fillLevels();
  const form = h('form', { class: 'inline', onsubmit: async (e) => {
    e.preventDefault();
    if (!person.value) return;
    const r = await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/links`, { username: person.value, permission: level.value }), 'Link created');
    if (!r) return;
    const url = location.origin + r.path;
    reveal.replaceChildren(h('div', { class: 'callout info stack' },
      h('div', null, icon('link'), h('strong', null, `For ${r.recipient} only, signed in. `),
        countdown(r.expires_at, { prefix: 'Expires in ', ended: 'Expired' })),
      h('div', { class: 'secret' }, url),
      h('div', null, h('button', { class: 'small', type: 'button', onclick: async () => {
        try { await navigator.clipboard.writeText(url); toast('Copied'); } catch (_) { toast('Copy failed - select the text instead', true); }
      } }, 'Copy link'))));
  } }, field('Person', person), field('Access', level), h('button', { type: 'submit', disabled: !holders.length }, 'Create link'));
  const revokeAll = h('button', { class: 'small danger', type: 'button', onclick: async () => {
    if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/links/revoke-all`), 'Every link to this document stopped working')) renderDocument(doc.id);
  } }, 'Revoke all links');
  return h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, `Share link · ${minutes} min`), revokeAll),
    h('p', { class: 'muted small-help' }, `For someone who already has access: opens this document for ${minutes} minutes, only for them, signed in. `,
      'Revoking any access, or "Revoke all links", stops every link at once.'),
    reveal, form,
    data && data.items.length ? table(['For', 'Access', 'Expires', 'Opened'], rows) : null);
}

// Plain words for the owner's activity list. The internal refusal reasons are
// not sent to owners at all - only administrators see them.
const ACTION_WORDS = {
  'document.upload': 'Uploaded', 'document.view': 'Opened details', 'document.preview': 'Opened viewer',
  'document.preview_page': 'Viewed a page', 'document.download': 'Downloaded', 'document.version_download': 'Downloaded a version',
  'document.version_upload': 'Uploaded a new version', 'document.update': 'Changed details', 'document.delete': 'Moved to trash',
  'document.restore': 'Restored', 'document.activity': 'Viewed activity', 'access.granted': 'Gave access',
  'access.changed': 'Changed access', 'access.extended': 'Extended access', 'access.revoked': 'Revoked access',
  'access.expired': 'Access expired', 'link.created': 'Made a share link', 'link.opened': 'Opened a share link',
  'link.revoked_all': 'Revoked all links', 'ai.suggestion.generated': 'Asked for suggestions',
  'ai.suggestion.accepted': 'Accepted a suggestion', 'ai.suggestion.dismissed': 'Dismissed a suggestion',
  'document.classified': 'Changed the label', 'access.requested': 'Asked for access',
  'access.request_approved': 'Approved a request', 'access.request_denied': 'Denied a request',
  'access.request_withdrawn': 'Withdrew a request',
};
const actionWords = a => ACTION_WORDS[a] || a;

async function activityPanel(doc) {
  const data = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/activity?limit=50`));
  const rows = (data ? data.items : []).map(a => h('tr', null,
    h('td', { class: 'num' }, fmtDate(a.ts)), h('td', null, a.actor_name || 'system'), h('td', null, actionWords(a.action)),
    h('td', null, badge(a.outcome === 'info' ? 'recorded' : a.outcome, a.outcome === 'info' ? 'neutral' : undefined))));
  return h('section', { class: 'panel' }, h('h2', null, 'Activity'),
    table(['When', 'Who', 'What', 'Outcome'], rows, 'No activity yet.'));
}

// ------------------------------------------------------------------ account
async function renderAccount() {
  const title = () => h('div', { class: 'page-head' }, h('h1', null, 'Account'));
  shell('account', title(), loadingPanel());
  const [tf, sessions] = await Promise.all([attempt(() => api('GET', '/api/auth/2fa')), attempt(() => api('GET', '/api/auth/sessions'))]);
  if (!tf || !sessions) { shell('account', title(), errorPanel(renderAccount)); return; }

  // --- password
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const next = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 12 });
  const pwForm = h('form', { class: 'stack', onsubmit: async (e) => {
    e.preventDefault();
    if (await attempt(() => api('POST', '/api/auth/change-password', { current_password: cur.value, new_password: next.value }),
      'Password changed. Your other sessions were signed out.')) { cur.value = ''; next.value = ''; renderAccount(); }
  } }, field('Current password', cur), field('New password (12+ characters)', next),
  h('div', null, h('button', { class: 'primary', type: 'submit' }, 'Change password')));
  const s = state.session;

  // --- two-step sign-in
  const flow = h('div');
  const who = state.user.username;
  function done(message) { toast(message); renderAccount(); }
  function startSetup() {
    const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    flow.replaceChildren(h('form', { class: 'stack narrow-form', onsubmit: async (e) => {
      e.preventDefault();
      const offer = await attempt(() => api('POST', '/api/auth/2fa/setup', { password: pw.value }));
      if (offer) confirmSetup(offer);
    } }, h('p', null, 'First, confirm it is you.'), field('Your password', pw),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Continue'),
        h('button', { type: 'button', onclick: () => flow.replaceChildren() }, 'Cancel'))));
    pw.focus();
  }
  function confirmSetup(offer) {
    const [label, input] = codeInput('The 6-digit code the app now shows');
    flow.replaceChildren(h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      const r = await attempt(() => api('POST', '/api/auth/2fa/enable', { code: input.value.trim() }));
      if (r) showCodes(r.backup_codes, 'Two-step sign-in is on.' + (r.other_sessions_revoked ? ` ${r.other_sessions_revoked} other session(s) were signed out.` : ''));
      else { input.value = ''; input.focus(); }
    } }, h('p', null, 'Scan this with your authenticator app (or type the key), then enter the code it shows.'
        + (tf.enabled ? ' Your old phone stops working once this is confirmed.' : '')),
      setupKeyBlock(offer), h('div', { class: 'narrow-form' }, label),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Turn on'),
        h('button', { type: 'button', onclick: () => flow.replaceChildren() }, 'Cancel'))));
    input.focus();
  }
  function showCodes(codes, headline) {
    flow.replaceChildren(h('div', { class: 'callout info stack' }, h('strong', null, headline),
      h('span', null, 'Save these backup codes now - they are shown only once. Each signs you in once without your phone.'),
      backupCodesBlock(codes, who),
      h('div', { class: 'actions' }, h('button', { type: 'button', class: 'primary', onclick: () => done('Backup codes saved') }, 'Done'))));
  }
  function newCodes() {
    const [label, input] = codeInput();
    flow.replaceChildren(h('form', { class: 'stack narrow-form', onsubmit: async (e) => {
      e.preventDefault();
      const r = await attempt(() => api('POST', '/api/auth/2fa/backup-codes', { code: input.value.trim() }));
      if (r) showCodes(r.backup_codes, 'New backup codes. The old ones no longer work.');
    } }, label, h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Make new codes'),
      h('button', { type: 'button', onclick: () => flow.replaceChildren() }, 'Cancel'))));
    input.focus();
  }
  function turnOff() {
    const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const [label, input] = codeInput('A code from the app, or a backup code');
    flow.replaceChildren(h('form', { class: 'stack narrow-form', onsubmit: async (e) => {
      e.preventDefault();
      if (await attempt(() => api('POST', '/api/auth/2fa/disable', { password: pw.value, code: input.value.trim() }))) done('Two-step sign-in is off');
    } }, field('Your password', pw), label,
      h('div', { class: 'actions' }, h('button', { class: 'danger', type: 'submit' }, 'Turn off'),
        h('button', { type: 'button', onclick: () => flow.replaceChildren() }, 'Cancel'))));
    pw.focus();
  }
  const twoStep = h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Two-step sign-in'),
      tf.enabled ? badge('on', 'ok') : badge('off', tf.required ? 'bad' : 'neutral')),
    h('p', { class: 'muted' }, tf.enabled
      ? `Signing in needs your password and a code from your phone. On since ${fmtDay(tf.enabled_at)}.`
      : 'Signing in needs only your password. Turn this on so a stolen password is not enough.'),
    tf.required ? h('p', { class: 'callout info' }, icon('shield'), 'Required for your role - it cannot be turned off.') : null,
    tf.enabled ? h('p', { class: tf.backup_codes_left <= 2 ? 'callout danger' : 'muted' },
      `${tf.backup_codes_left} backup code${tf.backup_codes_left === 1 ? '' : 's'} left.`) : null,
    h('div', { class: 'actions' },
      tf.enabled
        ? [h('button', { type: 'button', onclick: startSetup }, 'Move to a new phone'),
           h('button', { type: 'button', onclick: newCodes }, 'New backup codes'),
           tf.required ? null : h('button', { type: 'button', class: 'danger', onclick: turnOff }, 'Turn off')]
        : h('button', { type: 'button', class: 'primary', onclick: startSetup }, icon('shield'), 'Set up two-step sign-in')),
    flow);

  // --- sessions
  async function endSession(item) {
    const r = await attempt(() => api('DELETE', '/api/auth/sessions/' + enc(item.id)));
    if (!r) return;
    if (r.signed_out_here) { forgetUser(); state.notice = 'You signed out of this session.'; location.hash = '#/login'; return; }
    toast(`Signed out: ${item.device}`);
    renderAccount();
  }
  const sessionRows = sessions.items.map(i => h('tr', null,
    h('td', null, h('div', { class: 'cell-title' }, icon(/iOS|Android/.test(i.device) ? 'phone' : 'monitor'), h('strong', null, i.device)),
      i.current ? h('div', { class: 'cell-sub' }, badge('this device', 'ok')) : null),
    h('td', { class: 'mono nowrap' }, i.ip || '—'),
    h('td', { class: 'num' }, fmtDate(i.created_at)),
    h('td', { class: 'num' }, i.current ? 'now' : fmtDate(i.last_seen_at)),
    h('td', { class: 'right' }, h('button', { type: 'button', class: 'small', onclick: () => endSession(i) }, i.current ? 'Sign out here' : 'Sign out'))));
  const everywhere = h('button', { type: 'button', class: 'small danger', onclick: async () => {
    if (!window.confirm('Sign out on every device, this one included?')) return;
    const r = await attempt(() => api('POST', '/api/auth/sessions/sign-out-everywhere'));
    if (r) { forgetUser(); state.notice = `Signed out everywhere (${r.sessions_ended} session${r.sessions_ended === 1 ? '' : 's'}).`; location.hash = '#/login'; }
  } }, 'Sign out everywhere');

  shell('account', title(),
    h('div', { class: 'grid two' },
      h('section', { class: 'panel' }, h('dl', { class: 'meta' },
        h('dt', null, 'Name'), h('dd', null, state.user.display_name),
        h('dt', null, 'Username'), h('dd', null, state.user.username),
        h('dt', null, 'Role'), h('dd', null, roleBadge(state.user.role)),
        s ? [h('dt', null, 'This sign-in'), h('dd', null, countdown(s.expires_at, { prefix: 'ends in ', ended: 'ending now' }),
          h('div', { class: 'muted small-help' }, `or after ${Math.round(s.idle_timeout_seconds / 60)} minutes without activity`))] : null)),
      h('section', { class: 'panel' }, h('h2', null, 'Change password'), pwForm)),
    twoStep,
    h('section', { class: 'panel' },
      h('div', { class: 'panel-head' }, h('h2', null, 'Where you are signed in'), everywhere),
      h('p', { class: 'muted small-help' }, 'Signing a session out ends it on the server at once - the next click on that device asks for the password again.'),
      table(['Device', 'IP address', 'Signed in', 'Last active', ''], sessionRows)));
}

// -------------------------------------------------------------------- admin
async function renderAdmin() {
  shell('admin', h('div', { class: 'page-head' }, h('h1', null, 'Overview')), loadingPanel());
  const [stats, alerts] = await Promise.all([attempt(() => api('GET', '/api/admin/stats')),
    attempt(() => api('GET', '/api/admin/alerts?hours=24'))]);
  if (!stats || !alerts) { shell('admin', h('div', { class: 'page-head' }, h('h1', null, 'Overview')), errorPanel(renderAdmin)); return; }
  const tiles = [['Active users', stats.users], ['Documents', stats.documents], ['Live grants', stats.grants],
    ['Ending within 24 h', stats.expiring_24h], ['Links made today', stats.links_today], ['Events today', stats.events_today],
    ['Refused today', stats.denied_today, stats.denied_today ? 'bad' : ''], ['Downloads today', stats.downloads_today], ['In trash', stats.in_trash]];
  const integ = alerts.integrity;
  const verifyOut = h('div');
  shell('admin',
    h('div', { class: 'page-head' }, h('h1', null, 'Overview')),
    h('div', { class: 'grid stats' }, tiles.map(([l, n, tone]) => h('div', { class: 'stat ' + (tone || '') }, h('div', { class: 'n num' }, n), h('div', { class: 'l' }, l)))),
    h('div', { class: 'grid two' },
      h('section', { class: 'panel' }, h('h2', null, 'Worth noticing · last 24 h'),
        alerts.items.length ? alerts.items.map(a => h('div', { class: 'alert-item ' + a.severity },
          h('div', { class: 'alert-title' }, badge(a.severity), h('strong', null, a.title)),
          h('div', null, a.detail), h('div', { class: 'muted num small-help' }, `${fmtDate(a.first_seen)} → ${fmtDate(a.last_seen)}`)))
          : h('p', { class: 'empty-note' }, 'Nothing unusual in the last 24 hours.')),
      h('section', { class: 'panel' }, h('h2', null, 'Audit trail integrity'),
        h('p', { class: integ.ok ? 'callout info' : 'callout danger' },
          integ.ok ? `${integ.message} · ${integ.anchors_checked} external anchors.` : integ.message),
        integ.warnings.length ? h('p', { class: 'callout danger' }, integ.warnings.join('; ')) : null,
        h('div', { class: 'actions' }, h('button', { type: 'button', onclick: async () => {
          const r = await attempt(() => api('GET', '/api/admin/audit/verify'));
          if (r) verifyOut.replaceChildren(h('p', { class: r.ok ? 'callout info' : 'callout danger' }, `Just now: ${r.message}`));
        } }, icon('shield'), 'Verify integrity'), h('a', { class: 'btn', href: '#/admin/audit' }, 'Open the audit trail')), verifyOut,
        h('p', { class: 'muted small-help' }, 'Each entry is chained to the previous one with an HMAC whose key is not stored in the database, and the newest hash is anchored outside the database after every write.'))));
}

async function renderAdminUsers() {
  shell('users', h('div', { class: 'page-head' }, h('h1', null, 'Users')), loadingPanel());
  const data = await attempt(() => api('GET', '/api/admin/users'));
  if (!data) { shell('users', h('div', { class: 'page-head' }, h('h1', null, 'Users')), errorPanel(renderAdminUsers)); return; }
  const rows = data.items.map(u => {
    const role = h('select', { class: 'compact', 'aria-label': `Role for ${u.username}` },
      ['admin', 'owner', 'viewer'].map(r => h('option', { value: r, selected: r === u.role }, r)));
    const self = u.id === state.user.id;
    const deleted = !!u.deleted_at;
    const locked = u.locked_until && u.locked_until > new Date().toISOString();
    const status = deleted ? badge('deleted') : u.is_active ? badge('active') : badge('inactive');
    return h('tr', { class: deleted ? 'deleted-row' : '' },
      h('td', null, h('strong', null, u.username), h('div', { class: 'muted small-help' }, u.display_name)),
      h('td', null, self || deleted ? roleBadge(u.role) : role),
      h('td', null, h('div', { class: 'cell-sub' }, status, u.two_factor ? badge('2-step', 'ok') : null,
        u.is_external ? badge('external', 'neutral') : null, locked ? badge('locked') : null)),
      h('td', { class: 'num' }, String(u.active_sessions)), h('td', { class: 'num' }, `${u.owned_documents} / ${u.grants_held}`),
      h('td', null, self ? h('span', { class: 'muted' }, 'you') : deleted ? h('span', { class: 'muted num' }, `deleted ${fmtDay(u.deleted_at)}`) : h('div', { class: 'row-actions' },
        h('button', { class: 'small', onclick: async () => {
          if (await attempt(() => api('PATCH', '/api/admin/users/' + enc(u.id), { role: role.value }), 'Role updated')) renderAdminUsers();
        } }, 'Save role'),
        h('button', { class: u.is_active ? 'small danger' : 'small', onclick: async () => {
          if (u.is_active && !window.confirm(`Deactivate ${u.username}? All their sessions, grants and links stop working now.`)) return;
          if (await attempt(() => api('PATCH', '/api/admin/users/' + enc(u.id), { is_active: !u.is_active }), u.is_active ? 'Deactivated' : 'Activated')) renderAdminUsers();
        } }, u.is_active ? 'Deactivate' : 'Activate'),
        h('details', { class: 'menu' }, h('summary', { class: 'btn small' }, 'More'),
          h('div', { class: 'menu-items' },
            h('button', { class: 'small', onclick: async () => {
              const pw = window.prompt(`New password for ${u.username} (12+ characters):`);
              if (pw) await attempt(() => api('POST', `/api/admin/users/${enc(u.id)}/reset-password`, { new_password: pw }), 'Password reset; sessions ended');
            } }, 'Reset password'),
            h('button', { class: 'small', onclick: async () => {
              if (await attempt(() => api('POST', `/api/admin/users/${enc(u.id)}/unlock`), 'Unlocked')) renderAdminUsers();
            } }, 'Unlock'),
            h('button', { class: 'small', onclick: async () => {
              if (await attempt(() => api('POST', `/api/admin/users/${enc(u.id)}/revoke-sessions`), 'Signed out everywhere')) renderAdminUsers();
            } }, 'Sign out everywhere'),
            u.two_factor ? h('button', { class: 'small', onclick: async () => {
              if (!window.confirm(`Reset two-step sign-in for ${u.username}? Only do this if they lost their phone. They are signed out` +
                                  (u.role === 'viewer' ? '.' : ' and must set it up again at their next sign-in.'))) return;
              if (await attempt(() => api('POST', `/api/admin/users/${enc(u.id)}/reset-2fa`), 'Two-step sign-in reset')) renderAdminUsers();
            } }, 'Reset two-step sign-in') : null,
            h('button', { class: 'small danger', onclick: async () => {
              if (!window.confirm(`Delete ${u.username} permanently? They can never sign in again, and all their access is removed. ` +
                                  'The account record is kept so the audit trail still shows who did what.')) return;
              if (await attempt(() => api('DELETE', '/api/admin/users/' + enc(u.id)), 'User deleted')) renderAdminUsers();
            } }, 'Delete user'))))));
  });
  const un = h('input', { required: true, maxlength: 32, pattern: '[A-Za-z0-9._-]+' });
  const dn = h('input', { required: true, maxlength: 80 });
  const rl = h('select', null, ['viewer', 'owner', 'admin'].map(r => h('option', { value: r }, r)));
  const pw = h('input', { type: 'password', required: true, minlength: 12, autocomplete: 'new-password' });
  const ext = h('input', { type: 'checkbox' });
  const form = h('form', { class: 'inline', onsubmit: async (e) => {
    e.preventDefault();
    if (await attempt(() => api('POST', '/api/admin/users', { username: un.value, display_name: dn.value, role: rl.value, password: pw.value, is_external: ext.checked }), 'User created')) renderAdminUsers();
  } }, field('Username', un), field('Display name', dn), field('Role', rl), field('Initial password', pw),
  h('label', { class: 'check' }, ext, h('span', null, 'External')), h('button', { class: 'primary', type: 'submit' }, 'Create user'));
  shell('users', h('div', { class: 'page-head' }, h('h1', null, 'Users')),
    h('section', { class: 'panel flush' }, table(['User', 'Role', 'Status', 'Sessions', 'Owns / live grants', ''], rows)),
    h('section', { class: 'panel' }, h('h2', null, 'Create user'), form));
}

// ---------------------------------------------------------------- audit page
// Filters: an action dropdown filled from the actions actually in the trail,
// a denial-reason dropdown, quick filters, free-text actor and document id,
// dates. A row's plain-language summary has its raw JSON one click away;
// clicking the row opens the detail panel (full event, hashes, its session).
let drawer = null;

function closeDrawer() {
  if (!drawer) return;
  const back = drawer.returnTo;
  drawer.el.remove();
  document.removeEventListener('keydown', drawer.onKey);
  document.body.classList.remove('no-scroll');
  drawer = null;
  if (back && document.body.contains(back)) back.focus();
}

function checkLine(ok, yes, no) {
  return h('div', { class: 'check-line ' + (ok ? 'ok' : 'bad') }, icon(ok ? 'check' : 'x'), ok ? yes : no);
}

async function renderAdminAudit() {
  const title = () => h('div', { class: 'page-head' }, h('h1', null, 'Audit trail'));
  shell('audit', title(), loadingPanel());
  const opts = await attempt(() => api('GET', '/api/admin/audit/options'));
  if (!opts) { shell('audit', title(), errorPanel(renderAdminAudit)); return; }

  const presets = new Set();
  const CATEGORY = ['downloads', 'sharing', 'expired'];  // one category at a time
  let page = 1;
  let session = null;  // "show this session in the table"

  // --- filter controls
  const groupLabel = g => opts.groups[g] || 'Other';
  const groups = [...new Set(opts.actions.map(a => a.group))];
  const action = h('select', { name: 'action' }, h('option', { value: '' }, 'Any action'),
    groups.map(g => {
      const items = opts.actions.filter(a => a.group === g);
      return h('optgroup', { label: groupLabel(g) },
        items.length > 1 ? h('option', { value: g + '.' }, `All: ${groupLabel(g).toLowerCase()}`) : null,
        items.map(a => h('option', { value: a.action }, `${a.label} (${a.action}) · ${a.count}`)));
    }));
  const outcome = h('select', { name: 'outcome' }, h('option', { value: '' }, 'Any'),
    ['allowed', 'denied', 'error', 'info'].map(o => h('option', { value: o }, o)));
  const reason = h('select', { name: 'reason' }, h('option', { value: '' }, 'Any reason'),
    opts.reasons.map(r => h('option', { value: r.reason }, `${r.label} (${r.reason}) · ${r.count}`)));
  const actor = h('input', { name: 'actor', placeholder: 'username', maxlength: 64, autocomplete: 'off' });
  const docId = h('input', { name: 'document_id', placeholder: 'document id', maxlength: 64, autocomplete: 'off' });
  const from = h('input', { type: 'date', name: 'date_from' });
  const to = h('input', { type: 'date', name: 'date_to' });

  const chips = opts.presets.map(p => h('button', {
    type: 'button', class: 'chip' + (p.key === 'denied' ? ' rose' : ''), 'aria-pressed': 'false', title: p.description,
    'data-preset': p.key, onclick: () => togglePreset(p.key) }, p.label));
  function togglePreset(key) {
    if (presets.has(key)) presets.delete(key);
    else {
      if (CATEGORY.includes(key)) CATEGORY.forEach(k => presets.delete(k));
      presets.add(key);
    }
    for (const c of chips) c.setAttribute('aria-pressed', String(presets.has(c.dataset.preset)));
    // "Denied only" is the same thing as Outcome = denied: show it there too.
    outcome.disabled = presets.has('denied');
    if (presets.has('denied')) outcome.value = 'denied';
    else if (outcome.value === 'denied' && key === 'denied') outcome.value = '';
    page = 1; load();
  }

  function params(withPage = true) {
    const p = new URLSearchParams();
    if (withPage) { p.set('page', String(page)); p.set('page_size', '50'); }
    if (action.value) p.set('action', action.value);
    if (outcome.value && !presets.has('denied')) p.set('outcome', outcome.value);
    if (reason.value) p.set('reason', reason.value);
    if (actor.value.trim()) p.set('actor', actor.value.trim());
    if (docId.value.trim()) p.set('document_id', docId.value.trim());
    if (from.value) p.set('date_from', from.value);
    if (to.value) p.set('date_to', to.value);
    if (session) p.set('session', session);
    for (const k of presets) p.append('preset', k);
    return p.toString();
  }

  function clearAll(thenSession = null) {
    for (const el of [action, outcome, reason, actor, docId, from, to]) el.value = '';
    presets.clear(); outcome.disabled = false;
    for (const c of chips) c.setAttribute('aria-pressed', 'false');
    session = thenSession; page = 1; load();
  }

  // --- results
  const out = h('div', null, loadingPanel());
  const sessionNote = h('div');

  function eventRows(e) {
    const raw = h('tr', { class: 'detail-row hidden' }, h('td', { colspan: 7 },
      h('div', { class: 'raw-label' }, `Raw details of event #${e.seq}`),
      h('pre', { class: 'json' }, JSON.stringify(e.details, null, 2))));
    const jsonBtn = h('button', { type: 'button', class: 'small ghost json-toggle', 'aria-expanded': 'false',
      'aria-label': `Raw JSON of event ${e.seq}`, onclick: (ev) => {
        ev.stopPropagation();
        const open = raw.classList.toggle('hidden') === false;
        jsonBtn.setAttribute('aria-expanded', String(open));
        jsonBtn.textContent = open ? 'Hide JSON' : '{ } JSON';
      } }, '{ } JSON');
    const row = h('tr', { class: 'clickable' + (e.outcome === 'denied' || e.outcome === 'error' ? ' refused' : ''), tabindex: '0',
      'aria-label': `Event ${e.seq}: ${e.summary}. Press Enter for details.`,
      onclick: () => openEvent(e.seq, row),
      onkeydown: (ev) => { if (ev.target === row && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); openEvent(e.seq, row); } } },
      h('td', { class: 'mono nowrap' }, '#' + e.seq),
      h('td', { class: 'num nowrap' }, fmtDate(e.ts)),
      h('td', { class: 'who-cell' }, e.actor_name || h('span', { class: 'muted' }, 'system')),
      h('td', null, h('div', null, e.action_label), h('div', { class: 'code nowrap' }, e.action)),
      h('td', null, badge(e.outcome)),
      h('td', { class: 'summary-cell' }, h('span', { class: 'summary' }, e.summary), ' ', jsonBtn),
      h('td', { class: 'mono nowrap' }, e.ip || ''));
    return [row, raw];
  }

  async function load() {
    out.replaceChildren(loadingPanel());
    sessionNote.replaceChildren(session ? h('div', { class: 'callout info' }, icon('link'),
      h('span', null, 'Showing one sign-in session only: ', h('span', { class: 'mono' }, session)),
      h('button', { type: 'button', class: 'small', onclick: () => { session = null; page = 1; load(); } }, 'Show all sessions')) : '');
    const data = await attempt(() => api('GET', '/api/admin/audit?' + params()));
    if (!data) { out.replaceChildren(errorPanel(load)); return; }
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    out.replaceChildren(
      table(['#', 'When', 'Who', 'Action', 'Outcome', 'What happened', 'IP'], data.items.flatMap(eventRows),
            'No events match these filters.'),
      h('div', { class: 'pager' },
        h('span', { class: 'muted num' }, `${data.total.toLocaleString()} event${data.total === 1 ? '' : 's'} · page ${page} of ${pages} · click a row for the full event`),
        h('button', { type: 'button', class: 'small', disabled: page <= 1, onclick: () => { page--; load(); } }, '‹ Newer'),
        h('button', { type: 'button', class: 'small', disabled: page >= pages, onclick: () => { page++; load(); } }, 'Older ›')));
  }

  // --- detail panel
  async function openEvent(seq, returnTo) {
    if (!drawer) {
      const body = h('div', { class: 'drawer-body' });
      const panel = h('aside', { class: 'drawer', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'drawer-title' }, body);
      const el = h('div', { class: 'drawer-backdrop', onclick: (ev) => { if (ev.target === el) closeDrawer(); } }, panel);
      const onKey = (ev) => { if (ev.key === 'Escape') closeDrawer(); };
      document.addEventListener('keydown', onKey);
      document.body.append(el);
      document.body.classList.add('no-scroll');
      drawer = { el, body, onKey, returnTo };
    }
    drawer.body.replaceChildren(loadingPanel('Loading event…'));
    const d = await attempt(() => api('GET', `/api/admin/audit/events/${seq}`));
    if (!drawer) return;
    if (!d) { drawer.body.replaceChildren(errorPanel(() => openEvent(seq))); return; }
    const e = d.event;
    const reasonCode = e.details && e.details.reason;
    const close = h('button', { type: 'button', class: 'small ghost', 'aria-label': 'Close the event details', onclick: closeDrawer }, icon('x'), 'Close');
    const sameSession = d.session
      ? h('section', null,
          h('h3', null, `Same sign-in session · ${d.session.total} event${d.session.total === 1 ? '' : 's'}`),
          h('ol', { class: 'session-list' }, d.session.events.map(x => h('li', null,
            h('button', { type: 'button', 'aria-current': x.seq === e.seq ? 'true' : null, onclick: () => openEvent(x.seq) },
              h('span', { class: 'seq' }, '#' + x.seq), h('span', { class: 'when num' }, fmtTime(x.ts)),
              h('span', { class: 'what' }, x.summary), badge(x.outcome))))),
          d.session.truncated ? h('p', { class: 'muted small-help' }, 'Showing the first 200 events of this session.') : null,
          h('div', { class: 'actions section-gap' }, h('button', { type: 'button', class: 'small', onclick: () => {
            closeDrawer(); clearAll(d.session.ref);  // the whole session, whatever was filtered before
          } }, 'Show this session in the table')))
      : h('section', null, h('h3', null, 'Same sign-in session'),
          h('p', { class: 'muted' }, 'This event is not part of a sign-in session (for example a failed sign-in, or something the system did by itself).'));
    drawer.body.replaceChildren(
      h('div', { class: 'drawer-head' },
        h('div', null, h('div', { class: 'drawer-kicker' }, badge(e.outcome), h('span', { class: 'mono' }, '#' + e.seq), h('span', { class: 'muted num' }, fmtDate(e.ts))),
          h('h2', { id: 'drawer-title' }, e.summary)),
        close),
      h('section', null, h('h3', null, 'Event'),
        h('dl', { class: 'meta' },
          h('dt', null, 'Action'), h('dd', null, e.action_label, ' ', h('span', { class: 'code' }, e.action)),
          h('dt', null, 'When'), h('dd', null, fmtDate(e.ts), h('div', { class: 'code' }, e.ts)),
          h('dt', null, 'Who'), h('dd', null, e.actor_name || 'system', e.actor_id ? h('div', { class: 'code' }, e.actor_id) : null),
          reasonCode ? [h('dt', null, 'Reason'), h('dd', null, badge(reasonCode, 'bad'))] : null,
          e.document_id ? [h('dt', null, 'Document'), h('dd', null, e.document_name || 'not found', h('div', { class: 'code' }, e.document_id))] : null,
          e.target_username || e.target_user_id ? [h('dt', null, 'Person affected'), h('dd', null, e.target_username || '—', e.target_user_id ? h('div', { class: 'code' }, e.target_user_id) : null)] : null,
          h('dt', null, 'IP address'), h('dd', { class: 'mono' }, e.ip || '—'),
          h('dt', null, 'User agent'), h('dd', { class: 'mono' }, e.user_agent || '—'),
          h('dt', null, 'Session'), h('dd', { class: 'mono' }, e.session_ref || '—'))),
      h('section', null, h('h3', null, 'Integrity'),
        checkLine(d.integrity.hash_matches, 'Its hash matches its content', 'Its hash does NOT match its content: this event was changed'),
        checkLine(d.integrity.links_to_previous, e.seq === 1 ? 'It is the first event (genesis)' : `It links to event #${e.seq - 1}`,
          e.seq === 1 ? 'It does not start from the genesis value' : `It does NOT link to event #${e.seq - 1}`),
        h('dl', { class: 'meta hashes' },
          h('dt', null, 'Hash'), h('dd', { class: 'mono' }, e.entry_hash),
          h('dt', null, 'Previous hash'), h('dd', { class: 'mono' }, e.prev_hash)),
        h('p', { class: 'muted small-help' }, 'This checks one event. “Verify integrity” checks the whole chain and the external anchors.')),
      h('section', null, h('h3', null, 'Raw details'), h('pre', { class: 'json raw' }, JSON.stringify(e.details, null, 2))),
      sameSession);
    close.focus();
  }

  // --- verify and export
  const notice = h('div', { 'aria-live': 'polite' });
  const verifyBtn = h('button', { type: 'button', onclick: async () => {
    verifyBtn.disabled = true;
    const r = await attempt(() => api('GET', '/api/admin/audit/verify'));
    verifyBtn.disabled = false;
    if (!r) return;
    notice.replaceChildren(h('div', { class: 'callout ' + (r.ok ? 'info' : 'danger') },
      icon(r.ok ? 'shield' : 'alert'), h('strong', null, r.message),
      r.ok ? h('span', { class: 'muted' }, `${r.anchors_checked} external anchors checked`) : null,
      r.warnings.length ? h('span', null, r.warnings.join('; ')) : null));
    load();  // the verification itself is now the newest event
  } }, icon('shield'), 'Verify integrity');

  const exportBtn = h('button', { type: 'button', class: 'primary', onclick: async () => {
    exportBtn.disabled = true;
    try {
      const res = await rawFetch('GET', '/api/admin/audit/export?' + params(false));
      if (!res.ok) {
        let data = null;
        try { data = await res.json(); } catch (_) { /* not JSON */ }
        await handleError(res, data, {});
      }
      const blob = await res.blob();
      const sha = res.headers.get('X-Content-SHA256') || '';
      const rows = Number(res.headers.get('X-Export-Rows') || 0);
      const name = fileNameOf(res, 'trustvault-audit.csv');
      let matches = null;  // recomputed here when the browser allows it (HTTPS or localhost)
      if (window.crypto && window.crypto.subtle) {
        const digest = await window.crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
        matches = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('') === sha;
      }
      saveBlob(blob, name);
      notice.replaceChildren(h('div', { class: 'callout ' + (matches === false ? 'danger' : 'info') + ' stack' },
        h('strong', null, `Exported ${rows.toLocaleString()} event${rows === 1 ? '' : 's'} to ${name}`),
        h('div', null, 'SHA-256 of the file: ', h('span', { class: 'mono' }, sha)),
        matches === null ? h('div', { class: 'muted' }, `Check it later with: certutil -hashfile ${name} SHA256`)
          : h('div', null, matches ? 'Recomputed in your browser: the saved file has exactly this hash.'
                                    : 'The saved file does NOT match the hash the server sent. Export again.'),
        h('div', { class: 'muted small-help' }, 'The export and its hash are written to the audit trail, so this file can be shown to be unchanged later.'),
        h('div', { class: 'actions' }, h('button', { type: 'button', class: 'small', onclick: () =>
          saveBlob(new Blob([`${sha}  ${name}\n`], { type: 'text/plain' }), name + '.sha256') }, 'Save checksum file'))));
      load();
    } catch (e) { reportError(e); } finally { exportBtn.disabled = false; }
  } }, icon('download'), 'Export CSV');

  const form = h('form', { class: 'filters audit-filters', onsubmit: (e) => { e.preventDefault(); page = 1; load(); } },
    field('Action', action), field('Outcome', outcome), field('Denial reason', reason), field('Actor', actor),
    field('Document id', docId), field('From', from), field('To', to),
    h('div', { class: 'filter-buttons' }, h('button', { class: 'primary', type: 'submit' }, 'Filter'),
      h('button', { type: 'button', onclick: () => clearAll() }, 'Clear')));
  // Picking from a dropdown applies at once; typed fields wait for "Filter".
  for (const el of [action, outcome, reason, from, to]) el.addEventListener('change', () => { page = 1; load(); });

  shell('audit',
    h('div', { class: 'page-head' }, h('h1', null, 'Audit trail'), h('div', { class: 'actions' }, verifyBtn, exportBtn)),
    notice,
    h('section', { class: 'panel' },
      h('div', { class: 'chips', role: 'group', 'aria-label': 'Quick filters' }, h('span', { class: 'chips-label' }, 'Quick filters'), chips),
      // On a phone the full filter form starts folded so the events stay in view.
      h('details', { class: 'filter-more', open: window.matchMedia('(min-width: 641px)').matches },
        h('summary', null, 'All filters'), form)),
    sessionNote,
    h('section', { class: 'panel flush' }, out),
    h('p', { class: 'muted small-help' }, 'Export uses the filters above. Every event is chained to the one before it with a keyed hash; the newest hash is also anchored outside the database.'));
  load();
}

function unusedAccessPanel(review) {
  const chosen = new Set(review.items.filter(i => i.flagged).map(i => i.grant_id));
  let showAll = false;
  const body = h('div');
  const revokeBtn = h('button', { type: 'button', class: 'small danger' });
  function sync() {
    revokeBtn.textContent = `Revoke selected (${chosen.size})`;
    revokeBtn.disabled = chosen.size === 0;
  }
  revokeBtn.addEventListener('click', async () => {
    if (!window.confirm(`Revoke ${chosen.size} grant${chosen.size === 1 ? '' : 's'}? The people lose access at once, and every outstanding share link to those documents stops working.`)) return;
    const r = await attempt(() => api('POST', '/api/admin/access-review/revoke', { grant_ids: [...chosen] }));
    if (r) { toast(`Revoked ${r.revoked} grant${r.revoked === 1 ? '' : 's'} on ${r.documents} document${r.documents === 1 ? '' : 's'}`); renderAdminDocuments(); }
  });
  function draw() {
    const items = showAll ? review.items : review.items.filter(i => i.flagged);
    const rows = items.map(i => {
      const box = h('input', { type: 'checkbox', 'aria-label': `Select ${i.username} on ${i.document_name}` });
      box.checked = chosen.has(i.grant_id);
      box.addEventListener('change', () => { if (box.checked) chosen.add(i.grant_id); else chosen.delete(i.grant_id); sync(); });
      return h('tr', { class: i.flagged ? 'flagged-row' : '' },
        h('td', null, box),
        h('td', null, h('strong', null, i.display_name), h('div', { class: 'cell-sub' }, h('span', { class: 'muted' }, i.username),
          i.is_external ? badge('external', 'neutral') : null, i.is_active ? null : badge('inactive'))),
        h('td', null, i.document_name, h('div', { class: 'muted small-help' }, `owner: ${i.owner}`)),
        h('td', null, permBadge(i.permission)),
        h('td', { class: 'num' }, i.last_used_at ? fmtDate(i.last_used_at) : h('span', { class: 'muted' }, 'never')),
        h('td', { class: 'num' }, i.flagged ? badge(`${i.days_unused} days`, 'bad') : `${i.days_unused} day${i.days_unused === 1 ? '' : 's'}`),
        h('td', { class: 'num' }, fmtDay(i.expires_at)));
    });
    body.replaceChildren(table(['', 'Person', 'Document', 'Access', 'Last used', 'Unused for', 'Ends'], rows,
      showAll ? 'No live grants.' : `Nothing unused for ${review.unused_days} days. Every live grant has been used recently.`));
  }
  const toggle = h('button', { type: 'button', class: 'small', onclick: () => {
    showAll = !showAll;
    toggle.textContent = showAll ? 'Show only unused' : `Show all live grants (${review.items.length})`;
    draw();
  } }, `Show all live grants (${review.items.length})`);
  sync(); draw();
  return h('section', { class: 'panel' },
    h('div', { class: 'panel-head' },
      h('h2', null, `Unused access · no use in ${review.unused_days} days `, review.flagged ? badge(String(review.flagged), 'bad') : badge('0', 'ok')),
      h('div', { class: 'actions' }, toggle, revokeBtn)),
    h('p', { class: 'muted small-help' }, 'From the audit trail: the last time each person opened, viewed, downloaded or edited the document through their grant. Revoking can only ever reduce access.'),
    body);
}

async function renderAdminDocuments() {
  shell('access', h('div', { class: 'page-head' }, h('h1', null, 'Access review')), loadingPanel());
  const [data, review] = await Promise.all([attempt(() => api('GET', '/api/admin/documents')), attempt(() => api('GET', '/api/admin/access-review'))]);
  if (!data || !review) { shell('access', h('div', { class: 'page-head' }, h('h1', null, 'Access review')), errorPanel(renderAdminDocuments)); return; }
  const detail = h('div');
  async function showAccess(d) {
    detail.replaceChildren(loadingPanel());
    const a = await attempt(() => api('GET', `/api/admin/documents/${enc(d.id)}/access`));
    if (!a) { detail.replaceChildren(errorPanel(() => showAccess(d))); return; }
    clearTimers();
    detail.replaceChildren(h('section', { class: 'panel' },
      h('div', { class: 'panel-head' }, h('h2', null, `Who can reach “${d.name}”`),
        h('button', { class: 'small danger', type: 'button', onclick: async () => {
          if (await attempt(() => api('POST', `/api/admin/documents/${enc(d.id)}/links/revoke-all`), 'Every link to this document stopped working')) showAccess(d);
        } }, 'Revoke all links')),
      h('p', { class: 'muted small-help' }, 'Administrators can remove access here but can never add it, and can never open the document.'),
      table(['Person', 'Access', 'Time left', ''], a.grants.map(g => h('tr', { class: g.expired ? 'expired-row' : '' },
        h('td', null, g.username, ' ', g.is_external ? badge('external', 'neutral') : null, !g.is_active ? badge('inactive') : null),
        h('td', null, permBadge(g.permission)),
        h('td', { class: 'num' }, g.expired ? badge('expired') : countdown(g.expires_at, { prefix: '', ended: 'Expired' })),
        h('td', { class: 'right' }, h('button', { class: 'small danger', onclick: async () => {
          if (await attempt(() => api('DELETE', '/api/admin/grants/' + enc(g.id)), 'Grant revoked')) showAccess(d);
        } }, 'Revoke')))), 'Only the owner has access.'),
      a.recent_links.length ? [h('h3', { class: 'section-gap' }, 'Share links made recently'),
        table(['Made', 'By', 'For', 'Access', 'State'], a.recent_links.map(l => h('tr', null,
          h('td', { class: 'num' }, fmtDate(l.created_at)), h('td', null, l.created_by), h('td', null, l.recipient),
          h('td', null, permBadge(l.permission)), h('td', { class: 'num' }, l.live ? countdown(l.expires_at, { prefix: 'live · ', ended: 'Expired' }) : badge('expired')))))] : null));
    detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  const rows = data.items.map(d => h('tr', { class: 'clickable', tabindex: '0', onclick: () => showAccess(d),
    onkeydown: (e) => { if (e.key === 'Enter') showAccess(d); } },
    h('td', null, h('strong', null, d.name), h('div', { class: 'cell-sub' }, labelBadge(d.classification))),
    h('td', null, d.owner_username, ' ', !d.owner_active ? badge('inactive') : null),
    h('td', { class: 'num' }, String(d.grants)), h('td', { class: 'num' }, String(d.expired_grants)),
    h('td', null, d.purged_at ? badge('destroyed') : d.deleted_at ? badge('trash') : badge('active'))));
  shell('access', h('div', { class: 'page-head' }, h('h1', null, 'Access review')),
    unusedAccessPanel(review),
    h('h2', { class: 'section-gap' }, 'Documents'),
    h('p', { class: 'muted lead' }, 'Metadata only. Choose a document to see who can reach it, and until when.'),
    h('section', { class: 'panel flush' }, table(['Document', 'Owner', 'Live grants', 'Expired', 'State'], rows, 'No documents yet.')),
    detail);
}

// ------------------------------------------------------------------- router
async function ensureSession() {
  if (state.user) return true;
  try {
    const me = await api('GET', '/api/auth/me', undefined, { quiet401: true });
    state.user = me.user; state.csrf = me.csrf_token; state.session = me.session;
    state.lastActivity = Date.now();
    syncClock(me.session && me.session.server_time);
    return true;
  } catch (_) { return false; }
}

async function route() {
  clearTimers();
  closeDrawer();
  const hash = location.hash || '#/';
  if (hash === '#/login') { if (await ensureSession()) { location.hash = takeReturn() || '#/'; return; } renderLogin(); return; }
  if (hash.startsWith('#/l/')) return renderLinkOpen(hash.slice(4));
  if (!(await ensureSession())) { rememberReturn(); location.hash = '#/login'; return; }
  if (!state.meta) state.meta = await attempt(() => api('GET', '/api/meta'));
  let parts;
  try { parts = hash.slice(2).split('/').map(decodeURIComponent); } catch (_) { parts = ['documents']; }
  const admin = state.user.role === 'admin';
  state.lastDocId = parts[0] === 'doc' ? parts[1] : null;
  switch (parts[0]) {
    case 'doc': return renderDocument(parts[1]);
    case 'denied': return renderDenied();
    case 'upload': return renderUpload();
    case 'trash': return renderTrash();
    case 'account': return renderAccount();
    case 'admin':
      if (!admin) { location.hash = '#/documents'; return; }
      if (parts[1] === 'users') return renderAdminUsers();
      if (parts[1] === 'audit') return renderAdminAudit();
      if (parts[1] === 'documents') return renderAdminDocuments();
      return renderAdmin();
    case 'documents': return admin ? renderAdmin() : renderDocuments();
    default:
      location.hash = admin ? '#/admin' : '#/documents';
  }
}

window.addEventListener('hashchange', route);
route();
