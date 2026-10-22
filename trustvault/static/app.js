'use strict';
/*
 * TrustVault single-page UI.
 *
 * Security rules for this file (checked by tests/test_http_hardening.py):
 *  - DOM is built with createElement/textContent only. No HTML strings, ever,
 *    so a document called "<img src=x onerror=alert(1)>" is just text.
 *  - Every state-changing request carries the X-CSRF-Token header.
 *  - The UI hides buttons for convenience only; the server decides every time.
 */

const state = { user: null, csrf: null, meta: null, directory: null };

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

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
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

async function api(method, url, body, opts = {}) {
  const headers = {};
  if (method !== 'GET' && state.csrf) headers['X-CSRF-Token'] = state.csrf;
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch(url, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  let data = null;
  if ((res.headers.get('content-type') || '').includes('application/json')) data = await res.json();
  if (res.status === 401 && !opts.quiet401) {
    state.user = null; state.csrf = null;
    if (location.hash !== '#/login') location.hash = '#/login';
    throw new ApiError(401, 'Please sign in.');
  }
  if (!res.ok) throw new ApiError(res.status, describe(data, res.status));
  return data;
}

function toast(message, isError = false) {
  const box = document.getElementById('toast');
  const t = h('div', { class: 't' + (isError ? ' err' : '') }, message);
  box.append(t);
  setTimeout(() => t.remove(), isError ? 7000 : 3500);
}

async function attempt(fn, okMessage) {
  try {
    const r = await fn();
    if (okMessage) toast(okMessage);
    return r;
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 401)) toast(e.message || 'Something went wrong', true);
    return undefined;
  }
}

const fmtDate = s => (s ? new Date(s).toLocaleString() : '—');
const fmtDay = s => (s ? new Date(s).toLocaleDateString() : '—');
function fmtSize(n) {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}
const badge = (text, cls) => h('span', { class: 'badge ' + (cls || text) }, text);
const LEVELS = [
  ['view', 'View only', 'Open it in the browser (watermarked). Cannot download or change it.'],
  ['download', 'View + download', 'Can also download the original file.'],
  ['edit', 'Edit', 'Can also upload new versions and change name, category and description.'],
];
const levelLabel = p => (p === 'owner' ? 'owner' : (LEVELS.find(l => l[0] === p) || [p, p])[1]);
const permBadge = p => badge(levelLabel(p), p);
const enc = encodeURIComponent;

function table(headers, rows, emptyText) {
  return h('div', { class: 'table-wrap' },
    h('table', null,
      h('thead', null, h('tr', null, headers.map(x => h('th', null, x)))),
      h('tbody', null, rows.length ? rows : h('tr', null, h('td', { class: 'empty', colspan: headers.length }, emptyText || 'Nothing here yet.')))));
}

function field(label, input) { return h('label', null, label, input); }

function categorySelect(value, includeAny) {
  const cats = (state.meta && state.meta.categories) || [];
  return h('select', { name: 'category' },
    includeAny ? h('option', { value: '' }, 'Any category') : null,
    cats.map(c => h('option', { value: c, selected: c === value }, c)));
}

// ------------------------------------------------------------------- shell
const app = () => document.getElementById('app');

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
  const page = h('div', null,
    h('header', { class: 'topbar' },
      h('div', { class: 'brand' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }), 'TrustVault'),
      h('nav', null, links.map(([href, text, key]) => h('a', { href, class: key === active ? 'active' : '' }, text))),
      h('div', { class: 'whoami' },
        h('span', null, u.display_name), badge(u.role), u.is_external ? badge('external') : null,
        h('button', { class: 'small', type: 'button', onclick: logout }, 'Sign out'))),
    h('main', { class: 'page' }, content));
  app().replaceChildren(page);
}

async function logout() {
  await attempt(() => api('POST', '/api/auth/logout'));
  state.user = null; state.csrf = null; state.directory = null;
  location.hash = '#/login';
}

// ------------------------------------------------------------------- login
function renderLogin() {
  const msg = h('p', { class: 'error', role: 'alert' });
  const user = h('input', { name: 'username', autocomplete: 'username', required: true, maxlength: 64 });
  const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const form = h('form', { class: 'stack', onsubmit: async (e) => {
    e.preventDefault();
    msg.textContent = '';
    try {
      const r = await api('POST', '/api/auth/login', { username: user.value, password: pass.value }, { quiet401: true });
      state.user = r.user; state.csrf = r.csrf_token;
      pass.value = '';
      location.hash = r.user.role === 'admin' ? '#/admin' : '#/documents';  // hashchange re-renders
    } catch (err) { msg.textContent = err.message; pass.value = ''; pass.focus(); }
  } },
    h('h1', null, 'Sign in'),
    field('Username', user), field('Password', pass), msg,
    h('button', { class: 'primary', type: 'submit' }, 'Sign in'));
  app().replaceChildren(h('div', { class: 'login-wrap' },
    h('section', { class: 'login-side' },
      h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }), 'TrustVault'),
      h('h1', null, 'The wrong person can never read the file.'),
      h('ul', null,
        h('li', null, 'Every document is shared with named people only, server-checked on every request.'),
        h('li', null, 'Every open, download and refusal is written to a tamper-evident audit trail.'),
        h('li', null, 'Revoking access works on the very next click.'))),
    h('section', { class: 'login-form' }, form)));
  user.focus();
}

// ---------------------------------------------------------------- documents
async function renderDocuments() {
  const results = h('div');
  const q = h('input', { name: 'q', placeholder: 'Name contains…', maxlength: 200 });
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
    if (!data) return;
    const rows = data.items.map(d => h('tr', { class: 'clickable', onclick: () => { location.hash = '#/doc/' + enc(d.id); } },
      h('td', null, h('strong', null, d.name), d.description ? h('div', { class: 'muted' }, d.description.slice(0, 90)) : null),
      h('td', null, d.owner.display_name || d.owner.username),
      h('td', null, badge(d.category, 'cat')),
      h('td', null, fmtDay(d.created_at)),
      h('td', null, 'v' + (d.current_version.version_no || 1), ' · ', fmtSize(d.current_version.size_bytes)),
      h('td', null, permBadge(d.my_permission))));
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    results.replaceChildren(
      table(['Name', 'Owner', 'Category', 'Uploaded', 'Version', 'My access'], rows,
        'No documents match. You only ever see documents you own or were given.'),
      h('div', { class: 'pager' }, h('span', { class: 'muted' }, `${data.total} document(s) · page ${page} of ${pages}`),
        h('button', { class: 'small', disabled: page <= 1, onclick: () => { page--; load(); } }, '‹ Prev'),
        h('button', { class: 'small', disabled: page >= pages, onclick: () => { page++; load(); } }, 'Next ›')));
  }

  const form = h('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); page = 1; load(); } },
    field('Name', q), field('Owner', owner), field('Category', cat), field('From', from), field('To', to),
    field('Show', scope), h('button', { class: 'primary', type: 'submit' }, 'Search'));
  shell('documents',
    h('div', { class: 'panel-head' }, h('h1', null, 'Documents'),
      state.user.role === 'owner' ? h('a', { class: 'btn primary', href: '#/upload' }, '+ Upload') : null),
    h('section', { class: 'panel' }, form),
    h('section', { class: 'panel' }, results));
  load();
}

function renderUpload() {
  const file = h('input', { type: 'file', name: 'file', required: true,
    accept: ((state.meta && state.meta.allowed_extensions) || []).map(x => '.' + x).join(',') });
  const name = h('input', { name: 'name', maxlength: 200, placeholder: 'Defaults to the file name' });
  const desc = h('textarea', { name: 'description', maxlength: 1000 });
  const cat = categorySelect('general');
  const form = h('form', { class: 'stack', onsubmit: async (e) => {
    e.preventDefault();
    if (!file.files.length) return;
    const fd = new FormData();
    fd.append('file', file.files[0]);
    fd.append('category', cat.value);
    fd.append('name', name.value);
    fd.append('description', desc.value);
    const r = await attempt(() => api('POST', '/api/documents', fd), 'Uploaded and encrypted');
    if (r) location.hash = '#/doc/' + enc(r.id);
  } },
    field('File', file), field('Display name', name), field('Category', cat), field('Description', desc),
    h('p', { class: 'muted' }, `Allowed: ${((state.meta && state.meta.allowed_extensions) || []).join(', ')} · max ${fmtSize(state.meta ? state.meta.max_upload_bytes : 0)}. `,
      'Files are checked (type, macros, scripts) and encrypted before they are stored. Only you can see a new document until you share it.'),
    h('div', null, h('button', { class: 'primary', type: 'submit' }, 'Upload')));
  shell('upload', h('h1', null, 'Upload a document'), h('section', { class: 'panel' }, form));
}

async function renderTrash() {
  const data = await attempt(() => api('GET', '/api/documents/trash'));
  if (!data) return;
  const rows = data.items.map(d => h('tr', null,
    h('td', null, h('a', { href: '#/doc/' + enc(d.id) }, d.name)),
    h('td', null, badge(d.category, 'cat')),
    h('td', null, fmtDate(d.deleted_at)),
    h('td', null, h('button', { class: 'small', onclick: async () => {
      if (await attempt(() => api('POST', `/api/documents/${enc(d.id)}/restore`), 'Restored')) renderTrash();
    } }, 'Restore'))));
  shell('trash', h('h1', null, 'Trash'),
    h('p', { class: 'muted' }, `Documents in the trash cannot be opened by anyone you shared them with. They are destroyed (crypto-shredded) automatically after the retention period.`),
    h('section', { class: 'panel' }, table(['Name', 'Category', 'Deleted', ''], rows, 'The trash is empty.')));
}

// ----------------------------------------------------------- one document
async function renderDocument(id) {
  const doc = await attempt(() => api('GET', '/api/documents/' + enc(id)));
  if (!doc) { shell('documents', h('section', { class: 'panel' }, h('h1', null, 'Not available'),
    h('p', null, 'This document does not exist or you do not have access to it.'))); return; }
  const perm = doc.my_permission;
  const isOwner = perm === 'owner';
  const canEdit = perm === 'owner' || perm === 'edit';
  const canDownload = perm !== 'view';
  const trashed = !!doc.deleted_at;
  const current = doc.versions[0];
  const viewer = h('div');

  const head = h('section', { class: 'panel' },
    h('div', { class: 'doc-head' },
      h('div', null, h('h1', null, doc.name),
        h('div', { class: 'sub' }, badge(doc.category, 'cat'), 'Owner: ', doc.owner.display_name,
          ' · Your access: ', permBadge(perm), trashed ? badge('in trash', 'revoked') : null)),
      !trashed ? h('div', { class: 'actions' },
        h('button', { class: 'primary', type: 'button', onclick: () => openViewer(doc, viewer) }, '👁 View'),
        canDownload ? h('a', { class: 'btn', href: `/api/documents/${enc(doc.id)}/download` }, '⬇ Download') : null) : null),
    perm === 'view' ? h('p', { class: 'callout' },
      'You have view-only access: you can read this document here, but you cannot download it. ',
      'Every page you open is watermarked with your name and recorded.') : null,
    doc.description ? h('p', null, doc.description) : null,
    h('dl', { class: 'meta' },
      h('dt', null, 'Current file'), h('dd', null, current ? `${current.original_filename} (${fmtSize(current.size_bytes)})` : '—'),
      h('dt', null, 'SHA-256'), h('dd', { class: 'mono' }, current ? current.sha256 : '—'),
      h('dt', null, 'Created'), h('dd', null, fmtDate(doc.created_at)),
      h('dt', null, 'Updated'), h('dd', null, fmtDate(doc.updated_at))));

  const versions = h('section', { class: 'panel' }, h('h2', null, 'Versions'),
    table(['#', 'File', 'Size', 'Uploaded by', 'When', ''], doc.versions.map(v => h('tr', null,
      h('td', null, 'v' + v.version_no), h('td', null, v.original_filename), h('td', null, fmtSize(v.size_bytes)),
      h('td', null, v.uploaded_by), h('td', null, fmtDate(v.created_at)),
      h('td', null, trashed || !canDownload ? null : h('a', { class: 'btn small', href: `/api/documents/${enc(doc.id)}/versions/${enc(v.id)}/download` }, 'Download'))))));

  const left = [head, viewer, versions];
  const right = [];

  if (canEdit && !trashed) {
    const name = h('input', { value: doc.name, maxlength: 200 });
    const cat = categorySelect(doc.category);
    const desc = h('textarea', { maxlength: 1000 }, doc.description);
    const file = h('input', { type: 'file' });
    right.push(h('section', { class: 'panel' }, h('h2', null, 'Edit'),
      h('form', { class: 'stack', onsubmit: async (e) => {
        e.preventDefault();
        if (await attempt(() => api('PATCH', '/api/documents/' + enc(doc.id), { name: name.value, category: cat.value, description: desc.value }), 'Saved')) renderDocument(doc.id);
      } }, field('Name', name), field('Category', cat), field('Description', desc),
      h('div', null, h('button', { class: 'primary', type: 'submit' }, 'Save details'))),
      h('form', { class: 'stack', onsubmit: async (e) => {
        e.preventDefault();
        if (!file.files.length) return;
        const fd = new FormData(); fd.append('file', file.files[0]);
        if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/versions`, fd), 'New version uploaded')) renderDocument(doc.id);
      } }, h('h3', null, 'Upload a new version'), file, h('div', null, h('button', { type: 'submit' }, 'Upload version')))));
  }

  if (isOwner && !trashed) {
    right.push(await sharingPanel(doc));
    left.push(await linksPanel(doc));
    left.push(await activityPanel(doc));
  }
  if (isOwner) {
    right.push(h('section', { class: 'panel' }, h('h2', null, trashed ? 'In the trash' : 'Danger zone'),
      trashed
        ? h('div', { class: 'stack' },
            h('p', { class: 'muted' }, 'Nobody you shared this with can open it while it is in the trash.'),
            h('div', null, h('button', { onclick: async () => {
              if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/restore`), 'Restored')) renderDocument(doc.id);
            } }, 'Restore'), ' ',
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
  shell('documents', h('div', { class: 'grid two' }, h('div', null, left), h('div', null, right)));
}

async function openViewer(doc, box) {
  box.replaceChildren(h('section', { class: 'panel' }, h('p', { class: 'muted' }, 'Rendering…')));
  const p = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/preview`));
  if (!p) { box.replaceChildren(); return; }
  const close = h('button', { class: 'small', type: 'button', onclick: () => box.replaceChildren() }, 'Close');
  const head = h('div', { class: 'panel-head' },
    h('h2', null, `Viewing: ${p.filename} (v${p.version_no})`), close);
  const mark = h('p', { class: 'watermark-line' }, p.watermark);
  if (p.kind === 'text') {
    box.replaceChildren(h('section', { class: 'panel viewer' }, head, mark,
      h('pre', { class: 'doc-text' }, p.text || '(no text)'),
      p.truncated ? h('p', { class: 'muted' }, 'Preview truncated.') : null, mark.cloneNode(true)));
    return;
  }
  let page = 1;
  const img = h('img', { class: 'page-img', alt: 'Rendered page', draggable: 'false' });
  const label = h('span', { class: 'muted' });
  const prev = h('button', { class: 'small', type: 'button' }, '‹ Prev');
  const next = h('button', { class: 'small', type: 'button' }, 'Next ›');
  function show() {
    img.src = `/api/documents/${enc(doc.id)}/preview/pages/${page}?t=${Date.now()}`;
    label.textContent = `Page ${page} of ${p.pages}`;
    prev.disabled = page <= 1;
    next.disabled = page >= p.pages;
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

async function sharingPanel(doc) {
  const [grants, people] = await Promise.all([
    attempt(() => api('GET', `/api/documents/${enc(doc.id)}/grants`)), loadDirectory()]);
  const rows = (grants ? grants.items : []).map(g => h('tr', null,
    h('td', null, g.display_name, ' ', g.is_external ? badge('external') : null, !g.is_active ? badge('inactive') : null),
    h('td', null, permBadge(g.permission)),
    h('td', null, g.expires_at ? (g.expired ? badge('expired') : fmtDay(g.expires_at)) : 'never'),
    h('td', null, g.source === 'suggestion' ? badge('suggested', 'info') : 'manual'),
    h('td', null, h('button', { class: 'small danger', onclick: async () => {
      if (await attempt(() => api('DELETE', `/api/documents/${enc(doc.id)}/grants/${enc(g.id)}`), `Access removed for ${g.display_name}`)) renderDocument(doc.id);
    } }, 'Revoke'))));
  const person = h('select', { required: true }, h('option', { value: '' }, 'Choose a person…'),
    people.map(p => h('option', { value: p.username }, `${p.display_name} (${p.username})${p.is_external ? ' — external' : ''}`)));
  const perm = h('select', null, LEVELS.map(([v, label, help]) => h('option', { value: v, title: help }, label)));
  const permHelp = h('p', { class: 'muted small-help' }, LEVELS[0][2]);
  perm.addEventListener('change', () => { permHelp.textContent = (LEVELS.find(l => l[0] === perm.value) || LEVELS[0])[2]; });
  const expires = h('input', { type: 'date' });
  const form = h('form', { class: 'inline', onsubmit: async (e) => {
    e.preventDefault();
    if (!person.value) return;
    const body = { username: person.value, permission: perm.value };
    if (expires.value) body.expires_at = new Date(expires.value + 'T23:59:59').toISOString();
    if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/grants`, body), 'Access granted')) renderDocument(doc.id);
  } }, field('Person', person), field('Access', perm), field('Expires (optional)', expires),
  h('button', { class: 'primary', type: 'submit' }, 'Grant'), permHelp);

  const suggestBox = h('div');
  const suggestBtn = h('button', { type: 'button', onclick: async () => {
    const r = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/suggestions`));
    if (!r) return;
    if (!r.items.length) { suggestBox.replaceChildren(h('p', { class: 'muted' }, 'No suggestions: nothing in your own sharing history points to anyone.')); return; }
    suggestBox.replaceChildren(h('p', { class: 'callout' }, r.note), ...r.items.map(s => h('div', { class: 'alert-item' },
      h('strong', null, s.display_name), ' ', s.is_external ? badge('external') : null, ' ', permBadge('view'),
      h('span', { class: 'muted' }, ` score ${s.score}`),
      h('ul', { class: 'reasons' }, s.reasons.map(x => h('li', null, x))),
      h('div', null,
        h('button', { class: 'small primary', onclick: async () => {
          if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/grants`, { username: s.username, permission: 'view', suggestion_id: s.suggestion_id }), `View access granted to ${s.display_name}`)) renderDocument(doc.id);
        } }, 'Confirm: grant view'), ' ',
        h('button', { class: 'small', onclick: async (e) => {
          if (await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/suggestions/${enc(s.suggestion_id)}/dismiss`))) e.target.closest('.alert-item').remove();
        } }, 'Dismiss')))));
  } }, '✦ Suggest people');

  return h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Who has access'), suggestBtn),
    suggestBox,
    table(['Person', 'Access', 'Expires', 'Source', ''], rows, 'Only you can see this document.'),
    h('h3', null, 'Give someone access'), form);
}

async function linksPanel(doc) {
  const data = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/share-links`));
  const reveal = h('div');
  const rows = (data ? data.items : []).map(l => h('tr', null,
    h('td', null, l.label || '—'), h('td', null, badge(l.status)), h('td', null, `${l.use_count} / ${l.max_uses}`),
    h('td', null, fmtDate(l.expires_at)),
    h('td', null, l.status === 'active' ? h('button', { class: 'small danger', onclick: async () => {
      if (await attempt(() => api('DELETE', `/api/documents/${enc(doc.id)}/share-links/${enc(l.id)}`), 'Link revoked')) renderDocument(doc.id);
    } }, 'Revoke') : null)));
  const maxH = state.meta ? state.meta.share_link_max_hours : 168;
  const hours = h('input', { type: 'number', min: 1, max: maxH, value: 24 });
  const uses = h('input', { type: 'number', min: 1, max: state.meta ? state.meta.share_link_max_uses : 50, value: 3 });
  const label = h('input', { maxlength: 100, placeholder: 'e.g. for external auditor' });
  const form = h('form', { class: 'inline', onsubmit: async (e) => {
    e.preventDefault();
    const r = await attempt(() => api('POST', `/api/documents/${enc(doc.id)}/share-links`,
      { expires_in_hours: Number(hours.value), max_uses: Number(uses.value), label: label.value }), 'Link created');
    if (!r) return;
    const url = location.origin + r.path;
    reveal.replaceChildren(h('div', { class: 'callout warn stack' },
      h('strong', null, 'Copy this link now — it is shown only once.'),
      h('div', { class: 'secret' }, url),
      h('div', null, h('button', { class: 'small', type: 'button', onclick: async () => {
        try { await navigator.clipboard.writeText(url); toast('Copied'); } catch (_) { toast('Copy failed - select the text instead', true); }
      } }, 'Copy link'))));
  } }, field('Valid for (hours)', hours), field('Max downloads', uses), field('Label', label),
  h('button', { type: 'submit' }, 'Create link'));
  return h('section', { class: 'panel' }, h('h2', null, 'External share links'),
    h('p', { class: 'muted' }, `Read-only, expiring (max ${maxH} h), use-limited and revocable. They stop working if the document is trashed or you lose ownership.`),
    reveal, table(['Label', 'Status', 'Used', 'Expires', ''], rows, 'No links.'), form);
}

async function activityPanel(doc) {
  const data = await attempt(() => api('GET', `/api/documents/${enc(doc.id)}/activity?limit=50`));
  const rows = (data ? data.items : []).map(a => h('tr', null,
    h('td', null, fmtDate(a.ts)), h('td', null, a.actor_name || 'system'), h('td', null, a.action),
    h('td', null, badge(a.outcome)), h('td', { class: 'details' }, a.details && a.details.reason ? a.details.reason : '')));
  return h('section', { class: 'panel' }, h('h2', null, 'Activity on this document'),
    table(['When', 'Who', 'What', 'Outcome', 'Why'], rows, 'No activity.'));
}

// ------------------------------------------------------------------ account
function renderAccount() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const next = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 12 });
  const form = h('form', { class: 'stack', onsubmit: async (e) => {
    e.preventDefault();
    if (await attempt(() => api('POST', '/api/auth/change-password', { current_password: cur.value, new_password: next.value }),
      'Password changed. Your other sessions were signed out.')) { cur.value = ''; next.value = ''; }
  } }, field('Current password', cur), field('New password (12+ characters)', next),
  h('div', null, h('button', { class: 'primary', type: 'submit' }, 'Change password')));
  shell('account', h('h1', null, 'Account'),
    h('section', { class: 'panel' }, h('dl', { class: 'meta' },
      h('dt', null, 'Username'), h('dd', null, state.user.username),
      h('dt', null, 'Name'), h('dd', null, state.user.display_name),
      h('dt', null, 'Role'), h('dd', null, badge(state.user.role)))),
    h('section', { class: 'panel' }, h('h2', null, 'Change password'), form));
}

// -------------------------------------------------------------------- admin
async function renderAdmin() {
  const [stats, alerts] = await Promise.all([attempt(() => api('GET', '/api/admin/stats')),
    attempt(() => api('GET', '/api/admin/alerts?hours=24'))]);
  if (!stats || !alerts) return;
  const tiles = [['Active users', stats.users], ['Documents', stats.documents], ['Grants', stats.grants],
    ['Active links', stats.active_links], ['Events today', stats.events_today], ['Refused today', stats.denied_today],
    ['Downloads today', stats.downloads_today], ['In trash', stats.in_trash]];
  const integ = alerts.integrity;
  const verifyOut = h('div');
  shell('admin',
    h('h1', null, 'Administration'),
    h('div', { class: 'grid stats' }, tiles.map(([l, n]) => h('div', { class: 'stat' }, h('div', { class: 'n' }, n), h('div', { class: 'l' }, l)))),
    h('div', { class: 'grid two' },
      h('section', { class: 'panel' }, h('h2', null, 'Worth noticing (last 24 h)'),
        alerts.items.length ? alerts.items.map(a => h('div', { class: 'alert-item ' + a.severity },
          badge(a.severity), ' ', h('strong', null, a.title),
          h('div', null, a.detail), h('div', { class: 'muted' }, `${fmtDate(a.first_seen)} → ${fmtDate(a.last_seen)}`)))
          : h('p', { class: 'muted' }, 'Nothing unusual. Rules: refused-access bursts, password guessing, bulk downloads, share links spreading, deactivated accounts signing in, new admins, admin password resets (and sign-ins that follow them), external edit grants, integrity failures.')),
      h('section', { class: 'panel' }, h('h2', null, 'Audit trail integrity'),
        h('p', { class: integ.ok ? 'callout' : 'callout danger' },
          integ.ok ? `Intact: ${integ.entries_checked} entries and ${integ.anchors_checked} external anchors verified.`
                   : `BROKEN at entry ${integ.first_bad_seq}: ${integ.problems.join('; ')}`),
        integ.warnings.length ? h('p', { class: 'callout warn' }, integ.warnings.join('; ')) : null,
        h('button', { onclick: async () => {
          const r = await attempt(() => api('GET', '/api/admin/audit/verify'));
          if (r) verifyOut.replaceChildren(h('p', { class: r.ok ? 'callout' : 'callout danger' },
            r.ok ? `Verified ${r.entries_checked} entries just now.` : `Verification FAILED: ${r.problems.join('; ')}`));
        } }, 'Verify now'), verifyOut,
        h('p', { class: 'muted' }, 'Each entry is chained to the previous one with an HMAC whose key is not stored in the database, and the newest hash is anchored outside the database after every write.'))));
}

async function renderAdminUsers() {
  const data = await attempt(() => api('GET', '/api/admin/users'));
  if (!data) return;
  const rows = data.items.map(u => {
    const role = h('select', null, ['admin', 'owner', 'viewer'].map(r => h('option', { value: r, selected: r === u.role }, r)));
    const self = u.id === state.user.id;
    const deleted = !!u.deleted_at;
    return h('tr', { class: deleted ? 'deleted-row' : '' },
      h('td', null, h('strong', null, u.username), h('div', { class: 'muted' }, u.display_name)),
      h('td', null, self || deleted ? badge(u.role) : role),
      h('td', null, deleted ? badge('deleted', 'revoked') : badge(u.is_active ? 'active' : 'inactive'), ' ', u.is_external ? badge('external') : null,
        u.locked_until && u.locked_until > new Date().toISOString() ? badge('locked', 'denied') : null),
      h('td', null, String(u.active_sessions)), h('td', null, `${u.owned_documents} / ${u.grants_held}`),
      h('td', null, self ? h('span', { class: 'muted' }, 'you') : deleted ? h('span', { class: 'muted' }, `deleted ${fmtDay(u.deleted_at)}`) : h('div', { class: 'stack' },
        h('div', null,
          h('button', { class: 'small', onclick: async () => {
            if (await attempt(() => api('PATCH', '/api/admin/users/' + enc(u.id), { role: role.value }), 'Role updated')) renderAdminUsers();
          } }, 'Save role'), ' ',
          h('button', { class: u.is_active ? 'small danger' : 'small', onclick: async () => {
            if (u.is_active && !window.confirm(`Deactivate ${u.username}? All their sessions, grants and links stop working now.`)) return;
            if (await attempt(() => api('PATCH', '/api/admin/users/' + enc(u.id), { is_active: !u.is_active }), u.is_active ? 'Deactivated' : 'Activated')) renderAdminUsers();
          } }, u.is_active ? 'Deactivate' : 'Activate')),
        h('div', null,
          h('button', { class: 'small', onclick: async () => {
            const pw = window.prompt(`New password for ${u.username} (12+ characters):`);
            if (pw) await attempt(() => api('POST', `/api/admin/users/${enc(u.id)}/reset-password`, { new_password: pw }), 'Password reset; sessions ended');
          } }, 'Reset password'), ' ',
          h('button', { class: 'small', onclick: async () => {
            if (await attempt(() => api('POST', `/api/admin/users/${enc(u.id)}/unlock`), 'Unlocked')) renderAdminUsers();
          } }, 'Unlock'), ' ',
          h('button', { class: 'small', onclick: async () => {
            if (await attempt(() => api('POST', `/api/admin/users/${enc(u.id)}/revoke-sessions`), 'Signed out everywhere')) renderAdminUsers();
          } }, 'Sign out'), ' ',
          h('button', { class: 'small danger', onclick: async () => {
            if (!window.confirm(`Delete ${u.username} permanently? They can never sign in again, and all their access is removed. ` +
                                'The account record is kept so the audit trail still shows who did what.')) return;
            if (await attempt(() => api('DELETE', '/api/admin/users/' + enc(u.id)), 'User deleted')) renderAdminUsers();
          } }, 'Delete')))));
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
  field('External', ext), h('button', { class: 'primary', type: 'submit' }, 'Create user'));
  shell('users', h('h1', null, 'Users'),
    h('section', { class: 'panel' }, table(['User', 'Role', 'Status', 'Sessions', 'Owns / grants', 'Actions'], rows)),
    h('section', { class: 'panel' }, h('h2', null, 'Create user'), form));
}

async function renderAdminAudit() {
  const out = h('div');
  const action = h('input', { placeholder: 'e.g. document.download or permission.', maxlength: 64 });
  const outcome = h('select', null, h('option', { value: '' }, 'Any'), ['allowed', 'denied', 'error', 'info'].map(o => h('option', { value: o }, o)));
  const actor = h('input', { placeholder: 'username', maxlength: 64 });
  const docId = h('input', { placeholder: 'document id', maxlength: 64 });
  const from = h('input', { type: 'date' });
  const to = h('input', { type: 'date' });
  let page = 1;
  async function load() {
    const p = new URLSearchParams({ page: String(page), page_size: '50' });
    if (action.value.trim()) p.set('action', action.value.trim());
    if (outcome.value) p.set('outcome', outcome.value);
    if (actor.value.trim()) p.set('actor', actor.value.trim());
    if (docId.value.trim()) p.set('document_id', docId.value.trim());
    if (from.value) p.set('date_from', from.value);
    if (to.value) p.set('date_to', to.value);
    const data = await attempt(() => api('GET', '/api/admin/audit?' + p.toString()));
    if (!data) return;
    const rows = data.items.map(a => h('tr', null,
      h('td', { class: 'mono' }, '#' + a.seq), h('td', null, fmtDate(a.ts)), h('td', null, a.actor_name || 'system'),
      h('td', null, a.action), h('td', null, badge(a.outcome)), h('td', null, a.document_name || (a.document_id ? a.document_id : '')),
      h('td', { class: 'mono' }, a.ip || ''), h('td', { class: 'details' }, JSON.stringify(a.details))));
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    out.replaceChildren(table(['Seq', 'When', 'Who', 'Action', 'Outcome', 'Document', 'IP', 'Details'], rows, 'No matching events.'),
      h('div', { class: 'pager' }, h('span', { class: 'muted' }, `${data.total} event(s) · page ${page} of ${pages}`),
        h('button', { class: 'small', disabled: page <= 1, onclick: () => { page--; load(); } }, '‹ Newer'),
        h('button', { class: 'small', disabled: page >= pages, onclick: () => { page++; load(); } }, 'Older ›')));
  }
  shell('audit', h('h1', null, 'Audit trail'),
    h('section', { class: 'panel' }, h('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); page = 1; load(); } },
      field('Action', action), field('Outcome', outcome), field('Actor', actor), field('Document id', docId),
      field('From', from), field('To', to), h('button', { class: 'primary', type: 'submit' }, 'Filter'))),
    h('section', { class: 'panel' }, out));
  load();
}

async function renderAdminDocuments() {
  const data = await attempt(() => api('GET', '/api/admin/documents'));
  if (!data) return;
  const detail = h('div');
  async function showAccess(d) {
    const a = await attempt(() => api('GET', `/api/admin/documents/${enc(d.id)}/access`));
    if (!a) return;
    detail.replaceChildren(h('section', { class: 'panel' }, h('h2', null, `Access to “${d.name}”`),
      h('p', { class: 'muted' }, 'Administrators can remove access here but can never add it, and can never open the document.'),
      table(['Person', 'Access', 'Expires', 'Source', ''], a.grants.map(g => h('tr', null,
        h('td', null, g.username, ' ', g.is_external ? badge('external') : null, !g.is_active ? badge('inactive') : null),
        h('td', null, permBadge(g.permission)), h('td', null, g.expires_at ? fmtDay(g.expires_at) : 'never'), h('td', null, g.source),
        h('td', null, h('button', { class: 'small danger', onclick: async () => {
          if (await attempt(() => api('DELETE', '/api/admin/grants/' + enc(g.id)), 'Grant revoked')) showAccess(d);
        } }, 'Revoke')))), 'Only the owner has access.'),
      h('h3', null, 'Share links'),
      table(['Label', 'Used', 'Expires', 'Revoked', ''], a.share_links.map(l => h('tr', null,
        h('td', null, l.label || '—'), h('td', null, `${l.use_count} / ${l.max_uses}`), h('td', null, fmtDate(l.expires_at)),
        h('td', null, l.revoked_at ? fmtDate(l.revoked_at) : ''),
        h('td', null, l.revoked_at ? null : h('button', { class: 'small danger', onclick: async () => {
          if (await attempt(() => api('POST', `/api/admin/share-links/${enc(l.id)}/revoke`), 'Link revoked')) showAccess(d);
        } }, 'Revoke')))), 'No links.')));
  }
  const rows = data.items.map(d => h('tr', { class: 'clickable', onclick: () => showAccess(d) },
    h('td', null, h('strong', null, d.name)), h('td', null, d.owner_username, ' ', !d.owner_active ? badge('inactive') : null),
    h('td', null, badge(d.category, 'cat')), h('td', null, String(d.grants)), h('td', null, String(d.active_links)),
    h('td', null, String(d.versions)), h('td', null, d.purged_at ? badge('destroyed', 'revoked') : d.deleted_at ? badge('trash', 'expired') : badge('active'))));
  shell('access', h('h1', null, 'Access review'),
    h('p', { class: 'muted' }, 'Metadata only. Click a document to see who can reach it.'),
    h('section', { class: 'panel' }, table(['Document', 'Owner', 'Category', 'Grants', 'Live links', 'Versions', 'State'], rows)),
    detail);
}

// ------------------------------------------------------------------- router
async function ensureSession() {
  if (state.user) return true;
  try {
    const me = await api('GET', '/api/auth/me', undefined, { quiet401: true });
    state.user = me.user; state.csrf = me.csrf_token;
    return true;
  } catch (_) { return false; }
}

async function route() {
  const hash = location.hash || '#/';
  if (hash === '#/login') { if (await ensureSession()) { location.hash = '#/'; return; } renderLogin(); return; }
  if (!(await ensureSession())) { location.hash = '#/login'; return; }
  if (!state.meta) state.meta = await attempt(() => api('GET', '/api/meta'));
  let parts;
  try { parts = hash.slice(2).split('/').map(decodeURIComponent); } catch (_) { parts = ['documents']; }
  const admin = state.user.role === 'admin';
  switch (parts[0]) {
    case 'doc': return renderDocument(parts[1]);
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
