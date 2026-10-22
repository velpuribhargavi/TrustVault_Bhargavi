'use strict';
// The token lives in the URL fragment (#...), which browsers never send to
// the server with the page request, so it stays out of logs and Referer.
(function () {
  let token = '';
  try { token = decodeURIComponent((location.hash || '').slice(1)); } catch (_) { token = ''; }
  const status = document.getElementById('share-status');
  const meta = document.getElementById('share-meta');
  const button = document.getElementById('share-download');
  const title = document.getElementById('share-title');

  function fail(msg) {
    status.textContent = msg;
    status.className = 'error';
    meta.classList.add('hidden');
    button.classList.add('hidden');
  }

  function row(label, value) {
    const dt = document.createElement('dt'); dt.textContent = label;
    const dd = document.createElement('dd'); dd.textContent = value;
    meta.append(dt, dd);
  }

  function size(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  async function post(path) {
    return fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }), credentials: 'omit', cache: 'no-store'
    });
  }

  async function load() {
    if (token.length < 10) { fail('This link is incomplete.'); return; }
    const res = await post('/api/public/share/info');
    if (!res.ok) { fail('This link is invalid, has expired or has been revoked.'); return; }
    const info = await res.json();
    title.textContent = info.name;
    status.textContent = 'Someone shared this document with you.';
    meta.textContent = '';
    row('File', info.filename);
    row('Size', size(info.size_bytes));
    row('Link expires', new Date(info.expires_at).toLocaleString());
    row('Downloads left', String(info.uses_left));
    meta.classList.remove('hidden');
    button.classList.remove('hidden');
    button.onclick = async () => {
      button.disabled = true;
      const r = await post('/api/public/share/download');
      if (!r.ok) { fail('This link is no longer valid.'); return; }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = info.filename; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      load();
    };
    button.disabled = info.uses_left <= 0;
  }

  load().catch(() => fail('Could not reach TrustVault.'));
})();
