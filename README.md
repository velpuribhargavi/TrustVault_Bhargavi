# TrustVault
Live Url:https://trustvault-xfsj.onrender.com
The Backup code will display on Render website.

Secure document sharing where **the wrong person can never read the file** and you can **prove who read it**.

- Every document is shared with **named people** only, and the owner picks a level for each person:
  **View only** (read it in the browser, watermarked - the file itself is never sent), **View + download**, or **Edit**.
  The server checks it on **every request**, through **one access-check function**.
- **Access is time-limited**: every grant ends on its own (30 minutes unless the owner picks longer), and the owner
  can extend or revoke it. **Share links** work for **5 minutes**, for **one named person**, signed in as themselves.
- Every refusal gets the **same answer** - *"You don't have access to this file."* - so nobody can probe what exists.
  The real reason is written to the audit trail.
- Sessions end after **15 minutes without activity** (with a warning and *Stay signed in*) or **8 hours**, whatever happens.
  You can see every device you are signed in on and **sign any of them out** - or all of them - at once.
- **Two-step sign-in** (authenticator app codes, with backup codes) is **required for administrators and owners**:
  a stolen password alone opens nothing. Five failures - wrong passwords or wrong codes - lock the account for 15 minutes.
- Administrators see grants **nobody has used for 30 days** and can revoke them in bulk.
- Someone who hits *"You don't have access"* can **request access**; the owner **approves** (choosing the level and for
  how long) or **denies** with a reason, and the person sees the status. Asking never reveals whether a document exists.
- Every document carries a **label - Public, Internal or Confidential** - shown as a badge everywhere. Confidential
  pages are marked *CONFIDENTIAL* with the reader's name, and new access to them is **View only for 1 hour** by default.
  A label never grants access: *Public* still means "only the people it is shared with".
- Files are validated, then **encrypted at rest** (AES-256-GCM, one key per file version).
- Every upload, view, download, change, deletion, permission change - **and every refusal** - goes into an **HMAC hash-chained, append-only audit trail** with external anchors. Tampering is detected and raised as a critical alert.
- The administrator's **audit page** reads like plain English (*"Refused to download “Salary letter”: their access is View only"*),
  filters by action, denial reason and quick filters, shows every event of a sign-in session together, checks the
  whole chain on demand (*"Chain intact (1,234 events)"*) and exports to CSV with the file's **SHA-256 recorded in the trail**.
- **Revoking access works on the next request**: no cached permissions, no long-lived tokens.
- Administrators manage people and read the audit trail but **cannot open documents** and can only ever **remove** access.

Stack: **Python 3.10+, FastAPI, SQLite, vanilla JS**. One dark theme for every role - jet black, cerulean for
actions and allowed access, neon rose for anything denied, expired or dangerous - defined once as CSS variables in
`trustvault/static/style.css`, WCAG AA contrast, works at phone width. See [WRITEUP.md](WRITEUP.md) for why.

| Document | What it is |
|---|---|
| [THREATS.md](THREATS.md) | 85 threats, what was done about each, the test that proves it, what remains |
| [API.md](API.md) | Every endpoint and exactly who may call it |
| [WRITEUP.md](WRITEUP.md) | What was built, what was deliberately not built, the permission model, AI use |
| [PROMPTS.md](PROMPTS.md) | Dated log of AI use, including where the AI was wrong |
| `trustvault/schema.sql` | Database schema |

---

## 1. Run it (Windows)

Prerequisite: **Python 3.10 or newer** from https://www.python.org/downloads/ (tick *"Add python.exe to PATH"* during install).

```bat
cd C:\TrustVault
setup.bat        REM creates .venv, installs packages, creates the database, keys and demo data
run.bat          REM starts the server
```

Open **http://127.0.0.1:8000** and sign in with one of the three logins below.

> Already ran an older version? Run `setup.bat` once more (it installs `segno`, which draws the QR code for
> two-step sign-in), then start it. A schema v3, v4 or v5 database is **upgraded in place** at start-up -
> every document, grant and audit event is kept and the audit chain still verifies (`python scripts/migrate.py` does
> the same on purpose, after taking a backup). Only a database older than v3 needs `reset.bat`; the app tells you.
> Upgraded documents are labelled *Internal*. To get the demo two-step keys and the demo labels below on an existing
> database, run `reset.bat` (otherwise the admin and owner are asked to set up two-step sign-in with their own phone at
> their next sign-in).

### Same thing by hand (Windows PowerShell, macOS or Linux)

```bash
cd TrustVault
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/init_db.py --seed      # schema + keys + demo users/documents
python -m trustvault                  # http://127.0.0.1:8000   (add --port 9000 to change port)
```

> If PowerShell refuses to run `Activate.ps1`, either use `cmd` with `setup.bat`, or run
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

### The three logins

| Role | Username | Password | What this role can do |
|---|---|---|---|
| **Administrator** | `admin` | `Keeper!Vault2026` | **Users:** create, list, change role, deactivate / re-activate, reset password, unlock, sign out everywhere, **delete**. **Oversight:** audit trail, alerts, integrity check, access review, emergency revoke. **Cannot** open any document or give anyone access. |
| **Document owner** | `owner` | `Author!Vault2026` | **Documents:** upload (create), search and open (read), rename / recategorise / new version (update), move to trash / restore / destroy (delete). **Sharing:** give each person *View only*, *View + download* or *Edit* for a chosen time (5 minutes, 30 minutes, 1 hour, 1 day, 7 days or a custom end; default 30 minutes); extend, change or revoke it; send a person who has access a 5-minute share link; see who opened the document (but not why someone was refused - that is for admins). **Labels:** Public / Internal / Confidential at upload, changeable later. **Requests:** approve (level and duration) or deny (with a reason) requests for access to their documents. |
| **Viewer** | `viewer` | `Reader!Vault2026` | Only documents shared with them, at the level the owner chose. Can **ask** the owner for access to a document. Cannot upload, delete, share or change a label. |

**Administrator and owner: after the password, a 6-digit code.** Two-step sign-in is required for these roles. The
*demo* accounts use published keys so anyone can sign in - add one to any authenticator app (Google Authenticator,
Microsoft Authenticator, 1Password, Authy: *Add account → Enter a setup key*, time-based), or scan its QR code:

| Account | Setup key | QR code |
|---|---|---|
| `admin` | `DOO6 FYAT PLLH M2EP 7AHY FUIJ VMOG UMF3` | [docs/demo-2fa/admin-demo-qr.png](docs/demo-2fa/admin-demo-qr.png) |
| `owner` | `OY6Q L5X3 4F2D ETHP QY6Y E7ZM X7R3 UBXY` | [docs/demo-2fa/owner-demo-qr.png](docs/demo-2fa/owner-demo-qr.png) |

No phone at hand? On the computer running TrustVault: `python scripts\demo_code.py` prints both current codes
(`--watch` keeps printing). A code works **once**: if someone else just used it, wait for the next one (up to 30 s).
`init_db.py --seed` also prints ten single-use backup codes per account. In real use nobody shares a key: each person
scans their own QR code at their first sign-in. (To switch the requirement off for a quick local try:
`set TRUSTVAULT_TOTP_REQUIRED_ROLES=` before `run.bat`.)

What `viewer` gets with the demo data (all owned by `owner`):

| Document | Label | Level the owner gave `viewer` | So the viewer can... |
|---|---|---|---|
| Salary letter - Vikram (2-page PDF) | Confidential | **View only** | read it page by page in the browser, every page marked *CONFIDENTIAL* with their name; no Download button, download URL refused |
| Office floor plan (image) | Public | **View only** | see it, watermarked |
| Q3 services contract - Acme Corp (Word) | Internal | **View + download** | read it and download the original |
| Budget 2026 (CSV) | Internal | **Edit** | read, download, rename, upload a new version |
| Board minutes - private (PDF) | Confidential | *nothing* | nothing - *"You don't have access to this file."*, the same as for a document that does not exist. They can **request access**. |
| Audit papers FY2025-26 (CSV) | Confidential | *nothing* | nothing (try requesting access, then approve it as `owner`) |

The seed also contains *Ravi Rao (contractor)* - not a login - who was given access to the Q3 contract 45 days ago and
never used it: what Admin → **Access review → Unused access** is there to find.

The demo grants last **7 days** so the demo data keeps working; a grant made in the UI lasts 30 minutes unless the
owner picks longer. These are demo credentials - change them before any real use.

### Time limits (all in one place: `trustvault/config.py`)

| Limit | Value | What happens |
|---|---|---|
| `DEFAULT_GRANT_MINUTES` | 30 | A grant without a chosen duration ends after 30 minutes. The owner picks 5 min, 30 min, 1 hour, 1 day, 7 days or a custom end, and can **Extend** or **Revoke** at any time. The expiry is written to the audit trail (`access.expired`). |
| `LINK_TTL_SECONDS` | 300 | A share link works for 5 minutes, only for the person it names, only while they are signed in **and still hold a live grant** - a link never gives access on its own. *Revoke all links* - or taking anyone's access away - kills every outstanding link at once. |
| `SESSION_IDLE_MINUTES` | 15 | No request for 15 minutes signs you out. One minute before, the page asks *"Are you still there?"* with **Stay signed in**. After signing in again you land back on the page you were on. |
| `SESSION_MAX_HOURS` | 8 | Eight hours after sign-in the session ends however active you are. |
| `CONFIDENTIAL_GRANT_MINUTES` | 60 | New access to a **Confidential** document - given by hand or by approving a request - defaults to View only for 1 hour. The owner can still choose more, explicitly. |
| `ACCESS_REQUEST_DAYS` | 14 | A request for access nobody answers lapses after 14 days (and can be sent again). |

Each can be overridden with an environment variable (`TRUSTVAULT_LINK_TTL_SECONDS=60`, ...).

### Try a share link (2 minutes)

1. Sign in as `owner` in one browser window, open *Salary letter - Vikram* (Vikram already has View only access) → **Share link** → *Vikram Viewer* → **Create link** → **Copy link**.
2. Open the link in a **private window**. You are asked to sign in; sign in as `viewer` and you land on the document, with a 5-minute countdown.
   (A link can only be made for someone who already has access, at most at their level.)
3. Sign in as anyone else and open the same link: *"You don't have access to this file."* (and the admin sees a *"Share link used by someone it was not made for"* alert).

### Try a request for access (2 minutes)

1. As `viewer`, paste the id of *Audit papers FY2025-26* (Admin → Access review lists ids) after `#/doc/` →
   *"You don't have access to this file."* → **Request access** → pick *View + download*, add a note → **Send request**.
   (Paste a made-up id instead: the answer is word for word the same - asking never tells you what exists.)
2. As `owner`: **Documents** → *Requests waiting for you*. Because the document is Confidential the answer starts at
   **View only, 1 hour** → **Approve** (or **Deny** with a reason).
3. As `viewer`: **Documents** → *My requests* shows *Approved* with the countdown (or *Denied* and the owner's reason);
   open the document: every page is marked *CONFIDENTIAL · viewer · time*.
4. Admin → Audit trail: `access.requested`, `access.request_approved` / `access.request_denied`, `access.granted`.

### The three access levels

| | View only | View + download | Edit | Owner |
|---|:-:|:-:|:-:|:-:|
| See it in the list and its details | ✔ | ✔ | ✔ | ✔ |
| Read it in the browser (watermarked rendering) | ✔ | ✔ | ✔ | ✔ |
| Download the original file (any version) | ✘ | ✔ | ✔ | ✔ |
| Rename, recategorise, describe, upload a new version | ✘ | ✘ | ✔ | ✔ |
| Share / revoke / external links / see activity | ✘ | ✘ | ✘ | ✔ |
| Trash, restore, destroy | ✘ | ✘ | ✘ | ✔ |

View-only users are sent a **rendering**, never the file: PDF pages and images as PNGs with the viewer's name and the
time tiled across them. Word/Excel/PowerPoint are shown **as real pages** when [LibreOffice](https://www.libreoffice.org/)
is installed on the server (it is found automatically; `TRUSTVAULT_OFFICE_RENDERER=off` turns it off), otherwise as
extracted text with the same watermark line. Every page opened is in the audit trail. (A screenshot is still possible -
see THREATS.md T60 - but the file never leaves and any leaked picture names who it was rendered for.)

### The audit trail page (administrator)

Admin → **Audit trail**:

| Feature | How it works |
|---|---|
| **Action** dropdown | Filled from the actions actually in the database, grouped (Documents, Access, Share links, ...), with counts. "All: documents" etc. selects a whole group. |
| **Denial reason** dropdown | Every internal reason a request was refused for (`no_grant`, `view_only`, `grant_expired`, `wrong_user`, `role_required`, ...), in words, with counts. |
| **Quick filters** | *Denied only*, *Last 24 hours*, *Downloads*, *Sharing changes*, *Expired access*. They combine with each other and with the form. |
| **Plain language** | Each event is a sentence - `{"mode":"cookie"}` reads *"Signed in (browser session)"*. **{ } JSON** under it shows the raw details. |
| **Detail panel** | Click a row: the full event, IP, user agent, its hash and the previous hash, a check that this event's hash still matches and links to the one before, and **every other event from the same sign-in session** (*Show this session in the table*). |
| **Verify integrity** | Recomputes the whole chain and the external anchors: *"Chain intact (N events)"* or *"Chain broken at event #N"* / *"event #N is missing"*. Each verification is itself logged. |
| **Export CSV** | Exports exactly what is filtered. The response carries the file's **SHA-256**, the browser recomputes it, and the export (who, filters, rows, hash) is written to the audit trail - so the file can later be proven unchanged. Cells that a spreadsheet would run as a formula (`=`, `+`, `-`, `@`) are prefixed with `'`. |

Check an exported file yourself: `certutil -hashfile trustvault-audit-....csv SHA256` (Windows) or `sha256sum` - it must equal the
hash shown on screen and in the `audit.export` event.

---

## 2. Security controls - and how to show each one

Every control below is enforced by the server, has automated tests (`tests/`), and is listed in
[THREATS.md](THREATS.md) with the threat it answers. Demo steps assume `run.bat` and the three demo logins.
Two browser windows (one normal, one private) make the "two people" demos easy.

| # | Control | How to demo it (about a minute each) | Proven by |
|---|---|---|---|
| 1 | **One access check for every file request** (`authz.check_access`, called first by every document route) | As `viewer`, paste `#/doc/<id of Board minutes>` (Admin → Access review shows ids) → *"You don't have access to this file."* | `test_authz_matrix.py` (18 actions × 9 kinds of caller); a test parses every route |
| 2 | **One answer to every refusal** - the real reason goes to the audit trail only | As `viewer`, open a made-up id (`#/doc/AAAAAAAAAAAAAAAAAAAAAA`) and the private board minutes: same page. Admin → Audit trail → *Denied only*: `not_found` vs `no_grant` | `test_authz_unit.py::test_document_reasons`, `test_only_admins_see_why_a_request_was_refused` |
| 3 | **View-only download block** - a View-only person is sent watermarked page images, never the file | As `viewer`: *Salary letter* → **View** (pages carry their name and the time; no Download button). Paste `/api/documents/<id>/download` in the address bar → refused | `test_view_levels.py`, attack script "viewer CANNOT download the view-only file" |
| 4 | **Every grant expires** (30 minutes unless the owner picks longer) | As `owner`: give someone access for **5 minutes** → live countdown; when it ends they are refused and the trail shows `access.expired` | `test_time_limits.py` (server clock moved, no waiting) |
| 5 | **Instant revoke** - no cached permissions, no long-lived tokens | Window 1 `viewer` opens *Q3 contract*. Window 2 `owner` → *Who has access* → **Revoke**. Window 1 clicks **View** → refused on the very next click | `test_revocation.py` |
| 6 | **5-minute share links for one named person** (signed, not stored, need a live grant) | `owner` → *Salary letter* → **Share link** → Vikram → copy → open in the `viewer` window: countdown from 5:00. After 5 minutes (record with `set TRUSTVAULT_LINK_TTL_SECONDS=60` to wait 1 min) it is refused (`link_expired`). Opened by anyone else → refused (`wrong_user`) and an alert | `test_links.py::test_link_works_at_4_59_and_fails_at_5_01`, `test_forwarded_link_is_useless_to_anyone_else` |
| 7 | **Revoke all links** - any reduction of access kills every outstanding link of that document | `owner` → **Revoke all links** (or revoke anyone) → the link from step 6 stops at once | `test_links.py`, `test_access_review.py::test_bulk_revoke_kills_outstanding_share_links_of_the_document` |
| 8 | **Administrators never read content** and can only reduce access | As `admin`: no *Open* anywhere; `/api/documents/<id>/download` → refused; there is no endpoint to give an admin access | `test_admin.py::test_admin_sees_metadata_but_never_content` |
| 9 | **Unused-access review + bulk revoke** (no use in 30 days, read from the audit trail) | `admin` → **Access review**: *Ravi Rao (contractor)*, unused 45 days → **Revoke selected** → gone; the document's `access_version` went up, so its share links died too | `test_access_review.py` (6 tests) |
| 10 | **Two-step sign-in (TOTP)** required for administrators and owners; QR set-up, 10 backup codes, a code never works twice | Sign in as `admin` → after the password, *Two-step sign-in* asks for a code (use the demo key above). Type a wrong code → refused, `auth.2fa_failed` in the trail. Create a new owner (Admin → Users) and sign in as them → forced set-up with a **QR code** → backup codes shown once | `test_two_factor.py` (26 tests incl. RFC 6238 vectors, replay, lockout, backup codes) |
| 11 | **Sign-in rate limit + temporary lockout** - both audited | Type a wrong password 5 times for `viewer` → locked for 15 minutes even with the right password; Audit trail shows `auth.account_locked`. 20 attempts a minute from one address → *Too many sign-in attempts* (`rate_limited`) | `test_auth.py`, `test_account_sessions.py::test_lockout_and_rate_limit_each_write_an_audit_event` |
| 12 | **Your sessions, ended on the server** - sign out one device or everywhere | Sign in as `viewer` in both windows → **Account → Where you are signed in** lists both (device, IP, last active) → **Sign out** the other → its next click goes to sign-in | `test_account_sessions.py` |
| 13 | **Idle and maximum session time** (15 minutes / 8 hours) with a warning | Leave a window alone: *"Are you still there?"* one minute before; no answer → signed out, recorded as `auth.session_expired` | `test_sessions.py` |
| 14 | **Passwords**: Argon2id, 12+ characters, common passwords refused; changing it signs out every other session | Account → **Change password** with `password1234` → refused | `test_auth.py::test_password_policy`, `test_passwords_are_argon2id_hashed` |
| 15 | **Cookies and CSRF**: session cookie `HttpOnly`, `SameSite=Strict`, `Secure` whenever HTTPS is used (`__Host-` prefix with `TRUSTVAULT_COOKIE_SECURE=1`); every change needs the `X-CSRF-Token` header | Browser DevTools → Application → Cookies → `tv_session`. A request without the header → 403 | `test_account_sessions.py::test_the_session_cookie_is_httponly_samesite_and_secure_over_https`, `test_csrf_token_required_for_cookie_requests` |
| 16 | **Security headers**: Content-Security-Policy (`script-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` | `curl -I http://127.0.0.1:8000/` (or DevTools → Network → any response) | `test_http_hardening.py`, `test_security_headers_on_every_kind_of_response` |
| 17 | **Upload validation**: type allow-list + magic bytes + active-content checks (HTML, SVG, PDF JavaScript, macros, zip bombs, CSV formulas) | As `owner`, upload a `.html`, or an `.exe` renamed to `.pdf` → refused, and audited | `test_uploads.py` |
| 18 | **Encryption at rest**: AES-256-GCM, one key per file version, wrapped by a master key outside the database; destroying a document shreds its keys | Open any file in `instance\blobs\` - random bytes. Trash → **Destroy** → the key is gone, the bytes can never be read | `test_storage.py::test_files_are_encrypted_at_rest` |
| 19 | **Audit trail of every action and refusal**, in plain language, with the internal reason | Admin → **Audit trail** → *Denied only*, the *Denial reason* dropdown, click a row: the full event, its hash and the rest of that sign-in session | `test_audit.py`, `test_audit_page.py` |
| 20 | **Audit tamper detection**: append-only triggers + HMAC hash chain (key outside the database) + external anchors | `python scripts\tamper_demo.py` - on a copy: an edited row → *"Chain broken at event #2"*; deleted newest rows → *"event #N is missing"*. Admin → Audit trail → **Verify integrity** → *"Chain intact (N events)"* | `test_audit.py` (edit, delete, re-order, truncate, re-hash) |
| 21 | **Evidence export**: CSV of the filtered trail with its SHA-256 recorded in the trail; spreadsheet formulas neutralised | Audit trail → **Export CSV** → `certutil -hashfile <file> SHA256` equals the hash on screen and in the `audit.export` event | `test_audit_page.py::test_export_is_the_filtered_view_and_its_sha256_is_logged`, `test_exported_cells_cannot_run_as_spreadsheet_formulas` |
| 22 | **Alerts**: probing, guessing, credential stuffing, bulk downloads, forwarded or forged links, admin password / two-step resets, *right password + wrong codes* | Run the attack script, then Admin → **Overview → Worth noticing** | `test_admin.py` (alert tests), `test_two_factor.py::test_repeated_wrong_codes_after_a_right_password_raise_an_alert` |
| 23 | **Request access, decided by the owner** - asking never reveals whether a document exists; only the document's owner can approve (level + duration) or deny (reason); requested / approved / denied all audited | As `viewer`: open the *Audit papers* id → **Request access** → send. Then a made-up id → the same answer. As `owner`: *Requests waiting for you* → **Approve**. As `viewer`: *My requests* → *Approved*, countdown. (Steps: "Try a request for access" above.) | `test_access_requests.py` (15 tests), attack script |
| 24 | **Classification labels** - Public / Internal / Confidential at upload (default Internal), owner-only changes, each audited; Confidential pages marked *CONFIDENTIAL*, View only for 1 hour by default, raising to Confidential kills old share links; a label never grants access | As `owner`: **Upload** → *Classification*; a document → *Classification* → change → Audit trail shows `document.classified` from → to. As `viewer`: the *Salary letter* pages carry *CONFIDENTIAL · viewer* | `test_classification.py` (9 tests), attack script |
| 25 | **The tests really test the checks** (mutation testing) | `mutation.bat` removes each of the 71 tagged checks in turn and shows a test fails every time (`docs\mutation_report.txt`) | `tools/mutation_check.py` |
| 26 | **Attack the running system** | `python scripts\attack_selftest.py` - 64 real HTTP attacks as admin, owner and viewer, PASS/FAIL each | `scripts/attack_selftest.py` |

---

## 3. Test it

```bat
test.bat                         REM or: python -m pytest
```

**507 tests** run in about two minutes. They include:

- `tests/test_authz_matrix.py` - **every document endpoint × every kind of caller** (owner, edit, download, view-only, no grant, expired grant, admin, anonymous - 162 cases). Each refusal is checked to be *the same 403 message*, to have *no side effect* and to leave *an audit record with the right internal reason*. A structural test proves every document route calls `require_access()` first.
- `tests/test_authz_unit.py` - `check_access()` itself: every refusal reason, in order (`not_found`, `no_grant`, `grant_expired`, `view_only`, `wrong_user`, `link_expired`, `link_revoked`, ...).
- `tests/test_time_limits.py`, `tests/test_links.py`, `tests/test_sessions.py` - 30-minute grants, extend/revoke, `access.expired`, 5-minute recipient-bound links, 15-minute idle and 8-hour sessions - with the server clock moved forward, no sleeping.
- `tests/test_view_levels.py` - view-only users get watermarked renderings and can never download; each level allows exactly what it says; text extraction for Word/Excel/PowerPoint; XML bombs are not expanded.
- `tests/test_idor.py` - cross-object attacks (version / grant / link / suggestion of another document).
- `tests/test_revocation.py` - revoke, deactivate, password change, logout, idle and absolute expiry: all immediate.
- `tests/test_audit.py` - edits, deletions, re-ordering, truncation and re-hashing of the audit log are all detected.
- `tests/test_audit_page.py` - the audit page through the API: admin-only (and refusals recorded), the action dropdown matches the database, denial-reason and quick filters, plain-language sentences for every action and reason, the detail panel's hash check and same-session events, CSV export (filters, SHA-256 logged, formula injection neutralised, chain columns link up, size limit), *"Chain intact (N events)"* / first broken or missing event, and that each filter uses its index.
- `tests/test_migrations.py` - real v3, v4 and v5 databases are upgraded in place with their chain intact; an audit table without hashes gets them backfilled; too-old / too-new databases are refused clearly.
- `tests/test_two_factor.py` - two-step sign-in: RFC 6238 test vectors, no session before the second step, forced set-up for admins and owners (and a wrong first code turns nothing on), codes never reused, 3 wrong codes end the attempt, 5 failures lock the account, backup codes single-use and per person, secrets sealed and never sent out, admin reset, bearer mode, the alert.
- `tests/test_account_sessions.py` - session list (only your own), sign out one / everywhere on the server, cookie flags over HTTP, HTTPS and behind a proxy, security headers, lockout and rate-limit audit events.
- `tests/test_access_review.py` - grants unused for 30 days flagged from the audit trail, bulk revoke bumps each document's `access_version` once and kills its links, admin only.
- `tests/test_access_requests.py` - ask → approve with level and duration / deny with a reason; the same answer for a made-up id; only the document's owner decides (and only once, only while pending); requests private to the asker; spam limits; 14-day lapse; Confidential defaults; every step audited.
- `tests/test_classification.py` - default Internal, owner-only changes (each audited from → to), CONFIDENTIAL on every rendered page, View only for 1 hour, raising to Confidential kills share links, the badge in every list, Public opens nothing.
- `tests/test_uploads.py` - executables, HTML/SVG, PDF JavaScript, Office macros, remote templates, zip bombs, CSV formula injection...
- and Office rendering, search leakage, CSRF, storage encryption, admin limits, AI suggestions, HTTP hardening.

### Prove the tests test something (mutation check)

The judges will remove one authorisation check and re-run the tests. This tool does that for **every** check:

```bat
mutation.bat                     REM or: python tools/mutation_check.py --jobs 4
python tools/mutation_check.py --list    REM see each check and how it is removed
```

Every security check in the code is tagged `# AUTHZ-CHECK[name]` (or `AUTHZ-SQL`). The tool copies the project,
removes one check (turns `if <deny-condition>:` into `if False:`, or blanks the SQL filter), runs the suite, and
requires it to **fail**. Result: **71/71 mutants killed** - removing any single check breaks at least one test
(full report: `docs/mutation_report.txt`).

### Attack the running system

With the server running, in a second terminal:

```bat
.venv\Scripts\activate
python scripts\attack_selftest.py        REM 64 real HTTP checks as admin/owner/viewer; PASS/FAIL for each
python scripts\verify_audit.py           REM offline audit-chain verification (exit code 1 if tampered)
python scripts\tamper_demo.py            REM edits a COPY of the audit log and shows detection
python scripts\migrate.py                REM backup + schema upgrade + "Chain intact (N events)" (start-up does this too)
python scripts\demo_code.py              REM current two-step codes of the demo admin and owner
```

---

## 4. How it is built

```
trustvault/
  config.py        every time limit in one place (LINK_TTL_SECONDS, DEFAULT_GRANT_MINUTES, SESSION_*)
  authz.py         THE permission model - check_access(); every document route calls require_access() first
  links.py         signed 5-minute share links bound to one person who holds a grant (HMAC, not stored)
  expiry.py        writes access.expired to the audit trail when a grant runs out
  deps.py          session lookup (every request), CSRF, role checks
  totp.py          RFC 6238 codes, backup codes, the enrolment QR code
  twofactor.py     two-step sign-in: challenges, enrolment, verification, backup codes (secrets sealed per user)
  lockout.py       5 failures (passwords or codes) lock the account for 15 minutes, audited
  audit.py         append-only HMAC hash chain + external anchors + verify()
  audit_text.py    audit events in plain language (audit page, CSV export)
  migrations.py    in-place schema upgrades (v3 -> v6) and hash backfill for a pre-chain audit table
  classification.py  Public / Internal / Confidential: defaults (View only, 1 hour) and the CONFIDENTIAL page mark
  crypto.py        AES-256-GCM envelope encryption, per-version keys, crypto-shredding
  validation.py    file-type allow-list, magic bytes, active-content checks, filename sanitising
  preview.py       view-only rendering: PDF / images / Office (via LibreOffice) as watermarked PNG pages, else text
  storage.py       encrypted blob store (random ids, outside any served folder)
  alerts.py        "worth noticing" rules for the administrator
  suggestions.py   local, explainable "who should see this?" suggestions (never grants)
  routes/          auth, documents, sharing (grants, links, suggestions), access_requests, admin
  static/          single-page UI (no innerHTML; strict CSP)
  schema.sql       database schema with append-only triggers
scripts/           init_db (setup + seed), migrate, demo_code, verify_audit, tamper_demo, attack_selftest
tools/             mutation_check (proves tests catch a removed check)
tests/             pytest suite
```

Sign-in with two-step sign-in (no session exists until both steps pass):

```
POST /api/auth/login         password  ─► wrong: audited, counts towards the lockout
                                       ─► right, 2-step on:  {"two_factor": "verify", "challenge"}   (5 min, 3 tries)
                                       ─► right, admin/owner without it: {"two_factor": "enroll", QR, key}
POST /api/auth/login/verify  challenge + 6-digit code or backup code ─► session cookie (HttpOnly, SameSite=Strict, Secure on HTTPS)
POST /api/auth/login/enroll  challenge + first code ─► session + 10 backup codes (shown once)
```

Request path for a download:

```
cookie/bearer token ─► deps.current_principal ─► sessions ⋈ users   (exists? idle < 15 min? < 8 h? user active? CSRF for writes)
                    ─► authz.require_access(user, doc, DOWNLOAD, link?)
                         check_access: document exists → user active → not admin → owner / live grant / valid link
                                       for this person → not in trash → level allows it → version belongs to it
                         └─ refused → audit 'denied' row with the reason → 403 "You don't have access to this file."
                    ─► decrypt blob (AAD = doc id + version id) ─► verify SHA-256
                    ─► audit 'allowed' row (BEFORE any byte is sent; if this fails, nothing is sent)
                    ─► response: attachment, nosniff, CSP sandbox, no-store
```

---

## 5. Operating it

| Task | How |
|---|---|
| Back up | Stop the server; copy `instance/` **except** `instance/keys/`, and store the keys separately (offline / secret manager). Data without keys is unreadable - by design. |
| Verify the audit trail | Admin → Audit trail → **Verify integrity** (or Overview), or `python scripts/verify_audit.py` |
| Hand evidence to someone | Admin → Audit trail → filter → **Export CSV**. Give them the file and its SHA-256; the `audit.export` event records both. |
| Upgrade after pulling new code | Just start it (`run.bat`): the database is upgraded in place and the upgrade is logged as `audit.migrated`. `python scripts/migrate.py` does it on purpose with a backup first. |
| Someone leaves | Admin → Users → **Deactivate**. Their sessions end, their grants stop working, share links they made or were sent stop working - immediately. Reversible. |
| Remove an account for good | Admin → Users → **Delete**. Same as deactivate, plus their grants are removed and the account can never be re-activated or its username re-used. The record stays so the audit trail still names them. Owners must have their documents destroyed first. |
| A link leaked | It only works for the person it names, and for 5 minutes. To kill it sooner: Owner → document → *Share link* → **Revoke all links** (or Admin → Access review → **Revoke all links**). |
| Access should end sooner / later | Owner → document → *Who has access* → **Extend** or **Revoke**. |
| Someone asks for access | Owner → **Documents** → *Requests waiting for you* → pick the level and duration → **Approve**, or **Deny** with a reason they will see. Unanswered requests lapse after `ACCESS_REQUEST_DAYS` (14). |
| A document becomes sensitive | Owner → document → *Classification* → **Confidential**. Outstanding share links stop at once; existing grants are kept (revoke or shorten them under *Who has access*). |
| Locked-out user | Admin → Users → Unlock |
| Someone lost their phone | Admin → Users → *More* → **Reset two-step sign-in**. Their sessions end; administrators and owners set it up again at their next sign-in. (Your own is changed on the Account page, with your password and a code.) |
| A device was lost or a session looks wrong | The person: Account → **Where you are signed in** → *Sign out* that device, or *Sign out everywhere*. An admin: Users → *More* → *Sign out everywhere*. |
| Access nobody uses | Admin → Access review → **Unused access** (no use in `UNUSED_GRANT_DAYS`, default 30) → select → **Revoke selected**. |
| Retention | Trashed documents are crypto-shredded after `TRASH_RETENTION_DAYS` (default 30), checked at start-up. |
| Configuration | Environment variables, see `.env.example` (`TRUSTVAULT_COOKIE_SECURE=1` when served over HTTPS). |
| API docs (interactive) | http://127.0.0.1:8000/api/docs |

### Deploying beyond your own machine

The app binds to `127.0.0.1` by default. To expose it, put it behind a TLS-terminating reverse proxy
(Caddy / nginx / IIS), run `python -m trustvault --host 0.0.0.0`, and set `TRUSTVAULT_COOKIE_SECURE=1`,
`TRUSTVAULT_TRUST_PROXY=1` (only behind your proxy), and the two keys from a secret manager
(`TRUSTVAULT_MASTER_KEY`, `TRUSTVAULT_AUDIT_KEY`). Run a **single worker** (rate limiting is in-process; see THREATS.md T51).

## 6. Reset

```bat
reset.bat      REM deletes instance\ (database, files, keys, audit trail) and re-seeds
```
