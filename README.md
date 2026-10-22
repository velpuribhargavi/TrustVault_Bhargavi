# TrustVault

Secure document sharing where **the wrong person can never read the file** and you can **prove who read it**.

- Every document is shared with **named people** only, and the owner picks a level for each person:
  **View only** (read it in the browser, watermarked - the file itself is never sent), **View + download**, or **Edit**.
  The server checks it on **every request**, through **one access-check function**.
- **Access is time-limited**: every grant ends on its own (30 minutes unless the owner picks longer), and the owner
  can extend or revoke it. **Share links** work for **5 minutes**, for **one named person**, signed in as themselves.
- Every refusal gets the **same answer** - *"You don't have access to this file."* - so nobody can probe what exists.
  The real reason is written to the audit trail.
- Sessions end after **15 minutes without activity** (with a warning and *Stay signed in*) or **8 hours**, whatever happens.
- Files are validated, then **encrypted at rest** (AES-256-GCM, one key per file version).
- Every upload, view, download, change, deletion, permission change - **and every refusal** - goes into an **HMAC hash-chained, append-only audit trail** with external anchors. Tampering is detected and raised as a critical alert.
- **Revoking access works on the next request**: no cached permissions, no long-lived tokens.
- Administrators manage people and read the audit trail but **cannot open documents** and can only ever **remove** access.

Stack: **Python 3.10+, FastAPI, SQLite, vanilla JS**. See [WRITEUP.md](WRITEUP.md) for why.

| Document | What it is |
|---|---|
| [THREATS.md](THREATS.md) | 68 threats, what was done about each, the test that proves it, what remains |
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

> Already ran an older version? Run `reset.bat` once - the database format changed (schema v3: expiring grants and
> signed share links). The app tells you if you forget.

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
| **Document owner** | `owner` | `Author!Vault2026` | **Documents:** upload (create), search and open (read), rename / recategorise / new version (update), move to trash / restore / destroy (delete). **Sharing:** give each person *View only*, *View + download* or *Edit* for a chosen time (15 minutes to 90 days, default 30 minutes); extend, change or revoke it; make 5-minute share links for a named person; see who opened the document. |
| **Viewer** | `viewer` | `Reader!Vault2026` | Only documents shared with them, at the level the owner chose. Cannot upload, delete or share. |

What `viewer` gets with the demo data (all owned by `owner`):

| Document | Level the owner gave `viewer` | So the viewer can... |
|---|---|---|
| Salary letter - Vikram (2-page PDF) | **View only** | read it page by page in the browser, watermarked with their name; no Download button, download URL refused |
| Office floor plan (image) | **View only** | see it, watermarked |
| Q3 services contract - Acme Corp (Word) | **View + download** | read it and download the original |
| Budget 2026 (CSV) | **Edit** | read, download, rename, upload a new version |
| Board minutes - private (PDF) | *nothing* | nothing - *"You don't have access to this file."*, the same as for a document that does not exist |
| Audit papers FY2025-26 (CSV) | *nothing* | nothing - until the owner makes them a 5-minute share link |

The demo grants last **7 days** so the demo data keeps working; a grant made in the UI lasts 30 minutes unless the
owner picks longer. These are demo credentials - change them before any real use.

### Time limits (all in one place: `trustvault/config.py`)

| Limit | Value | What happens |
|---|---|---|
| `DEFAULT_GRANT_MINUTES` | 30 | A grant without a chosen duration ends after 30 minutes. The owner can pick 15 min ... 90 days or a date, and **Extend** or **Revoke** at any time. The expiry is written to the audit trail (`access.expired`). |
| `LINK_TTL_SECONDS` | 300 | A share link works for 5 minutes, only for the person it names, only while they are signed in. *Revoke all links* - or taking anyone's access away - kills every outstanding link at once. |
| `SESSION_IDLE_MINUTES` | 15 | No request for 15 minutes signs you out. Two minutes before, the page asks *"Are you still there?"* with **Stay signed in**. After signing in again you land back on the page you were on. |
| `SESSION_MAX_HOURS` | 8 | Eight hours after sign-in the session ends however active you are. |

Each can be overridden with an environment variable (`TRUSTVAULT_LINK_TTL_SECONDS=60`, ...).

### Try a share link (2 minutes)

1. Sign in as `owner` in one browser window, open *Audit papers FY2025-26* → **Share link** → person *Vikram Viewer* → **Create link** → **Copy link**.
2. Open the link in a **private window**. You are asked to sign in; sign in as `viewer` and you land on the document, with a 5-minute countdown.
3. Sign in as anyone else and open the same link: *"You don't have access to this file."* (and the admin sees a *"Share link used by someone it was not made for"* alert).

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

---

## 2. Test it

```bat
test.bat                         REM or: python -m pytest
```

**385 tests** run in about a minute. They include:

- `tests/test_authz_matrix.py` - **every document endpoint × every kind of caller** (owner, edit, download, view-only, no grant, expired grant, admin, anonymous - 153 cases). Each refusal is checked to be *the same 403 message*, to have *no side effect* and to leave *an audit record with the right internal reason*. A structural test proves every document route calls `require_access()` first.
- `tests/test_authz_unit.py` - `check_access()` itself: every refusal reason, in order (17 of them).
- `tests/test_time_limits.py`, `tests/test_links.py`, `tests/test_sessions.py` - 30-minute grants, extend/revoke, `access.expired`, 5-minute recipient-bound links, 15-minute idle and 8-hour sessions - with the server clock moved forward, no sleeping.
- `tests/test_view_levels.py` - view-only users get watermarked renderings and can never download; each level allows exactly what it says; text extraction for Word/Excel/PowerPoint; XML bombs are not expanded.
- `tests/test_idor.py` - cross-object attacks (version / grant / link / suggestion of another document).
- `tests/test_revocation.py` - revoke, deactivate, password change, logout, idle and absolute expiry: all immediate.
- `tests/test_audit.py` - edits, deletions, re-ordering, truncation and re-hashing of the audit log are all detected.
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
requires it to **fail**. Result: **42/42 mutants killed** - removing any single check breaks at least one test
(full report: `docs/mutation_report.txt`).

### Attack the running system

With the server running, in a second terminal:

```bat
.venv\Scripts\activate
python scripts\attack_selftest.py        REM 42 real HTTP checks as admin/owner/viewer; PASS/FAIL for each
python scripts\verify_audit.py           REM offline audit-chain verification (exit code 1 if tampered)
python scripts\tamper_demo.py            REM edits a COPY of the audit log and shows detection
```

---

## 3. How it is built

```
trustvault/
  config.py        every time limit in one place (LINK_TTL_SECONDS, DEFAULT_GRANT_MINUTES, SESSION_*)
  authz.py         THE permission model - check_access(); every document route calls require_access() first
  links.py         signed 5-minute share links bound to one person (HMAC, not stored)
  expiry.py        writes access.expired to the audit trail when a grant runs out
  deps.py          session lookup (every request), CSRF, role checks
  audit.py         append-only HMAC hash chain + external anchors + verify()
  crypto.py        AES-256-GCM envelope encryption, per-version keys, crypto-shredding
  validation.py    file-type allow-list, magic bytes, active-content checks, filename sanitising
  preview.py       view-only rendering: PDF / images / Office (via LibreOffice) as watermarked PNG pages, else text
  storage.py       encrypted blob store (random ids, outside any served folder)
  alerts.py        "worth noticing" rules for the administrator
  suggestions.py   local, explainable "who should see this?" suggestions (never grants)
  routes/          auth, documents, sharing (grants, links, suggestions), admin
  static/          single-page UI (no innerHTML; strict CSP)
  schema.sql       database schema with append-only triggers
scripts/           init_db (setup + seed), verify_audit, tamper_demo, attack_selftest
tools/             mutation_check (proves tests catch a removed check)
tests/             pytest suite
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

## 4. Operating it

| Task | How |
|---|---|
| Back up | Stop the server; copy `instance/` **except** `instance/keys/`, and store the keys separately (offline / secret manager). Data without keys is unreadable - by design. |
| Verify the audit trail | Admin → Overview → *Verify now*, or `python scripts/verify_audit.py` |
| Someone leaves | Admin → Users → **Deactivate**. Their sessions end, their grants stop working, share links they made or were sent stop working - immediately. Reversible. |
| Remove an account for good | Admin → Users → **Delete**. Same as deactivate, plus their grants are removed and the account can never be re-activated or its username re-used. The record stays so the audit trail still names them. Owners must have their documents destroyed first. |
| A link leaked | It only works for the person it names, and for 5 minutes. To kill it sooner: Owner → document → *Share link* → **Revoke all links** (or Admin → Access review → **Revoke all links**). |
| Access should end sooner / later | Owner → document → *Who has access* → **Extend** or **Revoke**. |
| Locked-out user | Admin → Users → Unlock |
| Retention | Trashed documents are crypto-shredded after `TRASH_RETENTION_DAYS` (default 30), checked at start-up. |
| Configuration | Environment variables, see `.env.example` (`TRUSTVAULT_COOKIE_SECURE=1` when served over HTTPS). |
| API docs (interactive) | http://127.0.0.1:8000/api/docs |

### Deploying beyond your own machine

The app binds to `127.0.0.1` by default. To expose it, put it behind a TLS-terminating reverse proxy
(Caddy / nginx / IIS), run `python -m trustvault --host 0.0.0.0`, and set `TRUSTVAULT_COOKIE_SECURE=1`,
`TRUSTVAULT_TRUST_PROXY=1` (only behind your proxy), and the two keys from a secret manager
(`TRUSTVAULT_MASTER_KEY`, `TRUSTVAULT_AUDIT_KEY`). Run a **single worker** (rate limiting is in-process; see THREATS.md T51).

## 5. Reset

```bat
reset.bat      REM deletes instance\ (database, files, keys, audit trail) and re-seeds
```
