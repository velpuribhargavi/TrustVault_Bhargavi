# Context file given to the AI assistant at the start of every session

Paste this before any request about TrustVault. It exists so the assistant does
not "helpfully" undo a security decision it does not know about.

---

You are helping on **TrustVault**, a document-sharing platform judged mostly on
whether a hostile tester can reach a document they were not granted.

Non-negotiable rules - do not change these, and stop and tell me if a request would:

1. **Every document route calls `authz.require_access()` as its first statement.**
   `check_access()` is the only function that decides document access; nothing
   else may call it or re-implement it. No route reads a version, grant or
   suggestion by id without checking the child belongs to the checked document.
2. **Admins never get document content.** Not via a grant, a link, a special
   endpoint, or "for support". Admins can only reduce access.
3. **No caching of permissions, no JWTs, no anonymous links.** Revocation must
   work on the next request. The only signed token is a share link: one named
   recipient, `LINK_TTL_SECONDS`, checked against `documents.access_version`.
4. **Every refusal is the same 403 "You don't have access to this file."** with
   `code: no_access`. The real reason goes to the audit trail only.
4b. **Every time limit lives in `config.py`** (LINK_TTL_SECONDS, DEFAULT_GRANT_MINUTES,
   SESSION_IDLE_MINUTES, SESSION_MAX_HOURS). Every clock read goes through
   `utils.utcnow()` so tests can move time. Every grant expires. Also
   CONFIDENTIAL_GRANT_MINUTES, ACCESS_REQUEST_DAYS, MAX_PENDING_REQUESTS.
5. **Every refusal writes a `denied` audit row**; every allowed access writes an
   `allowed` row *before* bytes are returned. If the audit write fails, the
   request fails.
6. **The audit table is append-only.** Never write UPDATE/DELETE against it,
   never add a code path that could. Schema upgrades only *add* nullable
   columns, and a new hashed field must be left out of the hash input while it
   is NULL, so existing rows keep their hashes (see `audit._entry_fields`).
   Anything written to a file that a person will open (CSV export) goes through
   `csv_cell()` - attackers choose usernames and user agents.
6b. **Admin endpoints use `require_role("admin")`**, which records every role
   refusal as `auth.forbidden`. New audit actions need a plain-language label in
   `audit_text.py` (a test fails otherwise).
6c. **No session before every sign-in step has passed.** Two-step sign-in (TOTP)
   is required for the roles in `TOTP_REQUIRED_ROLES`; a correct password only
   creates a short-lived challenge. TOTP keys are sealed (`KeyRing.seal`), backup
   codes stored as keyed hashes, and no endpoint ever returns either after set-up.
   Never `SELECT u.*` into a response.
7. **Suggestions never grant.** Only the owner, through the normal grant
   endpoint, creates grants.
7b. **Requests for access never reveal anything and never bypass sharing.**
   `POST /api/access-requests` gives the same answer for any well-formed id
   (real or not) and is not a document route. Approve/deny call
   `require_access(..., Action.SHARE)` on the request's document and then
   `sharing.give_access()` - never a second grant-writing path.
7c. **Classification labels never enter `check_access()`.** Public is not
   "open"; Confidential only tightens defaults (View only, 1 hour, CONFIDENTIAL
   page mark, links cancelled when raised). Changing a label is owner-only
   (`Action.CLASSIFY`) and always audited as `document.classified`.
   Every new document route needs a row in `tests/test_authz_matrix.py`.
8. **All SQL uses bound parameters.** Only fixed fragments may be concatenated.
9. **The UI never uses innerHTML** (or any HTML string) with data.
9b. **A `view` grant never receives the original file.** Only `/preview` renderings
    (watermarked PNG pages or extracted text); `download` is a separate action.
10. **Every new authorisation check is a single line tagged
    `# AUTHZ-CHECK[unique-name]`**, written as `if <deny-condition>:`, and has a
    test that fails when `tools/mutation_check.py` removes it.

Stack: Python 3.10+, FastAPI, SQLite (stdlib `sqlite3`), argon2-cffi,
cryptography, vanilla JS. Keep dependencies minimal.

When you write code, also write the test that proves the security property,
and tell me which THREATS.md entry it belongs to.
