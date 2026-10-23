# TrustVault API

Base URL: `http://127.0.0.1:8000`. Interactive version: `/api/docs` (OpenAPI at `/api/openapi.json`).

## Conventions

- **Authentication.** `POST /api/auth/login` sets an `HttpOnly; SameSite=Strict` session cookie (`tv_session`, or
  `__Host-tv_session` over HTTPS). API clients may send `{"mode": "bearer"}` and then use
  `Authorization: Bearer <token>`. Either way the session is looked up in the database on **every** request.
- **Sessions end** after `SESSION_IDLE_MINUTES` (15) without a request, or `SESSION_MAX_HOURS` (8) after sign-in.
  The first request after that gets `401 {"detail": "Your session has expired. Please sign in again.", "code": "session_expired"}`
  and the end is audited as `auth.session_expired` (reason `idle` or `max_lifetime`).
- **CSRF.** Cookie-authenticated `POST/PATCH/DELETE` must send `X-CSRF-Token` (returned by login and `/api/auth/me`).
  Bearer requests do not need it (no ambient credential).
- **Errors.** Every refused document request gets **one** answer:
  `403 {"detail": "You don't have access to this file.", "code": "no_access"}` - whether the document does not exist,
  was never shared with you, your grant expired or was revoked, a link was forwarded / expired / revoked, it is in the
  trash, or your level is too low. The real reason is written to the audit trail only (`details.reason`).
  Other errors: `401` not signed in / session ended; `403` (without `code`) your *role* does not allow it (e.g. a viewer
  calling the admin API - recorded as `auth.forbidden`, reason `role_required`, with method and path); `404` a sub-object of a document you manage (grant, suggestion) or a page number that does not
  exist; `400/422` invalid input; `413` too large; `429` rate limited. Bodies never contain stack traces.
- **Audit.** Every row marked ✎ writes an audit entry when allowed; every document route writes a `denied` entry, with
  its internal reason, when refused.
- **Time limits** live in one place, `trustvault/config.py`, and are reported by `GET /api/meta`:
  `LINK_TTL_SECONDS=300`, `DEFAULT_GRANT_MINUTES=30`, `SESSION_IDLE_MINUTES=15`, `SESSION_MAX_HOURS=8`.

## Who is who

| Term | Meaning |
|---|---|
| *any signed-in* | any active user with a valid session |
| *owner role* | global role `owner` (may upload) |
| *doc owner* | the person who uploaded this document |
| *view / download / edit grant* | a grant on **this** document at that level that has **not expired**. Levels are cumulative: download includes view, edit includes download. |
| *link for you* | a share link made by the doc owner **for you**, less than 5 minutes old and not revoked, sent in the `X-Link-Token` header. Works only while you also hold a live grant, and at most at your grant's level. |
| *admin* | global role `admin` - never has document content access |

## The access check (one function for every document route)

`authz.check_access()` decides; `authz.require_access()` audits and refuses. The reasons, in the order they are tested:

| # | Reason recorded | Meaning |
|---|---|---|
| 1 | `not_found` | no such document, never existed, or destroyed |
| 2 | `user_inactive` / `admin_never_reads_content` | defence in depth / separation of duties |
| 3 | `in_trash` | only the owner may look at, restore or destroy it |
| 4 | `link_invalid` | the request came through a link that is malformed or whose signature does not match |
| 5 | `link_wrong_document` | the link is for another document |
| 6 | `wrong_user` | the link was made for somebody else (forwarded) |
| 7 | `no_grant` / `grant_revoked` | never shared with this person / the owner or an admin took it away |
| 8 | `grant_expired` | the grant ran out (its `access.expired` event is written at the same moment) |
| 9 | `view_only` | a View-only person asked for more, e.g. a download (other levels: `download_cannot_edit`, ...) |
| 10 | `link_expired` | the link is older than `LINK_TTL_SECONDS` |
| 11 | `link_revoked` | access was taken away, or *Revoke all links*, since the link was made |
| 12 | `link_owner_changed` | the link's maker is no longer the active owner |
| 13 | `version_not_in_document` | a version id belonging to another document |

A request that comes through a link needs **both** a valid link **and** a live grant: a link never gives access on its
own, and it can only narrow what the grant allows (a View link to someone with Edit gives View). Only administrators
can read the reasons; the owner's activity view shows who was refused, not why.

## Authentication

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/auth/login` | anyone | ✎ Step 1: `{username, password, mode?}`. Rate-limited per IP (`rate_limited`, 429); 5 failures - wrong passwords and wrong two-step codes together - lock the account for 15 min (`auth.account_locked`). Same error for unknown user / wrong password / locked / deactivated. Without two-step sign-in: the session (cookie, or `token` with `mode: "bearer"`) and its limits. **With it** - always for roles in `TOTP_REQUIRED_ROLES` (admin, owner) - no session yet: `{"two_factor": "verify", "challenge", "expires_at"}`, or for someone who must set it up `{"two_factor": "enroll", "challenge", "secret", "secret_grouped", "otpauth_uri", "qr" (PNG data URI), ...}`. Audited `auth.2fa_required`. |
| POST | `/api/auth/login/verify` | anyone holding a challenge | ✎ Step 2: `{challenge, code}` - the 6-digit code or a backup code (`xxxx-xxxx`). Returns the session as above (plus `backup_codes_left` after a backup code). A code is accepted for its 30-second step ±1 and **never twice**. A wrong code: `401 {"code": "code_refused"}`, audited `auth.2fa_failed` (reason `bad_code`, `code_reused`, `bad_backup_code`), counts towards the lockout; after 3 wrong codes, or 5 minutes, the challenge is gone: `401 {"code": "sign_in_expired"}` - start with the password again. |
| POST | `/api/auth/login/enroll` | anyone holding an `enroll` challenge | ✎ (`auth.2fa_enrolled`) `{challenge, code}` - the first code from the newly added authenticator. Turns two-step sign-in on, returns the session **and** `backup_codes` (10, shown once). |
| GET | `/api/auth/2fa` | any signed-in | `{enabled, enabled_at, required, backup_codes_left}`. |
| POST | `/api/auth/2fa/setup` | any signed-in | ✎ (`auth.2fa_setup`) `{password}` → a new key + QR code (also to move to a new phone). Nothing changes until `/enable`. A wrong password counts towards the lockout. |
| POST | `/api/auth/2fa/enable` | any signed-in, after `/setup` | ✎ (`auth.2fa_enrolled`) `{code}` within 10 minutes → on; **every other session is signed out**; returns 10 backup codes. |
| POST | `/api/auth/2fa/disable` | any signed-in **except roles that require it** (403, audited `required_for_role`) | ✎ (`auth.2fa_disabled`) `{password, code}` (a code or a backup code). |
| POST | `/api/auth/2fa/backup-codes` | any signed-in with it on | ✎ (`auth.2fa_backup_codes_renewed`) `{code}` → 10 new codes; the old ones stop working. |
| GET | `/api/auth/sessions` | any signed-in - **own sessions only** | `items`: `id` (a 16-hex tag, not the token), `device` ("Chrome on Windows"), `ip`, `created_at`, `last_seen_at`, `expires_at`, `current`. |
| DELETE | `/api/auth/sessions/{id}` | any signed-in - own sessions only (someone else's id: 404, audited `session_not_found`) | ✎ (`auth.session_revoked`) Ends that session on the server at once; if it is the current one, the cookie is cleared too. |
| POST | `/api/auth/sessions/sign-out-everywhere` | any signed-in | ✎ (`auth.signed_out_everywhere`) Ends every session of the caller, this one included. |
| POST | `/api/auth/logout` | any signed-in | ✎ Deletes the session server-side. Optional `{"reason": "idle" | "max_lifetime"}` when the page's own timer ended it (audited as `auth.session_expired`, `detected: browser`). |
| GET | `/api/auth/me` | any signed-in | Current user, CSRF token, and `session`: `idle_timeout_seconds`, `warning_seconds`, `expires_at`, `server_time`. |
| POST | `/api/auth/keepalive` | any signed-in | ✎ (`auth.session_extended`) "Stay signed in": restarts the idle timer. Never extends the 8-hour limit. |
| POST | `/api/auth/change-password` | any signed-in | ✎ Requires current password; ends all *other* sessions. |

## Documents

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/documents` | owner role | ✎ multipart `file`, `category`, optional `name`, `description`, `classification` (`public` / `internal` / `confidential`, default `internal`; anything else → 400, audited). Validated, encrypted. Uploader becomes doc owner. |
| GET | `/api/documents` | any signed-in (admins always get an empty list) | Search: `q` (name contains), `owner` (username), `category`, `date_from`, `date_to` (YYYY-MM-DD), `scope=all|mine|shared`, `sort`, `page`, `page_size≤100`. Only documents you own or hold an unexpired grant on; trashed excluded. Each item has `my_access_expires_at`. |
| GET | `/api/documents/trash` | owner role (own trash only) | |
| GET | `/api/documents/{id}` | doc owner, grant, link for you | ✎ Metadata + version list + `my_permission`, `access_via` (`owner`/`grant`/`link`), `access_expires_at`. Trashed: doc owner only. |
| GET | `/api/documents/{id}/preview` | doc owner, grant, link for you | ✎ Opens the current version for reading **without sending the file**: `{"kind":"pages","pages":N}` for PDF/images (and Word/Excel/PowerPoint when LibreOffice is installed), or `{"kind":"text","text":...}`; plus `watermark`, `renderer`, `can_download`. |
| GET | `/api/documents/{id}/preview/pages/{n}` | doc owner, grant, link for you | ✎ Page *n* (1-based) as a PNG with the viewer's name and time tiled across it. `no-store`, CSP sandbox. 404 outside the page range. |
| GET | `/api/documents/{id}/download` | doc owner, download / edit grant, download link for you (**not view**) | ✎ The original file, current version. Attachment, `nosniff`, CSP sandbox, `no-store`, `X-Content-SHA256`. |
| GET | `/api/documents/{id}/versions/{vid}/download` | same as download | ✎ Version must belong to `{id}`. |
| POST | `/api/documents/{id}/versions` | doc owner, edit grant | ✎ New version (validated like an upload). |
| PATCH | `/api/documents/{id}` | doc owner, edit grant | ✎ `name`, `category`, `description` only (other fields → 422). |
| DELETE | `/api/documents/{id}` | doc owner | ✎ Move to trash. All grants and links stop working at once (links for good). |
| POST | `/api/documents/{id}/restore` | doc owner | ✎ From trash. |
| DELETE | `/api/documents/{id}/purge` | doc owner (document must be in trash) | ✎ Crypto-shred: keys destroyed, blobs deleted, grants removed. Irreversible. |
| GET | `/api/documents/{id}/activity` | doc owner | Audit entries for this document: who opened it, who was refused, who asked for access - **not why** someone was refused (reasons are admin-only). |
| PUT | `/api/documents/{id}/classification` | doc owner (action *classify*; Edit and below, and admins, get the uniform 403) | ✎ (`document.classified`, details `from`, `to`, `links_invalidated`) `{classification}`. Same label → `changed: false`, no event. **Raising to `confidential`** raises `access_version`, so every outstanding share link stops. |

Every document response and list item carries `classification`. For a `confidential` document the preview's
`watermark` - and the text drawn on every page - starts with `CONFIDENTIAL · `.

The content routes (`GET /{id}`, `/preview`, `/preview/pages/{n}`, `/download`, `/versions/{vid}/download`) accept a
share link in the **`X-Link-Token` header only** - a `?link=` in the URL is ignored, so tokens never reach access logs.

## Sharing: time-limited grants

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/users/directory` | owner role | Active, non-admin users to pick from. Viewers/externals cannot list users. |
| GET | `/api/documents/{id}/grants` | doc owner | Every grant with `expires_at`, `expired`, `seconds_left`; `server_time`; the document's `classification`, `default_grant_minutes` and `default_permission` (what the *Give access* form starts with). |
| POST | `/api/documents/{id}/grants` | doc owner | ✎ `{username, permission?: "view"|"download"|"edit", duration_minutes? , expires_at?, suggestion_id?}` - `permission` defaults to `view`; send one of `duration_minutes` / `expires_at`, or neither for `DEFAULT_GRANT_MINUTES` (30) - or `CONFIDENTIAL_GRANT_MINUTES` (60) for a Confidential document. At most `MAX_GRANT_DAYS` (366). Target must be active and not an admin. Audited `access.granted`, or `access.changed` (with the previous level and expiry) for a person who already has live access. Lowering a level also invalidates outstanding links. |
| POST | `/api/documents/{id}/grants/{gid}/extend` | doc owner | ✎ `{minutes}`. Adds time to the expiry - or, for an expired grant, from now. Audited `access.extended` (from, to). |
| DELETE | `/api/documents/{id}/grants/{gid}` | doc owner | ✎ `access.revoked`. Grant must belong to `{id}`. Effective on the grantee's next request; also kills outstanding links. |

When a grant runs out, `access.expired` is written once (actor `system:expiry`) - at the moment someone is refused
because of it, when the owner or an admin lists grants, or by a sweep that runs at most every 30 seconds.

## Sharing: 5-minute links for one named person

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/documents/{id}/links` | doc owner | ✎ (`link.created`) `{username, permission: "view"|"download"}`. Returns `token`, `path` (`/#/l/<token>`), `expires_at` (now + `LINK_TTL_SECONDS`). The recipient must be active, not an admin, and **already hold a live grant** at least at that level (else 400, audited `no_grant` / `link_above_grant`). The token is signed (HMAC) and **not stored**. |
| GET | `/api/documents/{id}/links` | doc owner | Links made in the last few minutes (from the audit trail): recipient, level, `active`/`expired`/`revoked`, opened or not. |
| POST | `/api/documents/{id}/links/revoke-all` | doc owner | ✎ (`link.revoked_all`) Every outstanding link to the document stops working now. |
| POST | `/api/links/open` | any signed-in - only the recipient succeeds | ✎ (`link.opened`) `{token}`. Returns `document_id`, `name`, `permission`, `expires_at`. Anyone else - even someone who holds a grant on the document - gets the uniform 403 (reason `wrong_user`, alert *forwarded_link*). The recipient also needs a live grant (reasons `no_grant`, `grant_revoked`, `grant_expired`). Rate-limited per user. |

## Requests for access

Not under `/api/documents/{id}`: the person asking has no access, and asking must not reveal whether a document
exists. Approve and deny go through the one access check (*share*) on the request's document, so only its owner can
decide; anyone else gets the uniform 403.

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/access-requests` | owner or viewer role (never an admin) | ✎ (`access.requested`) `{document_id, permission: "view"|"download"|"edit" (default view), note? (≤ 500)}`. **202 with the same body for any well-formed id**, existing or not: `{id, status: "pending", message}`. Asking again for the same document returns the same request. Refusals, all audited with a reason: not an id → 422 (`invalid_id`); more than 10 a minute → 429 (`rate_limited`); `MAX_PENDING_REQUESTS` (20) open → 429 (`too_many_pending`); you already have that level → 409 (`already_has_access`, only possible for people who can already open it). Lapses after `ACCESS_REQUEST_DAYS` (14). |
| GET | `/api/access-requests/mine` | any signed-in | Your requests: `status` `pending` / `approved` / `denied` / `withdrawn` / `expired`; `document_name` **only once approved**; `owner_reason` when denied; `granted_permission`, `grant_expires_at` when approved. |
| POST | `/api/access-requests/{rid}/withdraw` | the person who asked | ✎ (`access.request_withdrawn`) Pending requests only (409 otherwise); someone else's → 404. |
| GET | `/api/access-requests/ended` | any signed-in | Your grants that ran out in the last 90 days (to ask again), with `request_pending`. |
| GET | `/api/access-requests/incoming` | owner role | Pending requests for documents **you own**: requester, level asked, note, `classification`, and the form's starting values `default_permission` (`view` for Confidential, else what was asked) and `default_minutes` (60 for Confidential, else 30). |
| POST | `/api/access-requests/{rid}/approve` | the document's owner | ✎ (`access.request_approved`, then `access.granted` / `access.changed`) `{permission?, duration_minutes?, expires_at?}` - empty = the defaults above. Gives access through the same code as `POST /grants` (inactive or admin targets refused, durations capped), in one transaction with the request update. 409 (`request_not_pending`) unless pending and unexpired. |
| POST | `/api/access-requests/{rid}/deny` | the document's owner | ✎ (`access.request_denied`, details `owner_note`) `{reason?}` (≤ 300) - the requester sees it. Same 409 rule. |

## Suggestions

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/documents/{id}/suggestions` | doc owner | ✎ (`ai.suggestion.generated`) Suggests people for **view** (the lowest level). Changes nothing. |
| POST | `/api/documents/{id}/suggestions/{sid}/dismiss` | doc owner | ✎ |

## Administration (admin only - everyone else gets 403)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/admin/users` | Users with session/ownership/live-grant counts. |
| POST | `/api/admin/users` | ✎ Create `{username, display_name, role, password, is_external}`. |
| PATCH | `/api/admin/users/{uid}` | ✎ `role`, `is_active`, `display_name`, `is_external`. Deactivation deletes all sessions (reversible). Cannot change own role / deactivate self. 409 for a deleted account. |
| DELETE | `/api/admin/users/{uid}` | ✎ Delete an account. **Final**: sessions and grants removed, can never sign in, be re-activated or have its username re-used; the row stays so the audit trail still names them. 409 while they still own documents; 400 for your own account. |
| POST | `/api/admin/users/{uid}/reset-password` | ✎ Ends all sessions. Always raises an alert (and a high alert if the account is then used from the admin's address). |
| POST | `/api/admin/users/{uid}/unlock` | ✎ Clears lockout. |
| POST | `/api/admin/users/{uid}/revoke-sessions` | ✎ Sign out everywhere. |
| GET | `/api/admin/audit` | Search, newest first. Filters (all combine with AND): `action` (exact, or a prefix ending in `.`, e.g. `access.`), `outcome`, `reason` (internal denial reason, denied events only), `actor` (case-insensitive), `document_id`, `date_from`, `date_to`, `session` (16-hex session tag), `preset` (repeatable: `denied`, `last_24h`, `downloads`, `sharing`, `expired`), `page`, `page_size` (≤ 500). Each item has the raw row (`details` parsed, `prev_hash`, `entry_hash`, `session_ref`), `document_name`, `target_username`, `action_label` and `summary` - one plain-language sentence. |
| GET | `/api/admin/audit/options` | What the filters can be: `actions` (distinct actions in the database with label, group and count), `groups`, `reasons` (distinct denial reasons with plain words and count), `presets` (key, label, description). |
| GET | `/api/admin/audit/events/{seq}` | One event in full plus `integrity` (`hash_matches`: its HMAC still matches its content; `links_to_previous`: its `prev_hash` equals the previous event's hash) and `session` (`ref`, `total`, up to 200 `events` from the same sign-in session, or `null` for events outside a session). 404 for an unknown number. |
| GET | `/api/admin/audit/export` | ✎ (`audit.export`) Same filters as the search (no paging), oldest first, as CSV (UTF-8 with BOM). Headers: `X-Content-SHA256` (SHA-256 of the exact bytes sent), `X-Export-Rows`, `Content-Disposition: attachment`. The event records rows, bytes, SHA-256, file name and filters. Cells starting with `=`, `+`, `-`, `@`, tab or CR are prefixed with `'` (no formula runs when opened in a spreadsheet). More than `AUDIT_EXPORT_MAX_ROWS` (100,000) matching events → 400, audited `denied` / `too_many_rows`. Columns: `seq, time_utc, actor, actor_id, action, action_label, outcome, summary, document_id, document_name, target_user, ip, user_agent, session_ref, details_json, prev_hash, entry_hash`. |
| GET | `/api/admin/audit/verify` | ✎ (`audit.verify`) Recomputes every HMAC, the `prev_hash` links, the sequence and the external anchors; checks the append-only triggers. `message` is `"Chain intact (N events)"`, or `"Chain broken at event #N: ..."` naming the first modified, unlinked or missing event (a truncated tail is reported as the first missing number). |
| GET | `/api/admin/alerts?hours=24` | Rule-based alerts + integrity status. |
| GET | `/api/admin/stats` | Counters (live grants, grants ending within 24 h, links made today, ...). |
| GET | `/api/admin/documents` | All documents - **metadata only**, including `classification` - with live and expired grant counts. |
| GET | `/api/admin/documents/{id}/access` | Who holds grants (and until when) and which links were made recently. |
| DELETE | `/api/admin/grants/{gid}` | ✎ Emergency revoke (reduce-only). Audited `access.revoked` with `by_admin`. |
| POST | `/api/admin/documents/{id}/links/revoke-all` | ✎ Emergency: kill every outstanding link to a document. |
| POST | `/api/admin/users/{uid}/reset-2fa` | ✎ (`user.2fa_reset`) Someone lost their phone: their two-step sign-in is turned off, their sessions end; admins and owners set it up again at their next sign-in. Not for your own account (400; use the Account page). Raises an alert. |
| GET | `/api/admin/access-review?unused_days=30` | Every live grant with `last_used_at` (the latest allowed view / preview / download / edit / link-open by that person on that document, from the audit trail), `days_unused` (since the later of the grant and its last use) and `flagged` (≥ `UNUSED_GRANT_DAYS`, default 30). |
| POST | `/api/admin/access-review/revoke` | ✎ `{grant_ids: [...]}` (1-500). Deletes them (one `access.revoked` each, `bulk: true`, with `unused_days`), raises `access_version` **once per affected document** - so its outstanding share links stop - and writes one `access.bulk_revoked`. Unknown ids are counted as `not_found`; none found → 404. |

There is **no** endpoint through which an administrator can download a document, create a grant or a link, or grant themselves anything.

## Meta

| Method | Path | Who may call |
|---|---|---|
| GET | `/api/meta` | any signed-in - categories, allowed file types, upload limit, the time limits, Office renderer, `classifications`, `default_classification`, `confidential_grant_minutes`, `access_request_days` |
| GET | `/api/health` | anyone - liveness |

## Audit event names

`auth.login`, `auth.logout`, `auth.session_expired`, `auth.session_extended`, `auth.password_change`,
`document.upload`, `document.view`, `document.preview`, `document.preview_page`, `document.download`,
`document.version_download`, `document.version_upload`, `document.update`, `document.delete`, `document.restore`,
`document.purge`, `access.granted`, `access.changed`, `access.extended`, `access.revoked`, `access.expired`,
`link.created`, `link.opened`, `link.revoked_all`, `ai.suggestion.generated|accepted|dismissed`, `user.*`, `audit.verify`,
`audit.export`, `audit.migrated` (a schema upgrade, by `system:migration`), `auth.forbidden` (a role refusal),
`auth.2fa_required|failed|setup|enrolled|disabled|backup_codes_renewed`, `auth.account_locked`, `auth.session_revoked`,
`auth.signed_out_everywhere`, `user.2fa_reset`, `access.bulk_revoked`, `document.classified`, `access.requested`,
`access.request_approved`, `access.request_denied`, `access.request_withdrawn`.
Each has `outcome` `allowed` / `denied` / `error` / `info`; a `denied` row always carries `details.reason`.

### How an event is chained

```
entry_hash = HMAC-SHA256(audit_key, canonical JSON of {seq, ts, actor_id, actor_name, action, outcome, document_id,
                                                       target_user_id, ip, user_agent, details, prev_hash[, session_ref]})
prev_hash  = entry_hash of the previous event; "0" x 64 (genesis) for event #1
```

This is the specification's SHA-256 chain (`prev_hash + seq + timestamp + actor + action + outcome + document_id +
ip + details`) with more fields covered and a secret key added, so someone who can edit the database cannot recompute
valid hashes. The column the specification calls `hash` is `entry_hash` (name kept from the first version for API
compatibility). The hash is computed in the same transaction as the insert. `session_ref` (schema v4) is hashed only
when set, so events written before it existed keep their original hashes. Indexes: `(ts)`, `(actor_name, ts)`,
`(action, outcome, ts)`, `(document_id)`, `(session_ref)`.

## Example (curl, bearer mode)

```bash
# step 1: password -> a challenge (the owner has two-step sign-in)
CHALLENGE=$(curl -s -X POST localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"Author!Vault2026","mode":"bearer"}' | python -c "import sys,json;print(json.load(sys.stdin)['challenge'])")
# step 2: the current code (demo: python scripts/demo_code.py) -> the token
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login/verify -H 'Content-Type: application/json' \
  -d "{\"challenge\":\"$CHALLENGE\",\"code\":\"123456\"}" | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s localhost:8000/api/documents -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/api/documents -H "Authorization: Bearer $TOKEN" \
  -F file=@contract.pdf -F category=contract
# give the viewer view-only access for 4 hours
curl -s -X POST localhost:8000/api/documents/<doc-id>/grants -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"username":"viewer","permission":"view","duration_minutes":240}'
# a 5-minute link for the viewer
curl -s -X POST localhost:8000/api/documents/<doc-id>/links -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"username":"viewer","permission":"view"}'
```
