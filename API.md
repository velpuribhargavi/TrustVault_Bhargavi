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
  calling the admin API); `404` a sub-object of a document you manage (grant, suggestion) or a page number that does not
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
| *link for you* | a share link made by the doc owner **for you**, less than 5 minutes old and not revoked, sent in the `X-Link-Token` header. Gives view or view + download. |
| *admin* | global role `admin` - never has document content access |

## The access check (one function for every document route)

`authz.check_access()` decides; `authz.require_access()` audits and refuses. The reasons, in the order they are tested:

| # | Reason recorded | Meaning |
|---|---|---|
| 1 | `invalid_document_id` / `document_not_found` | no such document |
| 2 | `document_destroyed` | crypto-shredded |
| 3 | `user_inactive` | deactivated or deleted account |
| 4 | `admin_never_reads_content` | separation of duties |
| 5 | `link_invalid` | a link was sent but is malformed or its signature does not match |
| 6 | `link_wrong_document` | the link is for another document |
| 7 | `link_wrong_recipient` | the link was made for somebody else (forwarded) |
| 8 | `link_expired` | older than `LINK_TTL_SECONDS` |
| 9 | `link_revoked` | access was taken away / *revoke all links* since it was made |
| 10 | `link_owner_changed` | its maker is no longer the active owner |
| 11 | `grant_expired` | the grant ran out (its `access.expired` event is written at the same moment) |
| 12 | `grant_revoked` | the owner or an admin revoked it |
| 13 | `no_grant` | never shared with this person |
| 14 | `document_in_trash` | only the owner may look at / restore / destroy it |
| 15 | `<level>_cannot_<action>` | e.g. `view_cannot_download` |
| 16 | `version_not_in_document` | a version id belonging to another document |

A link never lowers what a grant allows, and a bad link does not block a valid grant (the link problem is still recorded).

## Authentication

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/auth/login` | anyone | ✎ Rate-limited per IP; account locks after 5 failures for 15 min. Same error for unknown user / wrong password / locked / deactivated. Returns `session` limits. |
| POST | `/api/auth/logout` | any signed-in | ✎ Deletes the session server-side. Optional `{"reason": "idle" | "max_lifetime"}` when the page's own timer ended it (audited as `auth.session_expired`, `detected: browser`). |
| GET | `/api/auth/me` | any signed-in | Current user, CSRF token, and `session`: `idle_timeout_seconds`, `warning_seconds`, `expires_at`, `server_time`. |
| POST | `/api/auth/keepalive` | any signed-in | ✎ (`auth.session_extended`) "Stay signed in": restarts the idle timer. Never extends the 8-hour limit. |
| POST | `/api/auth/change-password` | any signed-in | ✎ Requires current password; ends all *other* sessions. |

## Documents

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/documents` | owner role | ✎ multipart `file`, `category`, optional `name`, `description`. Validated, encrypted. Uploader becomes doc owner. |
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
| GET | `/api/documents/{id}/activity` | doc owner | Audit entries for this document (who opened it, who was refused and why). |

The content routes (`GET /{id}`, `/preview`, `/preview/pages/{n}`, `/download`, `/versions/{vid}/download`) accept a
share link in the **`X-Link-Token` header only** - a `?link=` in the URL is ignored, so tokens never reach access logs.

## Sharing: time-limited grants

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/users/directory` | owner role | Active, non-admin users to pick from. Viewers/externals cannot list users. |
| GET | `/api/documents/{id}/grants` | doc owner | Every grant with `expires_at`, `expired`, `seconds_left`; `server_time`. |
| POST | `/api/documents/{id}/grants` | doc owner | ✎ `{username, permission: "view"|"download"|"edit", duration_minutes? , expires_at?, suggestion_id?}` - send one of `duration_minutes` / `expires_at`, or neither for `DEFAULT_GRANT_MINUTES` (30). At most `MAX_GRANT_DAYS` (366). Target must be active and not an admin. Audited `access.granted`, or `access.changed` (with the previous level and expiry) for a person who already has live access. Lowering a level also invalidates outstanding links. |
| POST | `/api/documents/{id}/grants/{gid}/extend` | doc owner | ✎ `{minutes}`. Adds time to the expiry - or, for an expired grant, from now. Audited `access.extended` (from, to). |
| DELETE | `/api/documents/{id}/grants/{gid}` | doc owner | ✎ `access.revoked`. Grant must belong to `{id}`. Effective on the grantee's next request; also kills outstanding links. |

When a grant runs out, `access.expired` is written once (actor `system:expiry`) - at the moment someone is refused
because of it, when the owner or an admin lists grants, or by a sweep that runs at most every 30 seconds.

## Sharing: 5-minute links for one named person

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/documents/{id}/links` | doc owner | ✎ (`link.created`) `{username, permission: "view"|"download"}`. Returns `token`, `path` (`/#/l/<token>`), `expires_at` (now + `LINK_TTL_SECONDS`). Recipient must be active and not an admin. The token is signed (HMAC) and **not stored**. |
| GET | `/api/documents/{id}/links` | doc owner | Links made in the last few minutes (from the audit trail): recipient, level, `active`/`expired`/`revoked`, opened or not. |
| POST | `/api/documents/{id}/links/revoke-all` | doc owner | ✎ (`link.revoked_all`) Every outstanding link to the document stops working now. |
| POST | `/api/links/open` | any signed-in - only the recipient succeeds | ✎ (`link.opened`) `{token}`. Returns `document_id`, `name`, `permission`, `expires_at`. Anyone else - even someone who holds a grant on the document - gets the uniform 403 (reason `link_wrong_recipient`, alert *forwarded_link*). Rate-limited per user. |

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
| GET | `/api/admin/audit` | Filters: `action` (exact, or prefix ending in `.`, e.g. `access.`), `outcome`, `actor`, `document_id`, `date_from`, `date_to`, paging. |
| GET | `/api/admin/audit/verify` | ✎ Verifies HMAC chain, sequence, anchors, triggers. |
| GET | `/api/admin/alerts?hours=24` | Rule-based alerts + integrity status. |
| GET | `/api/admin/stats` | Counters (live grants, grants ending within 24 h, links made today, ...). |
| GET | `/api/admin/documents` | All documents - **metadata only** - with live and expired grant counts. |
| GET | `/api/admin/documents/{id}/access` | Who holds grants (and until when) and which links were made recently. |
| DELETE | `/api/admin/grants/{gid}` | ✎ Emergency revoke (reduce-only). Audited `access.revoked` with `by_admin`. |
| POST | `/api/admin/documents/{id}/links/revoke-all` | ✎ Emergency: kill every outstanding link to a document. |

There is **no** endpoint through which an administrator can download a document, create a grant or a link, or grant themselves anything.

## Meta

| Method | Path | Who may call |
|---|---|---|
| GET | `/api/meta` | any signed-in - categories, allowed file types, upload limit, the four time limits, Office renderer |
| GET | `/api/health` | anyone - liveness |

## Audit event names

`auth.login`, `auth.logout`, `auth.session_expired`, `auth.session_extended`, `auth.password_change`,
`document.upload`, `document.view`, `document.preview`, `document.preview_page`, `document.download`,
`document.version_download`, `document.version_upload`, `document.update`, `document.delete`, `document.restore`,
`document.purge`, `access.granted`, `access.changed`, `access.extended`, `access.revoked`, `access.expired`,
`link.created`, `link.opened`, `link.revoked_all`, `ai.suggestion.generated|accepted|dismissed`, `user.*`, `audit.verify`.
Each has `outcome` `allowed` / `denied` / `error` / `info`; a `denied` row always carries `details.reason`.

## Example (curl, bearer mode)

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"Author!Vault2026","mode":"bearer"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
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
