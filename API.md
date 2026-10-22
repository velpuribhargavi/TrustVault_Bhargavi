# TrustVault API

Base URL: `http://127.0.0.1:8000`. Interactive version: `/api/docs` (OpenAPI at `/api/openapi.json`).

## Conventions

- **Authentication.** `POST /api/auth/login` sets an `HttpOnly; SameSite=Strict` session cookie (`tv_session`, or
  `__Host-tv_session` over HTTPS). API clients may send `{"mode": "bearer"}` and then use
  `Authorization: Bearer <token>`. Either way the session is looked up in the database on **every** request.
- **CSRF.** Cookie-authenticated `POST/PATCH/DELETE` must send `X-CSRF-Token` (returned by login and `/api/auth/me`).
  Bearer requests do not need it (no ambient credential).
- **Errors.** `401` not signed in / session ended; `403` your role or your permission level does not allow it;
  `404` does not exist **or you have no access to it** (deliberately indistinguishable); `400/422` invalid input;
  `413` too large; `429` rate limited. Bodies are `{"detail": "..."}` and never contain stack traces.
- **Audit.** Every row marked ✎ writes an audit entry when allowed; every document route writes a `denied` entry when refused.

## Who is who

| Term | Meaning |
|---|---|
| *any signed-in* | any active user with a valid session |
| *owner role* | global role `owner` (may upload) |
| *doc owner* | the person who uploaded this document |
| *view / download / edit grant* | a live (not expired) grant on **this** document at that level. Levels are cumulative: download includes view, edit includes download. |
| *admin* | global role `admin` - never has document content access |

## Authentication

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/auth/login` | anyone | ✎ Rate-limited per IP; account locks after 5 failures for 15 min. Same error for unknown user / wrong password / locked / deactivated. |
| POST | `/api/auth/logout` | any signed-in | ✎ Deletes the session server-side. |
| GET | `/api/auth/me` | any signed-in | Current user + CSRF token. |
| POST | `/api/auth/change-password` | any signed-in | ✎ Requires current password; ends all *other* sessions. |

## Documents

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/documents` | owner role | ✎ multipart `file`, `category`, optional `name`, `description`. Validated, encrypted. Uploader becomes doc owner. |
| GET | `/api/documents` | any signed-in (admins always get an empty list) | Search: `q` (name contains), `owner` (username), `category`, `date_from`, `date_to` (YYYY-MM-DD), `scope=all|mine|shared`, `sort`, `page`, `page_size≤100`. Only documents you own or hold a live grant on; trashed excluded. |
| GET | `/api/documents/trash` | owner role (own trash only) | |
| GET | `/api/documents/{id}` | doc owner, view / download / edit grant | ✎ Metadata + version list + your permission. Trashed: doc owner only. |
| GET | `/api/documents/{id}/preview` | doc owner, view / download / edit grant | ✎ Opens the current version for reading **without sending the file**: `{"kind":"pages","pages":N}` for PDF/images, or `{"kind":"text","text":...}` for txt/csv/docx/xlsx/pptx, plus the `watermark` line and `can_download`. |
| GET | `/api/documents/{id}/preview/pages/{n}` | doc owner, view / download / edit grant | ✎ Page *n* (1-based) rendered as a PNG with the viewer's name and time tiled across it. `no-store`, CSP sandbox. 404 outside the page range. |
| GET | `/api/documents/{id}/download` | doc owner, download / edit grant (**not view**) | ✎ The original file, current version. Attachment, `nosniff`, CSP sandbox, `no-store`, `X-Content-SHA256`. A view-only user gets **403**. |
| GET | `/api/documents/{id}/versions/{vid}/download` | doc owner, download / edit grant (**not view**) | ✎ Version must belong to `{id}`. |
| POST | `/api/documents/{id}/versions` | doc owner, edit grant | ✎ New version (validated like an upload). |
| PATCH | `/api/documents/{id}` | doc owner, edit grant | ✎ `name`, `category`, `description` only (other fields → 422). |
| DELETE | `/api/documents/{id}` | doc owner | ✎ Move to trash. All grants and links stop working at once. |
| POST | `/api/documents/{id}/restore` | doc owner | ✎ From trash. |
| DELETE | `/api/documents/{id}/purge` | doc owner (document must be in trash) | ✎ Crypto-shred: keys destroyed, blobs deleted, grants removed. Irreversible. |
| GET | `/api/documents/{id}/activity` | doc owner | Audit entries for this document (who opened it, who was refused). |

## Sharing

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/users/directory` | owner role | Active, non-admin users to pick from. Viewers/externals cannot list users. |
| GET | `/api/documents/{id}/grants` | doc owner | |
| POST | `/api/documents/{id}/grants` | doc owner | ✎ `{username, permission: "view" | "download" | "edit", expires_at?, suggestion_id?}`. Target must be active and not an admin. Granting again to the same person changes their level (audited as `permission.change`, with the previous level) - raising or lowering takes effect on their next request. |
| DELETE | `/api/documents/{id}/grants/{gid}` | doc owner | ✎ Grant must belong to `{id}`. Effective on the grantee's next request. |
| GET | `/api/documents/{id}/share-links` | doc owner | Token never shown again after creation. |
| POST | `/api/documents/{id}/share-links` | doc owner | ✎ `{expires_in_hours ≤ 168, max_uses ≤ 50, label}`. Returns the token **once**, as `/share#<token>`. |
| DELETE | `/api/documents/{id}/share-links/{lid}` | doc owner | ✎ Link must belong to `{id}`. |
| GET | `/api/documents/{id}/suggestions` | doc owner | ✎ (`ai.suggestion.generated`) Suggests people for **view** (the lowest level). Changes nothing. |
| POST | `/api/documents/{id}/suggestions/{sid}/dismiss` | doc owner | ✎ |

## Public share links (no account)

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/public/share/info` | anyone holding a valid token | ✎ `{token}`. Name, size, expiry, uses left. Rate-limited per IP. |
| POST | `/api/public/share/download` | anyone holding a valid token | ✎ `{token}`. Atomically consumes one use. Refused if revoked, expired, used up, document trashed/purged, or the creator is deactivated / no longer the owner. |

The token travels in the POST body, and the page URL carries it in the `#fragment`, so it never appears in server logs or `Referer` headers.

## Administration (admin only - everyone else gets 403)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/admin/users` | Users with session/ownership/grant counts. |
| POST | `/api/admin/users` | ✎ Create `{username, display_name, role, password, is_external}`. |
| PATCH | `/api/admin/users/{uid}` | ✎ `role`, `is_active`, `display_name`, `is_external`. Deactivation deletes all sessions (reversible). Cannot change own role / deactivate self. 409 for a deleted account. |
| DELETE | `/api/admin/users/{uid}` | ✎ Delete an account. **Final**: sessions and grants removed, their share links revoked, can never sign in, be re-activated or have its username re-used; the row stays so the audit trail still names them. 409 while they still own documents; 400 for your own account. |
| POST | `/api/admin/users/{uid}/reset-password` | ✎ Ends all sessions. Always raises an alert (and a high alert if the account is then used from the admin's address). |
| POST | `/api/admin/users/{uid}/unlock` | ✎ Clears lockout. |
| POST | `/api/admin/users/{uid}/revoke-sessions` | ✎ Sign out everywhere. |
| GET | `/api/admin/audit` | Filters: `action` (exact, or prefix ending in `.`), `outcome`, `actor`, `document_id`, `date_from`, `date_to`, paging. |
| GET | `/api/admin/audit/verify` | ✎ Verifies HMAC chain, sequence, anchors, triggers. |
| GET | `/api/admin/alerts?hours=24` | Rule-based alerts + integrity status. |
| GET | `/api/admin/stats` | Counters. |
| GET | `/api/admin/documents` | All documents - **metadata only**. |
| GET | `/api/admin/documents/{id}/access` | Who holds grants / links on a document. |
| DELETE | `/api/admin/grants/{gid}` | ✎ Emergency revoke (reduce-only). |
| POST | `/api/admin/share-links/{lid}/revoke` | ✎ Emergency revoke. |

There is **no** endpoint through which an administrator can download a document, create a grant, or grant themselves anything.

## Meta

| Method | Path | Who may call |
|---|---|---|
| GET | `/api/meta` | any signed-in - categories, allowed file types, limits |
| GET | `/api/health` | anyone - liveness |

## Example (curl, bearer mode)

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"Author!Vault2026","mode":"bearer"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s localhost:8000/api/documents -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/api/documents -H "Authorization: Bearer $TOKEN" \
  -F file=@contract.pdf -F category=contract
# give the viewer view-only access to a document
curl -s -X POST localhost:8000/api/documents/<doc-id>/grants -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"username":"viewer","permission":"view"}' 
```
