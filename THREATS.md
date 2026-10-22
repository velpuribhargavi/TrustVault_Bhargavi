# THREATS.md - how TrustVault could be broken, and what stops it

**Scope.** The deployed web application, its API, its storage on disk and its audit trail.
**Assets.** Document content (most valuable), document names/metadata, who-has-access information, the audit trail, credentials and sessions, encryption keys.
**Attackers considered.**
A. an outsider with no account · B. a signed-in user trying to reach documents not shared with them (the judge) · C. a grantee trying to do more than their level allows · D. an ex-employee / revoked user · E. someone holding a forwarded share link · F. a malicious or compromised administrator · G. an insider with write access to the server's disk or database.

**How to read this file.** Each row: the attack → what was done → the test(s) that prove it (all in `tests/`) → what remains.
Every authorisation check named below is tagged `AUTHZ-CHECK[...]` in the code; `tools/mutation_check.py` removes each one in turn and confirms that a test fails.

Status legend: **Mitigated** (prevented and tested) · **Detected** (cannot be prevented by the app, but is recorded and alerted) · **Residual** (known gap, stated honestly).

---

## 1. Reaching a document you were not given (attacker B)

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T01 | **IDOR**: call `/api/documents/{id}` (view, preview, download, edit, delete, share, activity...) with someone else's id. | One choke point, `authz.authorize()`, runs first in **every** document route and re-reads user + document + grant from the DB. No grant → **404** (same as "does not exist", so ids cannot be probed). IDs are 128-bit random, but the check never relies on that. | `test_authz_matrix.py` - 15 endpoints × 9 caller types (135 cases), each refusal also checked for *no side effect* and *an audit row*. `test_matrix_covers_every_document_route` fails if a new route is added without being in the matrix. | Mitigated |
| T02 | **Version IDOR**: holder of a read grant on doc A downloads `/documents/A/versions/<version-of-B>`. | The version row must have `document_id == A` after A has been authorised (`AUTHZ-CHECK[version-belongs-to-document]`). | `test_idor.py::test_version_of_another_document_is_refused`, `test_owner_cannot_reach_foreign_version_through_own_document` | Mitigated |
| T03 | **Child-object IDOR**: owner of A revokes a grant / link / suggestion of B by calling it through A. | Every child lookup checks it belongs to the authorised document (`grant-belongs-to-document`, `link-belongs-to-document`, `dismiss-suggestion-belongs-to-document`, `suggestion-matches-document`). | `test_idor.py` (4 tests) | Mitigated |
| T04 | **Privilege escalation within a document**: view → download; download → edit; edit → delete/share/re-share; viewer → upload. | Explicit action table: `view={view}`, `download=view+{download}`, `edit=download+{edit}`, `owner=all` (`permission-allows-action`). Only the doc owner manages access (no re-sharing by grantees). Upload requires the `owner` role. Unknown levels (including the old `read`) are rejected with 422. | Matrix rows for `gina` (view), `carol` (download) and `dave` (edit); `test_view_levels.py::test_download_level_cannot_edit_and_edit_level_cannot_delete_or_share`, `test_old_read_level_and_unknown_levels_are_rejected`; `test_uploads.py::test_viewer_and_admin_cannot_upload` | Mitigated |
| T05 | **Mass assignment**: PATCH with `owner_id`, `role`, extra fields. | Every request model is Pydantic with `extra='forbid'`; updates write a fixed column list. | `test_idor.py::test_mass_assignment_fields_are_rejected` | Mitigated |
| T06 | **Search leakage**: names of other people's documents via search text, owner filter, `%`/`_` wildcards, result counts, trash. | Access scope is part of the SQL `WHERE` (owner OR live grant) for both the page and the count; LIKE wildcards escaped; trashed/purged excluded. | `test_search.py` (8 tests) incl. `test_like_wildcards_are_literal`, `test_outsider_finds_nothing_of_others` (count = 1) | Mitigated |
| T07 | **Admin reads content** - directly, or by being granted. | Admins get *no* document permission, even if a grant row somehow exists (`admin-has-no-content-access`, `admin-search-sees-nothing`). Grants to admins are refused (`grant-target-not-admin`). There is no admin download endpoint. | `test_authz_unit.py::test_admin_gets_nothing_even_with_a_grant_row`, `test_admin.py::test_admin_sees_metadata_but_never_content`, `test_admin_cannot_grant_and_cannot_be_granted` | Mitigated (but see T46) |
| T08 | **Over-sharing by inheritance**: "access to a folder to see one file, now sees forty". | Deliberate design: **no folders, no groups, no inheritance.** Every grant is one document × one named person. Categories are labels for search, never permissions. | By construction (there is no code path that grants more than one document). | Mitigated by design |
| T09 | **Trashed document still reachable** by grantees or links. | While `deleted_at` is set only the owner can view/restore/purge (`trashed-document-locked`); search hides trash; share links check the document is live. | `test_revocation.py::test_trash_suspends_grants_and_restore_brings_them_back`, `test_search.py::test_trashed_document_disappears_from_grantee_search`, `test_share_links.py::test_link_dies_with_the_document` | Mitigated |
| T10 | **Expired time-limited grant keeps working.** | Expiry compared on every request (`expired-grant-ignored`) and inside the search SQL (`search-grant-expiry`). | `test_authz_unit.py::test_expired_grant_is_ignored`, `test_grant_expiring_in_future_works_until_it_passes`, `test_search.py::test_expired_grant_disappears_from_search`, matrix row `erin` | Mitigated |
| T53 | **User directory enumeration** by viewers / external users. | Directory only for the `owner` role; excludes admins and inactive users. | `test_admin.py::test_directory_is_for_owners_only` | Mitigated |

### View-only access

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T60 | **A view-only user obtains the file anyway** - via the download or version-download URL, or because "viewing" just streams the original (a PDF shown in the browser's own viewer can be saved with one click). | `download` is a separate action that `view` does not include (403 + audited). Viewing never sends the original: the server renders PDF pages and images to PNG and Office/text files to extracted text, with the viewer's username and the time tiled across every page and in a footer. Images are re-encoded, so EXIF/metadata is dropped. Every page opened is audited (`document.preview_page`). **Residual:** whatever is shown on a screen can be screenshotted or photographed - no web app can stop that. What view-only guarantees is that the exact file (bytes, text layer, metadata, hidden content) never leaves, and that a leaked picture names who it was rendered for. | `test_view_levels.py::test_view_only_can_read_but_never_receives_the_file`, `test_view_only_cannot_download_any_way`, `test_image_preview_is_reencoded_without_metadata`, `test_rendered_page_carries_a_visible_watermark`, `test_every_view_is_audited`; matrix row `gina`; `test_revocation.py::test_downgrade_from_download_to_view_stops_downloads_at_once` | Mitigated (screenshot residual) |
| T61 | **Rendering untrusted documents attacks the server**: XML entity expansion ("billion laughs") in Office files, decompression/zip bombs, huge images, malformed PDFs crashing the renderer, concurrent renders corrupting PDFium. | Office text is pulled out with regular expressions, not an XML parser, so DTD entities are never expanded. Single XML parts over 20 MB are refused; images over 40 megapixels refused (same limit as upload); renders capped at 1600 px and 200 pages. PDFium (the engine inside Chrome) does the PDF parsing; any failure becomes a clean 422, and a global lock serialises it because it is not thread-safe. | `test_view_levels.py::test_entity_expansion_bomb_in_docx_is_not_expanded`, `test_corrupt_or_unsupported_documents_fail_cleanly`, `test_page_numbers_out_of_range` | Mitigated (PDFium bugs residual) |
| T62 | **Mass viewing** as a slower form of exfiltration by a view-only user. | The bulk-access alert counts documents *opened* as well as downloaded (10 different documents in 10 minutes). | `alerts.py` rule `bulk_download` | Detected |

## 2. Taking access away (attacker D) - "works immediately"

**What "immediately" means here:** the next HTTP request after the revocation commits is refused. There are no JWTs, no cached permissions, no pre-signed URLs: every request looks up the session, the user and the grant in the database.
**What it costs:** one indexed DB lookup per request (microseconds in SQLite); all file bytes must flow through the app (no CDN offload); horizontal scaling would need a shared database (see T51).

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T11 | **Leaver keeps access**: old sessions, API tokens, grants or share links still work after deactivation. | Deactivation deletes all sessions; *also* every request re-checks `is_active` (`inactive-user-rejected`), the policy ignores inactive users (`inactive-user-has-no-access`), and share links die when their creator is inactive (`share-link-creator-still-owner`). | `test_revocation.py::test_deactivated_user_is_locked_out_of_every_session_and_link` (cookie + second session + bearer token + share link), `test_inactive_user_with_surviving_session_row_is_rejected` | Mitigated |
| T12 | **Revocation delayed** by caching. | No permission cache. Grant revoke = row deleted; next request sees it. Downgrade edit→read likewise. | `test_revocation.py::test_revoked_grant_stops_the_same_session_at_once`, `test_downgrade_from_edit_to_read_is_immediate`, `test_role_change_takes_effect_on_next_request` | Mitigated |
| T63 | **A deleted account comes back**: re-activated, given a new password, unlocked, or its username re-registered so the audit trail now points at someone else. | Delete is final (`deleted-account-is-final`): every admin change to a deleted account returns 409; usernames are never freed. Delete also removes the person's grants, sessions and share links. An admin cannot delete their own account (`admin-cannot-delete-self`); owners must have their documents destroyed first. | `test_admin.py::test_admin_deletes_a_user_everything_ends_and_it_is_final`, `test_admin_cannot_delete_themselves`, `test_owner_with_documents_cannot_be_deleted`, `test_only_admins_can_delete_users` | Mitigated |
| T24 | **Stolen session survives a password change / admin reset.** | Password change deletes all other sessions; admin reset deletes all sessions. | `test_revocation.py::test_password_change_ends_other_sessions`, `test_admin_password_reset_ends_all_sessions` | Mitigated |
| T25 | **Sessions never expire.** | 30-min idle timeout + 8-h absolute lifetime, enforced server-side (`session-expiry`); logout deletes the session row. | `test_idle_session_expires`, `test_absolute_session_lifetime`, `test_logout_kills_the_token` | Mitigated |
| T47 | **Download already in progress** when access is revoked. | Files are capped at 10 MB and sent in one response, so the window is the transfer time of one response. | - | Residual (accepted) |
| T48 | **Copies already downloaded** before revocation. | Cannot be recalled by any web app (would need DRM). The audit trail records exactly who downloaded which bytes (SHA-256) and when, which is the evidence needed afterwards. | `test_audit.py::test_every_required_event_is_recorded` (checks the sha256 is logged) | Residual (stated) |

## 3. External sharing (attacker E)

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T13 | **Guessing a share token**, or reading tokens from a DB copy. | 256-bit random tokens; only SHA-256 stored; per-IP rate limit; unknown tokens audited and alerted (`share_link_guessing`). | `test_share_links.py::test_token_is_stored_hashed`, `test_guessed_tokens_are_refused_and_audited`, `test_admin.py::test_alert_on_credential_stuffing_and_guessing` | Mitigated |
| T14 | **Leaked / forwarded link** used indefinitely or by many people. | Mandatory expiry (≤ 7 days), mandatory use limit (≤ 50), revocable by owner or admin; token lives in the URL **fragment** (never sent to servers, logs or `Referer`); `Referrer-Policy: no-referrer`; alert when one link is used from ≥ 3 IPs. | `test_expired_link_refused`, `test_use_limit`, `test_lifetime_and_use_caps`, `test_revoked_link_stops_immediately`, `test_admin.py::test_alert_on_link_used_from_many_addresses` | Mitigated / Detected |
| T15 | **Race** for the last use (two parallel downloads both succeed). | Single conditional `UPDATE ... WHERE use_count < max_uses` and check `rowcount == 1`. | `test_share_links.py::test_last_use_cannot_be_taken_twice_concurrently` (8 threads, exactly one 200) | Mitigated |
| T16 | **Link outlives** the document, the creator's account, or the creator's ownership. | Checked on every use (`share-link-document-live`, `share-link-creator-still-owner`). | `test_link_dies_with_the_document`, `test_link_dies_when_creator_deactivated`, `test_link_dies_when_creator_is_no_longer_owner` | Mitigated |
| T17 | **Link used to modify** a document. | Links are only accepted by two read-only public endpoints; they are not sessions. | `test_link_is_read_only` | Mitigated |

## 4. AI inside the product

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T18 | **The machine widens access on its own**; or suggestions **leak** who has access to other people's documents; or document content is sent to a third-party AI. | Suggestions are read-only; a grant only happens when the owner calls the normal grant endpoint (CSRF-protected) with the suggestion id; suggestion + decision both audited (`ai.suggestion.generated`, `ai.suggestion.accepted` / `dismissed`, `permission.grant` with `suggestion_id`). Only `view` (the lowest level) is ever proposed. Signals come only from the requesting owner's **own** sharing history. A suggestion is single-use and bound to one document and one person. The engine is local and explainable; no content leaves the server. | `test_suggestions.py` (7 tests) incl. `test_suggestions_never_grant_by_themselves`, `test_suggestions_do_not_leak_other_owners_sharing`, `test_suggestion_cannot_be_redirected_to_another_person`; `test_idor.py::test_suggestion_of_another_document_cannot_be_used_to_grant` | Mitigated |

## 5. Authentication and sessions (attacker A)

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T19 | **Brute force / credential stuffing.** | Argon2id hashes; account lockout after 5 failures (15 min, even with the right password); 20 attempts/min per IP; alerts for bursts. | `test_auth.py::test_account_locks_after_repeated_failures_even_for_right_password`, `test_login_rate_limit_per_ip`, `test_passwords_are_argon2id_hashed` | Mitigated |
| T59 | **Password guessing through "change password"** with a stolen session, bypassing the sign-in lockout. | Wrong current-password attempts count towards the same lockout; reaching it locks the account and ends all its sessions (`password-guessing-locks-account`). | `test_auth.py::test_change_password_cannot_be_used_to_brute_force` | Mitigated |
| T52 | **Lockout used to deny service** to a known user. | Trade-off accepted: lockout is temporary, admins can unlock, IP limit slows the attacker, alert raised. | `test_account_locks...` (unlock path) | Residual (accepted) |
| T20 | **Username enumeration** through messages or timing. | One generic message for unknown user / wrong password / locked / deactivated; Argon2 always runs (dummy hash for unknown users). | `test_wrong_password_and_unknown_user_look_identical` | Mitigated |
| T21 | **Session theft via XSS.** | Cookie `HttpOnly; SameSite=Strict` (+ `Secure; __Host-` over HTTPS); strict CSP (`script-src 'self'`, no inline); UI never uses `innerHTML`; uploaded files never rendered on our origin. | `test_cookie_is_httponly_samesite_strict`, `test_http_hardening.py::test_security_headers_on_pages_and_api`, `test_frontend_never_uses_innerhtml_with_data` | Mitigated |
| T22 | **CSRF**: another site makes the browser grant/delete. | `SameSite=Strict` **and** a per-session CSRF token in a custom header, compared in constant time (`csrf-token-required`). | `test_csrf_token_required_for_cookie_requests` (missing, forged, other user's token) | Mitigated |
| T23 | **Session fixation.** | A new random token is minted at every login; tokens are stored only as SHA-256. | `test_new_session_on_every_login`, `test_session_tokens_are_stored_hashed` | Mitigated |
| T26 | **IP spoofing** with `X-Forwarded-For` to dodge rate limits or frame someone in the audit trail. | Header ignored unless `TRUSTVAULT_TRUST_PROXY=1` (only behind your own proxy). | `test_forwarded_for_header_is_ignored_by_default` | Mitigated |
| T45 | **No TLS** on the local demo. | Local runs on `127.0.0.1`. Any exposed deployment must sit behind TLS with `COOKIE_SECURE=1` (adds `Secure`, `__Host-` prefix and HSTS). | - | Residual (deployment step) |
| T55 | **No MFA.** | Not built in a week (see WRITEUP). Mitigated partly by lockout, rate limits and alerts. | - | Residual |

## 6. Files and storage (attackers A, B, G)

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T27 | **Malicious uploads**: executables, HTML/SVG (stored XSS), polyglots, PDF JavaScript (incl. `#xx`-escaped names), Office macros, remote-template injection, zip bombs, image decompression bombs, CSV formula injection, binary/escape codes in text. | Extension allow-list (pdf, png, jpg, txt, csv, docx, xlsx, pptx) **and** magic-byte check **and** per-type active-content checks; client `Content-Type` ignored; MIME derived server-side. Rejections audited. | `test_uploads.py` - 23 rejection cases + zip bomb + valid files accepted | Mitigated (signature-level; see T56) |
| T56 | Malware inside an otherwise valid file (e.g. exploit in a PDF parser). | Out of scope for content analysis; files are always delivered as downloads, never rendered by us. Production would add an AV scanner (ClamAV) hook. | - | Residual |
| T28 | **Path traversal / header injection** through the filename. | Filename only used for display: last path component, NFKC, control & bidi (RTLO) characters removed, reserved Windows names prefixed; blobs stored under random ids; `Content-Disposition` RFC 6266-encoded. | `test_filename_is_sanitised`, `test_header_injection_through_filename_is_impossible` | Mitigated |
| T29 | **Bypassing the app** to read files: guessing a static URL, or stealing the disk / a backup. | Blobs live outside every served folder; each version encrypted with AES-256-GCM under its own key, wrapped by a master key kept outside the DB (env var or separate key file). | `test_files_are_encrypted_at_rest` (no plaintext anywhere in `instance/`), `test_storage_is_not_served_over_http` | Mitigated (keys on the same disk locally: see T49) |
| T30 | **Swapping blobs or wrapped keys** on disk so doc A serves doc B's bytes. | Document id + version id bound as AES-GCM associated data; plaintext SHA-256 verified; failure → 500, audited as `error`, **critical alert**. | `test_swapped_blob_is_detected_not_served`, `test_wrapped_key_swap_is_detected` | Mitigated / Detected |
| T31 | **Uploaded file rendered inline** on our origin (stored XSS). | Always `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`. HTML/SVG are rejected anyway. | `test_download_headers_force_attachment_and_sandbox` | Mitigated |
| T32 | **Denial of service** with huge or endless uploads. | Body-size middleware (Content-Length and streamed byte count) before parsing; per-file limit (10 MB); zip/image bomb limits. | `test_oversized_upload_is_refused_before_parsing`, `test_body_size_limit`, `test_zip_bomb_is_rejected` | Mitigated |
| T33 | **Documents cached** by the browser or a proxy on a shared computer. | `Cache-Control: no-store` on every API response and download. | `test_api_responses_are_not_cached`, download header test | Mitigated |
| T49 | **Backups / deleted data**. | Purge crypto-shreds (wrapped keys set to NULL, blobs deleted) so old blob backups become unreadable; retention auto-purges trash after 30 days. A *database* backup taken before the purge still holds the wrapped key; keys must be backed up separately from data. | `test_purge_crypto_shreds`, `test_retention_purges_old_trash` | Partly residual (stated) |

## 7. The audit trail (attackers F, G) - "an audit trail that can be quietly altered is not evidence"

**What stops quiet alteration:** (1) SQLite triggers make `audit_log` append-only for the application; (2) each row's `entry_hash = HMAC-SHA256(audit_key, all fields + prev_hash)` - the key is **not in the database**, so someone who can edit the DB cannot forge a valid chain; (3) after every commit the newest `(seq, hash)` is appended to an anchor file **outside** the database, which catches deleting the newest rows (a chain alone cannot). `verify()` checks all three and the presence of the triggers.

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T34 | Insider with DB write access **edits** (who/what), **deletes** a middle row, **re-orders** rows, **truncates** the tail, or **re-hashes** with plain SHA-256. | As above. Verification failure → **critical** alert on the admin dashboard with the first bad sequence number. | `test_audit.py`: `test_application_cannot_update_or_delete_audit_rows`, `test_edited_row_is_detected`, `test_rehashed_row_without_the_key_is_detected`, `test_deleted_middle_row_is_detected`, `test_truncated_tail_is_detected_by_external_anchor`, `test_reordered_rows_are_detected`; `scripts/tamper_demo.py` | Detected |
| T35 | Insider with **both** the DB **and** the audit key **and** write access to the anchor file rewrites everything consistently. | Cannot be prevented inside one machine. Production design: audit key in a secret manager/HSM, anchors shipped to write-once storage (S3 Object Lock / syslog server) owned by a different team. | - | Residual (stated) |
| T36 | **Action happens without a record** (audit write fails, fail-open). | Audit row written in the same transaction as the change; for downloads the `allowed` row is committed **before** any byte is returned. If it fails, the request fails. | `test_storage.py::test_audit_failure_means_no_download` | Mitigated |
| T39 | **Refused attempts not recorded.** | Every refusal in `authorize()` and every child-object refusal writes a `denied` row with the reason; failed logins, bad share tokens and rejected uploads too. | Matrix asserts a new `denied` row for every refused case; `test_every_required_event_is_recorded` | Mitigated |
| T37 | **Log injection / XSS** through usernames, filenames or details shown to the admin. | Fields normalised (control chars and newlines stripped, length-capped), details stored as JSON, UI renders with `textContent` only. | `test_log_injection_is_inert`, `test_frontend_never_uses_innerhtml_with_data` | Mitigated |
| T38 | **Audit flooding** to bury evidence or fill the disk. | Login and public-link rate limits; authenticated actions need a valid account. A determined authenticated user can still create many rows. | `test_login_rate_limit_per_ip` | Partly residual |

## 8. Administrators (attacker F)

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T46 | **Malicious admin** reads a document by resetting the owner's password and signing in as them. | Cannot be fully prevented without an out-of-band channel (email/MFA). Made loud instead: every admin reset raises an alert; a sign-in to that account from the admin's own IP raises a **high** "possible impersonation" alert; all of it is in the tamper-evident trail. Admins cannot change their own role or deactivate themselves (so one admin always remains). | `test_admin.py::test_admin_impersonation_after_password_reset_is_flagged`, `test_admin_cannot_lock_themselves_out` | Detected (residual) |
| T57 | **Admin creates a second admin** to act through. | Alert `privilege_change` (high) on admin creation and on promotion to admin. | `test_alert_on_new_admin_and_external_edit` | Detected |
| T58 | Non-admin calls admin API. | `role-required` dependency on every admin route. | `test_non_admins_cannot_use_admin_api` | Mitigated |

## 9. Web platform

| # | Threat | What we did | Proof | Status |
|---|---|---|---|---|
| T40 | **Error messages leak internals** (stack traces, paths, input echo). | Global handler returns `{"detail":"Internal error","incident":id}`; validation errors list fields, not values. | `test_errors_do_not_leak_internals`, `test_validation_errors_do_not_echo_input` | Mitigated |
| T41 | **Clickjacking.** | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'`. | `test_security_headers_on_pages_and_api` | Mitigated |
| T42 | **SQL injection.** | Bound parameters everywhere; only fixed SQL fragments are concatenated; sort keys from an allow-list. | `test_sql_injection_strings_are_just_data`, `test_search_paging_and_sorting` | Mitigated |
| T43 | **Secrets committed** to the repository. | Keys generated at first run into `instance/keys` (git-ignored) or injected via env vars; demo passwords are documented as demo-only. | `.gitignore` | Mitigated |
| T44 | **Vulnerable dependencies.** | Five runtime dependencies, minimum versions with known fixes (e.g. python-multipart ≥ 0.0.18). Run `pip install pip-audit && pip-audit` before deploying. | - | Residual (process) |
| T50 | **Path traversal on static files / storage.** | Starlette `StaticFiles` (normalises paths); blob paths validated against a strict id pattern and resolved inside the store root. | `test_storage_is_not_served_over_http`, `test_garbage_and_traversal_ids_are_plain_404` | Mitigated |
| T51 | **Scaling breaks guarantees**: in-process rate limiter and anchor writer assume one process. | Documented: run a single worker. Multi-instance would move rate limits to Redis and the DB to Postgres. | - | Residual (stated) |

---

## How the tests prove the checks matter

```
python tools/mutation_check.py
```

removes each of the 40 tagged checks one at a time and runs the whole suite against each mutant. The hand-in run killed **every** mutant (see `tools/mutation_check.py --list` for each check and its mutation). If you add a check, tag it; if the tool reports a survivor, a test is missing.
