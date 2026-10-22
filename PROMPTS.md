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

## Template for the next entries

```
## YYYY-MM-DD - N. <title>  *(authorisation | audit trail | other)*
**Asked:** <prompt or fair summary>
**Produced:** <what the AI gave>
**What was wrong:** <specifically - the line, the attack, the failing test>
**What I did instead:** <the fix, the test that pins it>
**Fixed in:** <commit link>
```
