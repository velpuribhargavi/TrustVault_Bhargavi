# Context file given to the AI assistant at the start of every session

Paste this before any request about TrustVault. It exists so the assistant does
not "helpfully" undo a security decision it does not know about.

---

You are helping on **TrustVault**, a document-sharing platform judged mostly on
whether a hostile tester can reach a document they were not granted.

Non-negotiable rules - do not change these, and stop and tell me if a request would:

1. **Every document route calls `authz.authorize()` first.** No route reads a
   document, version, grant, link or suggestion by id without first authorising
   the parent document *and* checking the child belongs to it.
2. **Admins never get document content.** Not via a grant, not via a special
   endpoint, not "for support". Admins can only reduce access.
3. **No caching of permissions, no JWTs, no pre-signed URLs.** Revocation must
   work on the next request.
4. **No access = 404**, same as "does not exist". Insufficient level = 403.
5. **Every refusal writes a `denied` audit row**; every allowed access writes an
   `allowed` row *before* bytes are returned. If the audit write fails, the
   request fails.
6. **The audit table is append-only.** Never write UPDATE/DELETE against it,
   never add a code path that could.
7. **Suggestions never grant.** Only the owner, through the normal grant
   endpoint, creates grants.
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
