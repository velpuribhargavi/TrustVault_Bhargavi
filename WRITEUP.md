# TrustVault - write-up

## What I built

A document platform where every document is shared with **named people only**, the **server decides on every request**, every access (and every refused attempt) lands in a **tamper-evident audit trail**, and **revoking access works on the next click**.

- **Accounts & roles**: administrator, document owner, viewer (+ an "external" flag for people outside the company). Admins create, list, change, deactivate and delete accounts.
- **Documents**: upload with validation, encrypted storage, versions, rename/recategorise/describe, search by name/owner/category/date, trash with restore, permanent destruction (crypto-shredding), automatic retention.
- **Sharing**: per-document grants to named people at one of three levels - **view only**, **view + download**, **edit** - with optional expiry; read-only external share links with mandatory expiry and use limits.
- **View-only reading**: the server renders the document (PDF pages and images as PNGs, Word/Excel/PowerPoint/text as extracted text) with the viewer's name and the time watermarked on it; the original file is never sent.
- **Audit**: HMAC hash chain + append-only triggers + external anchors; per-document activity for owners; full search and integrity verification for admins.
- **Admin view**: users, audit trail, access review (who can reach what), alerts ("worth noticing"), integrity status.
- **AI in the product**: "Suggest people" for a document - a local, explainable suggestion that never grants anything by itself.
- **Proof**: 319 automated tests, a mutation tool that removes each of the 40 authorisation checks and shows a test fails, an attack script for the live system (35 checks), and a tamper demo for the audit trail.

## The permission model, in plain words

1. A document belongs to the person who uploaded it (the **owner**). Nobody else can see it - not even an administrator - until the owner shares it.
2. The owner shares a document **with one named person at a time**, choosing one of three levels:
   - **view only** - open it in the browser and read it. They receive a watermarked rendering, never the file itself, so there is nothing to download;
   - **view + download** - also download the original file (any version);
   - **edit** - also upload a new version and change its name, category and description.
   Each level includes the one before it. The owner can raise or lower a person's level at any time, and it applies on their next click. A grant can have an expiry date. There are no folders, no groups and no inheritance, so giving someone one document can never give them a second one.
3. Only the owner can share, revoke, delete, restore, destroy, create external links, see the document's activity or ask for suggestions. People with access cannot re-share.
4. **Viewers** cannot upload; they only ever work with what was shared with them. **Owners** (the role) can upload. Changing someone from owner to viewer stops new uploads; documents they already own stay theirs.
5. **Administrators** run the system, not the documents: they create, change, deactivate and delete accounts, read the audit trail and see *who has access to what* - but they can never open a document, never be given access, and can only ever **take access away** (deactivate or delete a person, revoke a grant or link). Deleting an account is final - it can never be revived or its username re-used - but the record stays, because the audit trail must keep naming who did what.
6. Every request is checked again from the database: is the session valid, is the person still active, do they still hold a live grant on *this* document, does their level allow *this* action, is the document not in the trash. The answer for "no access" is the same as "does not exist".
7. External links are a deliberate, narrow exception: read-only, at most 7 days, at most 50 downloads, revocable, and they die if the document is trashed or the owner leaves.

## Why this stack

Python + FastAPI + SQLite + plain JavaScript. Few moving parts I can defend line by line: seven runtime dependencies (two of them - PDFium and Pillow - only for view-only rendering), explicit SQL (no ORM hiding a missing `WHERE`), one process, one file database that makes a clean-clone setup a single command on Windows. The cost is scale - see "What is unfinished".

## What I deliberately did not build, and why

| Not built | Why |
|---|---|
| Folders / groups / inherited permissions | That is exactly the "access to one file, sees forty" failure in the brief. Per-document named grants are smaller and cannot leak sideways. |
| Admin access to content ("break-glass") | Separation of duties. If an admin can read salary letters, the platform's promise is only as good as every admin. |
| Re-sharing by grantees | Keeps the question "who decided this person could see it?" answerable with one name. |
| An LLM reading document content for suggestions | Sending confidential content to a third-party model would itself be a leak. The suggestion engine uses only names, categories and the owner's own sharing history. |
| Showing the original file in the browser | Rendering untrusted HTML/SVG/PDF on our origin is the classic stored-XSS route, and a PDF shown in the browser's own viewer can be saved with one click - which would make "view only" meaningless. Viewing is a server-side rendering to PNG/text instead; downloads are attachments, sandboxed. |
| Hard-deleting user rows | The audit trail must keep naming people. "Delete" is final for the account but keeps the record. |
| Password reset by e-mail, MFA, SSO | No mail infrastructure in a one-week local build. The consequence (an admin reset could be abused) is detected and alerted, see THREATS.md T46. |
| Antivirus scanning | Would need ClamAV; the hook point is `validation.validate_upload`. Files are never executed or rendered by us. |
| Multi-instance scaling | Rate limiting and anchors are in-process; SQLite is single-node. Documented in T51. |

## How I used AI, and where it was wrong

I used Claude (an AI assistant) to design and write most of the first version, then directed it with security-specific review and testing prompts (kept in `docs/ai/`). The detailed, dated log is in **PROMPTS.md**. The mistakes that mattered:

- **Audit trail**: a query-building shortcut in the admin audit search would have corrupted the bound parameter names (`:action` → `:a.action`) and broken filtering by action. Caught on review; rewritten with explicit aliases.
- **Authentication**: the first password policy accepted `password1234`; my own test caught it.
- **Admin alerts**: the "access probing" rule flagged an owner's own rejected uploads as probing - a false accusation in the audit view. Seen on the dashboard after running the attack script; fixed with a regression test.
- **Authorisation**: a "last admin cannot be removed" check was unreachable code. Dead security code looks protective but cannot be tested; removed and the real invariant documented.
- **Testability of checks**: a multi-line authorisation condition could not be removed cleanly by the mutation tool; restructured so every check is one line and provably tested.

The judgement calls - per-document grants only, admins never reading content, the AI never granting, fail-closed auditing - are mine to defend in the interview.

## What is unfinished / known gaps

Honest list (details and test references in THREATS.md):

- No MFA, no e-mail flows; an admin password reset can be abused (detected and alerted, not prevented).
- Keys live on the same disk as the data in local mode (environment variables / a secret manager are supported for deployment).
- Audit anchors are a local file; production should ship them to write-once storage owned by someone else.
- One process only (in-memory rate limiter); SQLite. Fine for a team, not for a large company.
- Content-level malware is not scanned (signature checks only).
- View-only cannot stop a screenshot or a phone camera; it stops the file leaving and puts the viewer's name on every rendered page.
- Watermark timestamps are in UTC.
- A file already downloaded cannot be recalled - only proven (who, when, which SHA-256).
- Ownership transfer when an owner leaves is not built: their documents keep the grants they already have (their share links stop), but nobody can manage them until an admin re-activates the account. Safe by default, but inconvenient; a transfer would have to be an audited, two-person action.
