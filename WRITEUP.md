# TrustVault - write-up

## What I built

A document platform where every document is shared with **named people only and for a limited time**, the **server decides on every request through one access-check function**, every access (and every refused attempt, with its reason) lands in a **tamper-evident audit trail**, and **revoking access works on the next click**.

- **Accounts & roles**: administrator, document owner, viewer (+ an "external" flag for people outside the company). Admins create, list, change, deactivate and delete accounts.
- **Documents**: upload with validation, encrypted storage, versions, rename/recategorise/describe, search by name/owner/category/date, trash with restore, permanent destruction (crypto-shredding), automatic retention.
- **Sharing**: per-document grants to named people at one of three levels - **view only**, **view + download**, **edit** - that always expire (30 minutes unless the owner picks 15 minutes ... 90 days), with **Extend** and **Revoke**; **5-minute share links for one named, signed-in person**, signed so they cannot be edited, killed at once by "Revoke all links" or by taking anyone's access away.
- **One answer to every refusal**: *"You don't have access to this file."* - the real reason (17 of them, in a fixed order) goes to the audit trail.
- **Sessions**: sign-out after 15 idle minutes (with a "Stay signed in" warning, and back to the same page after signing in again) or 8 hours.
- **View-only reading**: the server renders the document (PDF pages and images as PNGs; Word/Excel/PowerPoint as real pages through LibreOffice when it is installed, otherwise as extracted text) with the viewer's name and the time watermarked on it; the original file is never sent.
- **Audit**: HMAC hash chain + append-only triggers + external anchors; per-document activity for owners; full search and integrity verification for admins.
- **Admin view**: users, audit trail, access review (who can reach what), alerts ("worth noticing"), integrity status.
- **AI in the product**: "Suggest people" for a document - a local, explainable suggestion that never grants anything by itself.
- **Proof**: 385 automated tests (time limits tested by moving the server clock, no sleeping), a mutation tool that removes each of the 42 authorisation checks and shows a test fails, an attack script for the live system (42 checks), and a tamper demo for the audit trail.

## The permission model, in plain words

1. A document belongs to the person who uploaded it (the **owner**). Nobody else can see it - not even an administrator - until the owner shares it.
2. The owner shares a document **with one named person at a time**, choosing one of three levels:
   - **view only** - open it in the browser and read it. They receive a watermarked rendering, never the file itself, so there is nothing to download;
   - **view + download** - also download the original file (any version);
   - **edit** - also upload a new version and change its name, category and description.
   Each level includes the one before it. The owner can raise or lower a person's level at any time, and it applies on their next click. **Every grant ends on its own**: the owner picks how long (15 minutes to 90 days; 30 minutes if they do not choose), can extend it or revoke it, and its end is recorded. There are no folders, no groups and no inheritance, so giving someone one document can never give them a second one.
3. Only the owner can share, extend, revoke, delete, restore, destroy, make share links, see the document's activity or ask for suggestions. People with access cannot re-share.
4. **Viewers** cannot upload; they only ever work with what was shared with them. **Owners** (the role) can upload. Changing someone from owner to viewer stops new uploads; documents they already own stay theirs.
5. **Administrators** run the system, not the documents: they create, change, deactivate and delete accounts, read the audit trail and see *who has access to what* - but they can never open a document, never be given access, and can only ever **take access away** (deactivate or delete a person, revoke a grant or link). Deleting an account is final - it can never be revived or its username re-used - but the record stays, because the audit trail must keep naming who did what.
6. Every request is checked again from the database, by one function (`check_access`): is the session valid, is the person still active, do they own the document or hold an **unexpired** grant on *this* document - or a valid link made for them - does their level allow *this* action, is the document not in the trash. Whatever the reason, the answer is the same: *"You don't have access to this file."*
7. A **share link** is a 5-minute pass to one document for **one named person**, who must be signed in as themselves. It is signed (so it cannot be edited into "download" or "an hour"), it is not stored anywhere, and it carries the document's `access_version`: revoking anyone's access, lowering a level, "Revoke all links" or the trash bumps that number and kills every outstanding link immediately. Forwarded to anyone else it opens nothing and the admin is told.

## Why this stack

Python + FastAPI + SQLite + plain JavaScript. Few moving parts I can defend line by line: seven runtime dependencies (two of them - PDFium and Pillow - only for view-only rendering), explicit SQL (no ORM hiding a missing `WHERE`), one process, one file database that makes a clean-clone setup a single command on Windows. The cost is scale - see "What is unfinished".

## What I deliberately did not build, and why

| Not built | Why |
|---|---|
| Folders / groups / inherited permissions | That is exactly the "access to one file, sees forty" failure in the brief. Per-document named grants are smaller and cannot leak sideways. |
| Anonymous "anyone with the link" sharing | A link anyone can use is a password written in an e-mail. Phase 1 removed the old anonymous links: a link now works only for the person it names, signed in, for 5 minutes. |
| Grants that never expire | Forgotten access is how a leaver - or a contractor from two projects ago - still reads salary letters. Every grant has an end; extending is one click. |
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
- **Sessions (Phase 1)**: the browser's idle timer and the server's disagreed, and the sign-in page's "am I signed in?" request silently revived the session it was meant to end. Now the browser ends the session on the server, and the idle end is audited either way.
- **Uniform refusal (Phase 1)**: once every refusal became the same 403, removing the "no grant" check no longer changed any status code - only the audit reason. The tests now assert the recorded reason for every refusal, so the mutation is caught for the right reason.

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
- The idle timer counts *requests*: reading one long page for 15 minutes without clicking signs you out (after a warning). That is the intended trade-off for an unattended screen.
- LibreOffice rendering of Office files parses untrusted input on the server; it is sandboxed by process, profile, temp folder and time limit, but not by OS-level isolation (THREATS.md T69). It can be switched off.
- A file already downloaded cannot be recalled - only proven (who, when, which SHA-256).
- Ownership transfer when an owner leaves is not built: their documents keep the grants they already have (their share links stop), but nobody can manage them until an admin re-activates the account. Safe by default, but inconvenient; a transfer would have to be an audited, two-person action.
