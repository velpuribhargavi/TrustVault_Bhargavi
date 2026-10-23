# Five-minute demo script

Before recording: `reset.bat` (fresh data), then start the server **with a short idle timeout so the sign-out
warning can be shown on camera**:

```bat
set TRUSTVAULT_SESSION_IDLE_MINUTES=3
run.bat
```

Open http://127.0.0.1:8000 in **two browser windows** (one normal, one private) so two people can be signed in at
once. Keep a terminal open in the project folder with the virtual environment activated, and a second one running
`python scripts\demo_code.py --watch` (or add the demo keys from the README to your phone's authenticator app) -
the admin and owner sign in with a 6-digit code.

| Time | Show | Say |
|---|---|---|
| 0:00 | Login page | "TrustVault: the wrong person can never read the file, and we can prove who did. Three logins: admin, owner, viewer." |
| 0:15 | Sign in as **owner** (`Author!Vault2026`) → the **Two-step sign-in** step → code from the app → Documents | "Owners and admins need a code from their phone too - a stolen password alone opens nothing, and a code never works twice. The owner sees what she owns; search is scoped by the server to what you can access." |
| 0:30 | Open *Board minutes - private* → *Who has access* → person Vikram, **View only**, **For how long: 15 minutes** → Grant | "Access is per document, per named person, at one of three levels - and it always ends. 30 minutes by default; here 15. There's the countdown, with Extend and Revoke." |
| 0:55 | Private window: sign in as **viewer** (`Reader!Vault2026`) → *Salary letter* → **View** | "View only: the server never sends the PDF. It renders each page as an image with the viewer's name and the time across it. No download button - and the download URL is refused." |
| 1:20 | Owner: *Q3 contract* → change Vikram to **View only**. Viewer: open the contract → **Download** | "Changing access applies on the very next click. And look at the answer: *You don't have access to this file.* It's the same answer for a document that doesn't exist, one you were never given, one that expired - you learn nothing by probing. The real reason is in the audit trail." |
| 1:50 | Owner: *Board minutes* (Vikram has 15 minutes) → **Share link** → Vikram → Create → Copy. Paste into the viewer window | "A share link works for five minutes, only for the person it names, signed in as themselves, and only while they still have access - a link never gives access on its own. Here it is, with its countdown." |
| 2:15 | Paste the same link into the owner's window (or sign in as admin) | "Forwarded to anyone else, it opens nothing - and the admin is told." |
| 2:30 | Owner: **Revoke all links**. Viewer: click View again → no access | "Revoking doesn't wait for the five minutes: the link carries a version number, and revoking changes it." |
| 2:40 | Owner: open *Audit papers* (Confidential, not shared) → copy the address. Viewer: **Documents → Ask for access** → paste → *View + download*, a note → **Send request**. Owner: **Documents** → *Requests waiting for you* → **Approve** | "Refused? Ask. The request gives the same answer for a made-up id, so it's no way to find out what exists - and the viewer doesn't see the name until the owner says yes. Because this one is Confidential, the owner's answer starts at View only for one hour. Requested, approved, denied: all in the trail." |
| 3:00 | Viewer: **My requests** → *Approved* with its countdown → open it → **View** | "Confidential means every page is marked CONFIDENTIAL with the reader's name. A label never opens anything - Public still means only the people it's shared with - and only the owner can change it, every change audited." |
| 3:15 | Leave the viewer window alone until the *"Are you still there?"* dialog appears → **Stay signed in** | "Sessions end after 15 minutes without activity - three for this recording - or 8 hours. One minute before, it asks. If nobody answers, you're signed out, and after signing in you land back where you were." |
| 3:30 | Terminal: `python scripts\attack_selftest.py` | "This attacks the running system the way a judge would: other documents' ids, versions of other documents, view-only trying to download, forged and forwarded links, CSRF, search wildcards, malicious uploads, a spreadsheet formula as a username, a password without its code, approving your own request. 64 of 64 held." |
| 3:50 | Sign in as **admin** (`Keeper!Vault2026` + code) → **Audit trail** → quick filter **Denied only** → click the viewer's refused download | "Every event in plain English - 'Refused to download: their access is View only' - with the raw JSON one click away, the hash check, and everything else that viewer did in the same sign-in session." |
| 4:05 | **Verify integrity**, then **Export CSV** | "Verify recomputes the whole chain: 'Chain intact', with the number of events. The export carries its SHA-256, and the export itself, with that hash, is now an event in the trail. The admin can never open a document, never give access - only take it away." |
| 4:15 | **Access review → Unused access**: Ravi, unused for 45 days → **Revoke selected** | "Access nobody uses is flagged from the audit trail and removed in one click - its share links die with it." |
| 4:25 | Terminal: `python scripts\tamper_demo.py` | "Append-only triggers, an HMAC chain whose key is not in the database, an external anchor. Edit a row: 'Chain broken at event #2'. Delete the newest rows: 'event #N is missing'." |
| 4:38 | Terminal: `python tools\mutation_check.py --list`, then `docs\mutation_report.txt` | "You said you'd remove an authorisation check and rerun our tests. This tool does that for all 71 checks. Every single removal makes a test fail." |
| 4:52 | `trustvault\config.py` (the time limits), then THREATS.md | "Every time limit in one place, every threat with the test that proves it - and what we chose not to build." |
