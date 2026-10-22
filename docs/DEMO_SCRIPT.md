# Five-minute demo script

Before recording: `reset.bat` (fresh data), then start the server **with a short idle timeout so the sign-out
warning can be shown on camera**:

```bat
set TRUSTVAULT_SESSION_IDLE_MINUTES=3
run.bat
```

Open http://127.0.0.1:8000 in **two browser windows** (one normal, one private) so two people can be signed in at
once. Keep a terminal open in the project folder with the virtual environment activated.

| Time | Show | Say |
|---|---|---|
| 0:00 | Login page | "TrustVault: the wrong person can never read the file, and we can prove who did. Three logins: admin, owner, viewer." |
| 0:15 | Sign in as **owner** (`Author!Vault2026`) → Documents | "The owner sees what she owns. Search is scoped by the server to what you can access." |
| 0:30 | Open *Board minutes - private* → *Who has access* → person Vikram, **View only**, **For how long: 15 minutes** → Grant | "Access is per document, per named person, at one of three levels - and it always ends. 30 minutes by default; here 15. There's the countdown, with Extend and Revoke." |
| 0:55 | Private window: sign in as **viewer** (`Reader!Vault2026`) → *Salary letter* → **View** | "View only: the server never sends the PDF. It renders each page as an image with the viewer's name and the time across it. No download button - and the download URL is refused." |
| 1:20 | Owner: *Q3 contract* → change Vikram to **View only**. Viewer: open the contract → **Download** | "Changing access applies on the very next click. And look at the answer: *You don't have access to this file.* It's the same answer for a document that doesn't exist, one you were never given, one that expired - you learn nothing by probing. The real reason is in the audit trail." |
| 1:50 | Owner: *Audit papers* → **Share link** → Vikram → Create → Copy. Paste into the viewer window | "A share link works for five minutes, only for the person it names, signed in as themselves. Here it is, with its countdown." |
| 2:15 | Paste the same link into the owner's window (or sign in as admin) | "Forwarded to anyone else, it opens nothing - and the admin is told." |
| 2:30 | Owner: **Revoke all links**. Viewer: click View again → no access | "Revoking doesn't wait for the five minutes: the link carries a version number, and revoking changes it." |
| 2:45 | Leave the viewer window alone until the *"Are you still there?"* dialog appears → **Stay signed in** | "Sessions end after 15 minutes without activity - three for this recording - or 8 hours. Two minutes before, it asks. If nobody answers, you're signed out, and after signing in you land back where you were." |
| 3:05 | Terminal: `python scripts\attack_selftest.py` | "This attacks the running system the way a judge would: other documents' ids, versions of other documents, view-only trying to download, forged and forwarded links, CSRF, search wildcards, malicious uploads. 42 of 42 held." |
| 3:30 | Sign in as **admin** (`Keeper!Vault2026`) → Overview, then *Access review* → a document | "The admin sees what happened: refused access, the forwarded link. Every grant with its end time. But the admin can never open a document, never give access - only take it away." |
| 3:55 | Terminal: `python scripts\tamper_demo.py` | "What stops someone quietly editing the audit trail? Append-only triggers, an HMAC chain whose key is not in the database, and an external anchor. Edit a row, delete the newest rows - all detected." |
| 4:20 | Terminal: `python tools\mutation_check.py --list`, then `docs\mutation_report.txt` | "You said you'd remove an authorisation check and rerun our tests. This tool does that for all 42 checks. Every single removal makes a test fail." |
| 4:45 | `trustvault\config.py` (the four time limits), then THREATS.md | "Every time limit in one place, every threat with the test that proves it - and what we chose not to build." |
