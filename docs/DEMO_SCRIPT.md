# Five-minute demo script

Before recording: `reset.bat` (fresh data), `run.bat`, open http://127.0.0.1:8000 in two browser windows
(one normal, one private) so two people can be signed in at once. Keep a terminal open in the project folder
with the virtual environment activated.

| Time | Show | Say |
|---|---|---|
| 0:00 | Login page | "TrustVault: the wrong person can never read the file, and we can prove who did. Three logins: admin, owner, viewer." |
| 0:20 | Sign in as **owner** (`Author!Vault2026`) → Documents | "The owner sees what she owns. Search by name, owner, category, date - the server scopes every search to the caller's access." |
| 0:40 | Open *Board minutes - private* → Who has access → show the Access dropdown | "Access is per document, per named person, at one of three levels: view only, view plus download, or edit. No folders, so sharing one file never shares forty." |
| 1:00 | Private window: sign in as **viewer** (`Reader!Vault2026`) → Documents | "The viewer sees only the four documents shared with them - the board minutes do not exist for them." |
| 1:15 | Viewer: open *Salary letter - Vikram* → **View** → page 2 | "View only: no Download button. The server never sends the PDF - it renders each page as an image with the viewer's name and the time across it. Every page opened is recorded." |
| 1:40 | Viewer: open *Q3 contract* → View, then Download | "This one is view plus download, so the original file comes down." |
| 1:55 | Owner: on the contract, change viewer to **View only**. Viewer: click Download again → refused | "Changing access is immediate: no cached permissions. The very next request is refused - and the refusal is recorded." |
| 2:15 | Terminal: `python scripts\attack_selftest.py` | "This attacks the running system the way a judge would - other documents' ids, versions of other documents, view-only trying to download, privilege escalation, CSRF, search wildcards, malicious uploads. 35 of 35 held." |
| 2:50 | Owner: upload a `.html` file → rejected | "Uploads are checked by content, not by name: executables, HTML, SVG, PDF JavaScript, Office macros, zip bombs, CSV formulas are refused. Accepted files are encrypted with a key per version." |
| 3:05 | Copy the address of the *Board minutes* page into the viewer's window and press refresh 5 times | "The viewer guesses a document address. Every attempt says *not found* - the same answer as a document that does not exist." |
| 3:20 | Sign in as **admin** (`Keeper!Vault2026`) → Overview | "The admin sees what just happened: a high alert for repeated refused access by the viewer, plus integrity status. But the admin cannot open any document and can only remove access." |
| 3:40 | Admin → Users | "Admin CRUD: create, change role, deactivate, delete. Delete is final but keeps the record, because the audit trail must still name who did what." |
| 3:55 | Terminal: `python scripts\tamper_demo.py` | "What stops someone quietly editing the audit trail? Append-only triggers, an HMAC chain whose key is not in the database, and an external anchor. Edit a row, delete the newest rows - all detected." |
| 4:25 | Terminal: `python tools\mutation_check.py --list`, then `docs\mutation_report.txt` | "You said you'd remove an authorisation check and rerun our tests. This tool does that for all 40 checks. Every single removal makes a test fail." |
| 4:50 | THREATS.md on screen | "Every threat we thought of, what we did, the test that proves it - and what we chose not to build." |
