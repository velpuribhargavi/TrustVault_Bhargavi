# Reusable prompt: adversarial review of a change

Used after every non-trivial change (paste the diff after it). The point is to
make the assistant attack the code instead of praising it.

---

Act as the hackathon judge whose job is to reach a document you were not
granted on this system. Here is a change to TrustVault (diff below).

For this diff only:

1. List every new or changed code path that reads or writes a document,
   version, grant, share link, suggestion, user or session.
2. For each, state exactly which check stops (a) a signed-in user with no grant,
   (b) a read-grantee trying to edit, (c) an edit-grantee trying to share or
   delete, (d) an admin, (e) a deactivated user with an old session,
   (f) someone using an id that belongs to a *different* document.
   Quote the line. If you cannot quote a line, say "NO CHECK FOUND".
3. Is every refusal written to the audit trail? Quote the call.
4. Could any of these be answered differently by *removing one line* without a
   test failing? Name the test that would catch it, or say "NO TEST".
5. Anything that is cached, signed, or long-lived that would survive revocation?

Do not summarise what the code does. Do not say it looks good. Only list
findings, each with the line, the attack, and the missing check or test.
