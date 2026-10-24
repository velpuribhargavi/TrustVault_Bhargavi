"""Access suggestions ("who should see this document?").

Design rules, each enforced in code and covered by tests:

1. **It never widens access.** This module only reads. The only way a
   suggestion becomes a grant is the owner calling the normal, authenticated,
   CSRF-protected grant endpoint with the suggestion id; both the suggestion
   and the decision are written to the audit trail.
2. **It never leaks.** Signals come only from the requesting owner's *own*
   sharing history. Other owners' grants are never read, so a suggestion
   cannot reveal who has access to documents the owner cannot see.
3. **Least privilege.** It only ever proposes ``view`` (no download).
4. **No content leaves the server.** It is a local, explainable scoring model
   over document names and categories - no file content is sent to any
   external AI service. Every suggestion carries human-readable reasons.
"""
from __future__ import annotations

import re
import sqlite3

STOPWORDS = {"the", "and", "for", "with", "from", "of", "to", "in", "on", "a", "an", "rev", "v1", "v2", "final",
             "draft", "copy", "doc", "docx", "pdf", "xlsx", "pptx", "txt", "csv", "png", "jpg"}
MIN_SCORE = 0.15
MAX_SUGGESTIONS = 5


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) >= 3 and t not in STOPWORDS}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def suggest_readers(conn: sqlite3.Connection, owner_id: str, document: dict) -> list[dict]:
    candidates = conn.execute(
        """SELECT id, username, display_name, is_external FROM users
           WHERE is_active = 1 AND role != 'admin' AND id != :owner
             AND id NOT IN (SELECT user_id FROM grants WHERE document_id = :doc)""",
        {"owner": owner_id, "doc": document["id"]},
    ).fetchall()
    if not candidates:
        return []
    # Only the owner's own sharing history (rule 2).
    history = conn.execute(
        """SELECT g.user_id, d.category, d.name FROM grants g JOIN documents d ON d.id = g.document_id
           WHERE d.owner_id = :owner AND d.id != :doc AND d.purged_at IS NULL""",
        {"owner": owner_id, "doc": document["id"]},
    ).fetchall()
    by_user: dict[str, list] = {}
    for h in history:
        by_user.setdefault(h["user_id"], []).append(h)

    doc_tokens = _tokens(document["name"])
    results = []
    for c in candidates:
        shared = by_user.get(c["id"], [])
        if not shared:
            continue
        same_category = sum(1 for h in shared if h["category"] == document["category"])
        best_name, best_sim = None, 0.0
        for h in shared:
            sim = _jaccard(doc_tokens, _tokens(h["name"]))
            if sim > best_sim:
                best_name, best_sim = h["name"], sim
        score = 0.6 * min(same_category, 5) / 5 + 0.3 * best_sim + 0.1 * min(len(shared), 10) / 10
        reasons = []
        if same_category:
            reasons.append(f"You shared {same_category} other '{document['category']}' document(s) with them")
        if best_sim > 0:
            reasons.append(f"They have access to your similarly named document '{best_name}'")
        if len(shared) and not same_category and best_sim == 0:
            reasons.append(f"You have shared {len(shared)} document(s) with them before")
        if c["is_external"]:
            score *= 0.5
            reasons.append("External user - check this document is meant to leave the company")
        if score >= MIN_SCORE:
            results.append({
                "user_id": c["id"], "username": c["username"], "display_name": c["display_name"],
                "is_external": bool(c["is_external"]), "permission": "view",
                "score": round(score, 3), "reasons": reasons,
            })
    results.sort(key=lambda r: (-r["score"], r["username"]))
    return results[:MAX_SUGGESTIONS]
