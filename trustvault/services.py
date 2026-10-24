"""Services stub."""
import logging
log = logging.getLogger("trustvault")

def purge_expired_trash(conn, ctx) -> int:
    try:
        cur = conn.execute("DELETE FROM documents WHERE deleted_at IS NOT NULL AND deleted_at < datetime('now', '-30 days')")
        if cur.rowcount:
            log.info("Purged %d expired trash docs", cur.rowcount)
        return cur.rowcount
    except Exception:
        return 0
