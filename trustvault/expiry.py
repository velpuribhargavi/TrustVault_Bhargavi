"""Expiry helpers - minimal stub for deploy."""
import logging

log = logging.getLogger("trustvault")

SWEEP_INTERVAL_SECONDS = 300

def log_expired_grants(conn, audit) -> int:
    """Log expired grants at startup. Stub returns 0."""
    try:
        # Try to find expired grants if table exists, else do nothing
        rows = conn.execute("SELECT id FROM grants WHERE expires_at < datetime('now')").fetchall()
        if rows:
            log.info("Found %d expired grants at startup", len(rows))
        return len(rows)
    except Exception:
        # Table may not exist yet during first run
        return 0
