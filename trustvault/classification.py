"""Classification labels: Public, Internal, Confidential.

The owner picks one at upload (default Internal) and can change it later;
every change is audited (``document.classified``). A label never grants
access - every document, Public included, is still shared with named people
only and checked by ``authz.check_access`` on every request. What a label
changes:

* **Confidential** - every preview page is marked CONFIDENTIAL (on top of the
  viewer's name and the time that every preview carries); new access defaults
  to *View only* for CONFIDENTIAL_GRANT_MINUTES (1 hour) instead of
  DEFAULT_GRANT_MINUTES; raising a document to Confidential cancels its
  outstanding share links.
* **Internal** (default) and **Public** - the normal defaults.
"""
from __future__ import annotations

LABELS = ("public", "internal", "confidential")
DEFAULT = "internal"
RANK = {"public": 0, "internal": 1, "confidential": 2}
NAMES = {"public": "Public", "internal": "Internal", "confidential": "Confidential"}


class BadLabel(ValueError):
    pass


def validate(label: str | None) -> str:
    value = (label or DEFAULT).strip().lower()
    if value not in LABELS:
        raise BadLabel(f"Classification must be one of: {', '.join(LABELS)}")
    return value


def default_grant_minutes(settings, label: str) -> int:
    if label == "confidential":  # AUTHZ-CHECK[confidential-access-defaults-to-one-hour]
        return settings.confidential_grant_minutes
    return settings.default_grant_minutes


def default_permission(label: str) -> str:
    """Least privilege by default: View only - for Confidential, the spec's rule."""
    return "view"


def watermark_prefix(label: str) -> str:
    if label == "confidential":  # AUTHZ-CHECK[confidential-preview-is-marked]
        return "CONFIDENTIAL · "
    return ""
