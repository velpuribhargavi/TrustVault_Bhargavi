"""Small shared helpers: clock, identifiers, text hygiene."""
from __future__ import annotations

import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone

ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

# Characters that can visually reorder or hide text (used to spoof file
# extensions such as "invoice‮txt.exe") plus zero-width characters.
_BIDI_AND_INVISIBLE = {
    "​", "‌", "‍", "‎", "‏",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩", "﻿",
}


# Every "what time is it" in the server goes through utcnow(). The tests move
# this offset forward to check time limits (a 5-minute link, a 30-minute grant,
# a 15-minute idle timeout) without sleeping. Production never changes it.
_CLOCK_OFFSET = timedelta(0)


def utcnow() -> datetime:
    return datetime.now(timezone.utc) + _CLOCK_OFFSET


def iso(dt: datetime) -> str:
    """Fixed-width UTC timestamp so that string comparison == time comparison."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_iso() -> str:
    return iso(utcnow())


def iso_in(**delta) -> str:
    return iso(utcnow() + timedelta(**delta))


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def new_id() -> str:
    """Unguessable identifier (128 bits). IDs are not the security boundary -
    authorization is - but random IDs make enumeration pointless."""
    return secrets.token_urlsafe(16)


def is_valid_id(value: str) -> bool:
    return bool(ID_PATTERN.match(value or ""))


def clean_text(value: str, max_len: int) -> str:
    """Normalise user-supplied text: NFKC, drop control/bidi characters, trim."""
    value = unicodedata.normalize("NFKC", value or "")
    value = "".join(
        ch for ch in value
        if ch not in _BIDI_AND_INVISIBLE and (ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    )
    return value.strip()[:max_len]


def clean_line(value: str, max_len: int) -> str:
    """Like clean_text but also removes newlines (for names, log fields)."""
    return " ".join(clean_text(value, max_len * 2).split())[:max_len]
