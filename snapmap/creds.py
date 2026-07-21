"""Default-credentials database: lookup + updater.

Data source: ihebski/DefaultCreds-cheat-sheet (aggregates changeme, routersploit
and SecLists). Bundled as ``data/default_creds.csv`` (columns:
``productvendor,username,password``; ``<blank>`` means empty value).

Matching is passive: we only *propose* candidate credentials for a fingerprinted
product. Actively testing them is intentionally out of scope here.
"""

from __future__ import annotations

import csv
import re
import urllib.request
from functools import lru_cache
from importlib import resources
from pathlib import Path

from .models import CredCandidate

DEFAULT_CREDS_URL = (
    "https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/"
    "main/DefaultCreds-Cheat-Sheet.csv"
)

_BLANK = "<blank>"


def _csv_path() -> Path:
    return Path(str(resources.files("snapmap.data").joinpath("default_creds.csv")))


@lru_cache(maxsize=1)
def _load_db() -> dict[str, list[tuple[str, str]]]:
    """Return ``product_lower -> [(username, password), ...]``."""
    db: dict[str, list[tuple[str, str]]] = {}
    try:
        text = _csv_path().read_text(encoding="utf-8", errors="replace")
    except OSError:
        return db
    reader = csv.reader(text.splitlines())
    next(reader, None)  # header
    for row in reader:
        if len(row) < 3:
            continue
        product, user, pw = row[0].strip(), row[1].strip(), row[2].strip()
        if not product:
            continue
        user = "" if user == _BLANK else user
        pw = "" if pw == _BLANK else pw
        db.setdefault(product.lower(), []).append((user, pw))
    return db


@lru_cache(maxsize=1)
def _product_index() -> list[str]:
    """Product keys sorted longest-first so specific names win over generic ones."""
    return sorted(_load_db().keys(), key=len, reverse=True)


# High-confidence vendor aliases: a product/brand often shows up under a marketing
# name in fingerprints (e.g. "HP LaserJet") but under a vendor name in the database
# (e.g. "Hewlett-Packard"). Each entry maps a signal regex to the db product keys to
# propose. This also covers vendors whose db key is too short (<3 chars) to match
# generically, like "hp".
_VENDOR_ALIASES: list[tuple[str, list[str]]] = [
    (r"\bhp\b|hewlett|laserjet|officejet|deskjet|jetdirect|chaisoe", ["hewlett-packard", "hp"]),
    (r"mikrotik|routeros", ["mikrotik"]),
    (r"ubiquiti|unifi|\bubnt\b", ["ubiquiti"]),
    (r"fortinet|fortigate|fortios", ["fortinet"]),
    (r"\bcisco\b", ["cisco"]),
    (r"hikvision", ["hikvision"]),
    (r"\bdahua\b", ["dahua"]),
]


def _add_product(out, seen, db, key, max_per_product) -> None:
    if key in db and key not in seen:
        seen.add(key)
        for user, pw in db[key][:max_per_product]:
            out.append(CredCandidate(product=key, username=user, password=pw))


def match_products(
    *signals: str,
    max_products: int = 3,
    max_per_product: int = 10,
) -> list[CredCandidate]:
    """Propose default credentials by keyword-matching fingerprint ``signals``
    (nmap product, Server header, page title, detected technologies, ...)."""
    db = _load_db()
    if not db:
        return []
    hay = " ".join(s for s in signals if s).lower()
    if not hay.strip():
        return []
    out: list[CredCandidate] = []
    seen: set[str] = set()
    # high-confidence vendor aliases first (e.g. "HP LaserJet" -> Hewlett-Packard/HP)
    for pattern, keys in _VENDOR_ALIASES:
        if re.search(pattern, hay):
            for key in keys:
                _add_product(out, seen, db, key, max_per_product)
    # then generic product-name matching to fill the remaining slots
    for product in _product_index():
        if len(seen) >= max_products:
            break
        if len(product) < 3 or product in seen:
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(product) + r"(?![a-z0-9])", hay):
            _add_product(out, seen, db, product, max_per_product)
    return out


def search(query: str, limit: int = 300) -> list[CredCandidate]:
    """Return every credential pair whose product name contains ``query`` (case-
    insensitive substring). Powers the ``snapmap creds`` lookup command."""
    db = _load_db()
    q = (query or "").strip().lower()
    if not q or not db:
        return []
    out: list[CredCandidate] = []
    for product in sorted(db):
        if q in product:
            for user, pw in db[product]:
                out.append(CredCandidate(product=product, username=user, password=pw))
                if len(out) >= limit:
                    return out
    return out


def db_stats() -> tuple[int, int]:
    """Return ``(product_count, credential_pair_count)``."""
    db = _load_db()
    return len(db), sum(len(v) for v in db.values())


def update_db(url: str = DEFAULT_CREDS_URL, dest: Path | None = None) -> tuple[int, int]:
    """Download the latest credentials CSV over the bundled copy.

    Returns ``(product_count, credential_pair_count)`` after refresh. Raises on
    network error or if the payload does not look like the expected CSV.
    """
    dest = dest or _csv_path()
    req = urllib.request.Request(url, headers={"User-Agent": "snapmap-update"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (trusted URL)
        data = resp.read().decode("utf-8", errors="replace")
    first = data.splitlines()[0].lower() if data else ""
    if "username" not in first or "password" not in first:
        raise ValueError("downloaded file does not look like the expected CSV (missing header)")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(data, encoding="utf-8")
    _load_db.cache_clear()
    _product_index.cache_clear()
    return db_stats()
