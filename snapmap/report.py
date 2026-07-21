"""Report generation: one self-contained HTML page plus JSON/CSV exports.

The HTML report is the primary deliverable: a single file with an inlined
dark-theme UI (client-side search/filter/sort, per-endpoint issues editor and a
findings recap). ``endpoint_to_dict`` is the single source of truth for the
shape of both the embedded JSON and the standalone JSON export.
"""

from __future__ import annotations

import csv
import io
import json
from importlib import resources
from typing import Any

import jinja2

from .issues import SEVERITIES, SEVERITY_ORDER, SEVERITY_WEIGHT
from .models import Endpoint

_env = jinja2.Environment(
    loader=jinja2.FunctionLoader(
        lambda name: resources.files("snapmap.templates").joinpath(name).read_text("utf-8")
    ),
    autoescape=True,
)


def endpoint_to_dict(ep: Endpoint, include_screenshot: bool = True) -> dict[str, Any]:
    """Flatten an :class:`Endpoint` into a JSON-serialisable dict.

    The key set is fixed and consumed verbatim by the report JS and the JSON
    export; ``screenshot`` is ``""`` when excluded or absent.
    """
    return {
        "url": ep.url,
        "scheme": ep.scheme,
        "ip": ep.ip,
        "port": ep.port,
        "host": ep.host,
        "nmap_service": ep.nmap_service,
        "nmap_product": ep.nmap_product,
        "nmap_version": ep.nmap_version,
        "status": ep.status,
        "reason": ep.reason,
        "title": ep.title,
        "server": ep.server,
        "content_type": ep.content_type,
        "content_length": ep.content_length,
        "final_url": ep.final_url,
        "redirects": list(ep.redirects),
        "technologies": list(ep.technologies),
        "security_headers": dict(ep.security_headers),
        "response_headers": dict(ep.response_headers),
        "tls": ep.tls,
        "favicon_hash": ep.favicon_hash,
        "cred_candidates": [
            {"product": c.product, "username": c.username, "password": c.password}
            for c in ep.cred_candidates
        ],
        "issues": [
            {"id": i.id, "title": i.title, "severity": i.severity, "detail": i.detail, "source": i.source}
            for i in ep.issues
        ],
        "interest": ep.interest,
        "error": ep.error,
        "alive": ep.alive,
        "subnet": ep.subnet,
        "screenshot": ep.screenshot if include_screenshot else "",
    }


def render_html(endpoints: list[Endpoint], meta: dict) -> str:
    """Render the self-contained HTML report for ``endpoints``."""
    data = [endpoint_to_dict(ep, include_screenshot=True) for ep in endpoints]
    # Embed as JSON inside a <script type="application/json"> block. Escaping
    # "<" prevents the payload from breaking out of the element (e.g. "</script>").
    data_json = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    severity_meta = {
        "severities": SEVERITIES,
        "order": SEVERITY_ORDER,
        "weight": SEVERITY_WEIGHT,
    }
    template = _env.get_template("report.html.j2")
    return template.render(
        data_json=data_json,
        meta=meta,
        meta_json=json.dumps(meta, ensure_ascii=False).replace("<", "\\u003c"),
        severity_json=json.dumps(severity_meta, ensure_ascii=False).replace("<", "\\u003c"),
    )


def write_html(endpoints: list[Endpoint], meta: dict, path: str) -> None:
    """Render and write the HTML report to ``path``."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(endpoints, meta))


def write_json(endpoints: list[Endpoint], path: str, meta: dict | None = None) -> None:
    """Write a JSON export (screenshots excluded) to ``path``."""
    payload: dict[str, Any] = {
        "endpoints": [endpoint_to_dict(ep, include_screenshot=False) for ep in endpoints]
    }
    if meta is not None:
        payload["meta"] = meta
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def write_csv(endpoints: list[Endpoint], path: str) -> None:
    """Write a flat CSV summary (one row per endpoint) to ``path``."""
    columns = [
        "url", "ip", "port", "scheme", "status", "title", "server",
        "technologies", "tls_version", "tls_insecure", "cred_products",
        "issue_count", "top_severity", "interest",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for ep in endpoints:
        tls = ep.tls or {}
        cred_products = ";".join(dict.fromkeys(c.product for c in ep.cred_candidates))
        top_severity = ""
        if ep.issues:
            top_severity = max(ep.issues, key=lambda i: SEVERITY_ORDER.get(i.severity, -1)).severity
        writer.writerow({
            "url": ep.url,
            "ip": ep.ip,
            "port": ep.port,
            "scheme": ep.scheme,
            "status": ep.status if ep.status is not None else "",
            "title": ep.title,
            "server": ep.server,
            "technologies": ";".join(ep.technologies),
            "tls_version": tls.get("version", ""),
            "tls_insecure": tls.get("insecure", ""),
            "cred_products": cred_products,
            "issue_count": len(ep.issues),
            "top_severity": top_severity,
            "interest": ep.interest,
        })
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(buf.getvalue())


def save_screenshots(endpoints: list[Endpoint], directory: str) -> int:
    """Write each endpoint's embedded screenshot to a PNG file under ``directory``.

    Returns the number of files written. Screenshots are also embedded in the HTML
    report; this simply gives a project folder browsable image files as well.
    """
    import base64
    import os
    import re

    written = 0
    for ep in endpoints:
        if not ep.screenshot:
            continue
        if written == 0:
            os.makedirs(directory, exist_ok=True)
        # name by scheme_ip_port so it is unique per endpoint (URLs with a trailing
        # slash would otherwise collide and overwrite each other)
        raw = f"{ep.scheme}_{ep.ip}_{ep.port}"
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")[:120] or "endpoint"
        try:
            with open(os.path.join(directory, f"{name}.png"), "wb") as fh:
                fh.write(base64.b64decode(ep.screenshot))
            written += 1
        except (OSError, ValueError):
            continue
    return written
