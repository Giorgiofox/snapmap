"""Automatic issue/finding generation for an endpoint.

Issues are the unit of the report's recap: each carries a severity, and the
endpoint's ``interest`` score is the weighted sum of its issues. The HTML report
lets the analyst add further ``manual`` issues on top of these.
"""

from __future__ import annotations

from .models import Endpoint, Issue

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 .. critical=4
SEVERITY_WEIGHT = {"critical": 100, "high": 40, "medium": 20, "low": 8, "info": 2}

_SENSITIVE_TECH = {
    "jenkins": "high",
    "phpmyadmin": "high",
    "webmin": "high",
    "gitlab": "medium",
    "grafana": "medium",
    "kibana": "medium",
    "tomcat": "medium",
    "portainer": "high",
    "elasticsearch": "high",
    "zabbix": "medium",
    "splunk": "medium",
}


def generate_issues(ep: Endpoint) -> list[Issue]:
    """Derive automatic findings from a probed endpoint."""
    issues: list[Issue] = []

    def add(id_: str, title: str, severity: str, detail: str = "") -> None:
        issues.append(Issue(id=id_, title=title, severity=severity, detail=detail, source="auto"))

    if ep.cred_candidates:
        products = ", ".join(sorted({c.product for c in ep.cred_candidates}))
        add(
            "default-creds",
            f"Possible default credentials ({products})",
            "high",
            f"{len(ep.cred_candidates)} candidate pair(s) from the DefaultCreds database.",
        )

    tls = ep.tls or {}
    if tls.get("insecure"):
        add("insecure-tls", f"Outdated TLS protocol ({tls.get('version', '?')})", "medium",
            "A deprecated TLS/SSL version was negotiated.")

    title = (ep.title or "").lower()
    url = (ep.final_url or ep.url).lower()

    if title.startswith("index of /") or "directory listing for" in title:
        add("dir-listing", "Directory listing exposed", "medium")

    if any(k in title or k in url for k in ("login", "sign in", "log in")):
        add("login-page", "Login page exposed", "info")

    if any(k in title or k in url for k in ("admin", "dashboard", "console", "/manager")):
        add("admin-interface", "Administrative interface exposed", "medium")

    if ep.status in (401, 403):
        add("auth-required", "Authentication required (401/403)", "info")

    if ep.scheme == "http":
        add("cleartext-http", "Cleartext HTTP service (no TLS)", "low")

    if ep.scheme == "https" and ep.security_headers:
        if not ep.security_headers.get("strict-transport-security", False):
            add("missing-hsts", "HSTS header missing", "low")
        if not ep.security_headers.get("content-security-policy", False):
            add("missing-csp", "Content-Security-Policy missing", "info")

    if ep.server and any(ch.isdigit() for ch in ep.server):
        add("version-disclosure", f"Server header discloses version: {ep.server}", "info")

    techs_lower = [t.lower() for t in ep.technologies]
    for tech, severity in _SENSITIVE_TECH.items():
        if any(tech in t for t in techs_lower):
            add(f"tech-{tech}", f"Sensitive technology exposed: {tech}", severity)

    return issues


def interest_score(issues: list[Issue]) -> int:
    """Weighted sum of issue severities → the endpoint's sort/interest score."""
    return sum(SEVERITY_WEIGHT.get(i.severity, 0) for i in issues)
