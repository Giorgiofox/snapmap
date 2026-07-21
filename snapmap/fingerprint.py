"""Lightweight technology fingerprinting from HTTP headers + body.

Not a full Wappalyzer — a curated signature set biased toward things that matter
for recon: web servers, frameworks, and exposed admin panels / devices (which
also drive default-credential matching in :mod:`snapmap.creds`).
"""

from __future__ import annotations

import re

# name -> list of (where, regex). where is "header:<lower-name>" or "body".
_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "Apache": [("header:server", r"apache")],
    "nginx": [("header:server", r"nginx")],
    "Microsoft-IIS": [("header:server", r"microsoft-iis")],
    "LiteSpeed": [("header:server", r"litespeed")],
    "Tomcat": [("header:server", r"(coyote|tomcat)"), ("body", r"apache tomcat")],
    "Jetty": [("header:server", r"jetty")],
    "lighttpd": [("header:server", r"lighttpd")],
    "PHP": [("header:x-powered-by", r"php"), ("header:set-cookie", r"phpsessid")],
    "ASP.NET": [("header:x-powered-by", r"asp\.net"), ("header:x-aspnet-version", r".+")],
    "Express": [("header:x-powered-by", r"express")],
    "Node.js": [("header:x-powered-by", r"node")],
    "WordPress": [("body", r"/wp-(content|includes)/"), ("header:link", r"wp-json")],
    "Joomla": [("body", r"/media/jui/|joomla")],
    "Drupal": [("header:x-generator", r"drupal"), ("body", r"drupal")],
    "Jenkins": [("header:x-jenkins", r".+"), ("body", r"jenkins")],
    "GitLab": [("body", r"gitlab"), ("header:set-cookie", r"_gitlab_session")],
    "Grafana": [("body", r"grafana"), ("header:set-cookie", r"grafana_")],
    "Kibana": [("body", r"kibana|kbn-")],
    "phpMyAdmin": [("body", r"phpmyadmin"), ("header:set-cookie", r"phpmyadmin")],
    "Splunk": [("body", r"splunk")],
    "Zabbix": [("body", r"zabbix")],
    "pfSense": [("body", r"pfsense")],
    "Cockpit": [("body", r"cockpit")],
    "Webmin": [("header:server", r"miniserv"), ("body", r"webmin")],
    "Portainer": [("body", r"portainer")],
    "Kubernetes": [("body", r"kubernetes"), ("header:server", r"kube")],
    "Elasticsearch": [("body", r'"cluster_name"'), ("header:x-elastic-product", r".+")],
    "MikroTik": [("header:server", r"mikrotik|routeros")],
    "TP-LINK": [("header:www-authenticate", r"tp-link"), ("body", r"tp-link|tplink")],
    "Ubiquiti": [("body", r"\b(?:ubnt|unifi|ubiquiti)\b")],
    "Cisco": [("header:server", r"cisco"), ("body", r"cisco")],
    "D-Link": [("header:server", r"dlink"), ("body", r"d-link")],
    "Netgear": [("body", r"netgear")],
    "Fortinet": [("header:server", r"fortinet"), ("body", r"fortigate|fortinet")],
    "Hikvision": [("header:server", r"hikvision|dvrdvs|app-webs"), ("body", r"hikvision")],
    "Dahua": [("body", r"dahua")],
    "Axis": [("header:server", r"\baxis\b"), ("body", r"axis communications|/axis-cgi/")],
    "VMware": [("body", r"vmware"), ("header:server", r"vmware")],
    "Synology": [("header:server", r"nginx"), ("body", r"synology|diskstation")],
    "QNAP": [("body", r"qnap")],
    "Printer/JetDirect": [("header:server", r"(jetdirect|hp http server|printer)")],
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def fingerprint(headers: dict[str, str], body: bytes, *extra: str) -> list[str]:
    """Return a sorted list of detected technologies.

    ``headers`` keys must be lower-cased. ``extra`` accepts additional free-text
    signals (e.g. nmap product) that are matched against the body signatures.
    """
    text = body.decode("utf-8", errors="replace").lower() if body else ""
    if extra:
        text += " " + " ".join(e.lower() for e in extra if e)
    found: set[str] = set()
    for name, sigs in _SIGNATURES.items():
        for where, pattern in sigs:
            if where == "body":
                haystack = text
            else:
                haystack = headers.get(where.split(":", 1)[1], "").lower()
            if haystack and re.search(pattern, haystack):
                found.add(name)
                break
    # Surface the raw Server value too (often carries product+version).
    server = headers.get("server", "").strip()
    if server:
        found.add(server if len(server) <= 40 else server[:40])
    return sorted(found)


def security_headers(headers: dict[str, str]) -> dict[str, bool]:
    """Presence map for the security headers we care about (keys lower-cased)."""
    return {h: (h in headers) for h in SECURITY_HEADERS}
