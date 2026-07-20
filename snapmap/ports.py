"""Port list aliases and helpers.

Aliases mirror aquatone's lists so existing muscle-memory keeps working, plus a
web-focused default. ``resolve_ports`` returns an ``nmap -p`` compatible string.
"""

from __future__ import annotations

PORT_ALIASES: dict[str, str] = {
    "small": "80,443",
    "medium": "80,443,8000,8080,8443",
    "web": "80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888",
    "large": "80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888",
    "xlarge": (
        "80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,"
        "3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,"
        "8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,"
        "8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,"
        "9200,9443,9800,9981,12443,16080,18091,18092,20720,28017"
    ),
}

DEFAULT_ALIAS = "web"

# Ports that should default to https when the service name is ambiguous.
SECURE_PORTS: set[int] = {
    443, 832, 981, 1010, 1311, 2083, 2087, 2095, 2096, 4443, 4712, 7000, 8172,
    8243, 8333, 8443, 8834, 9443, 12443, 18091, 18092, 44300,
}


def resolve_ports(spec: str | None) -> str:
    """Resolve an alias to a concrete nmap port string; pass through raw specs."""
    if not spec:
        return PORT_ALIASES[DEFAULT_ALIAS]
    spec = spec.strip()
    return PORT_ALIASES.get(spec, spec)


def parse_port_list(spec: str | None) -> list[int]:
    """Expand a resolved port spec (list and ``a-b`` ranges) to a sorted int list."""
    resolved = resolve_ports(spec)
    ports: list[int] = []
    for part in resolved.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted({p for p in ports if 1 <= p <= 65535})
