"""nmap / masscan driver and XML parser.

Runs a fast nmap sweep, parses the resulting XML (nmap *or* masscan share the
same schema) into :class:`~snapmap.models.Host` objects, and turns those into
probe-ready :class:`~snapmap.models.Endpoint` objects with sensible scheme
guessing and IPv6-safe URLs.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .models import Endpoint, Host, Service
from .ports import SECURE_PORTS, parse_port_list, resolve_ports


class NmapNotFound(RuntimeError):
    """Raised when the ``nmap`` binary cannot be located on ``PATH``."""


# Service names whose ssl/tls variants are clearly not web interfaces.
_NON_WEB_SERVICES: set[str] = {
    "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "ftp", "ftps",
    "ssh", "telnet", "ldap", "ldaps", "ntp", "dns", "domain", "snmp",
    "rdp", "ms-wbt-server", "vnc", "mysql", "postgresql", "redis",
    "mongodb", "sip", "sips", "xmpp", "irc", "ircs", "nntp", "nntps",
    "rsync", "ident", "netbios-ssn", "microsoft-ds", "kerberos-sec",
}


def nmap_available() -> bool:
    """Return ``True`` if the ``nmap`` binary is on ``PATH``."""
    return shutil.which("nmap") is not None


def run_nmap(
    target: str,
    ports: str,
    *,
    rate: int = 5000,
    timing: int = 4,
    no_ping: bool = False,
    service_detection: bool = True,
    extra_args: list[str] | None = None,
    sudo: bool = False,
    out_base: str | None = None,
    log=print,
) -> str:
    """Run a fast nmap sweep and return its XML output as a string.

    Builds a speed-oriented command and streams XML to stdout via ``-oX -``.
    Raises :class:`NmapNotFound` if nmap is missing and :class:`RuntimeError`
    if the scan exits non-zero.
    """
    if not nmap_available():
        raise NmapNotFound("nmap not found on PATH; install nmap or use `report`")

    cmd: list[str] = [
        "nmap", "-n", f"-T{timing}", "--min-rate", str(rate),
        "--open", "-p", resolve_ports(ports), "-oX", "-",
    ]
    if out_base:
        # also persist the human-readable + greppable formats next to the XML
        cmd += ["-oN", f"{out_base}.nmap", "-oG", f"{out_base}.gnmap"]
    if no_ping:
        cmd.append("-Pn")
    if service_detection:
        cmd += ["-sV", "--version-light"]
    if extra_args:
        cmd += extra_args
    cmd += target.split()
    if sudo:
        cmd = ["sudo"] + cmd

    log("running: " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"nmap exited with {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout


def parse_nmap_xml(xml_text: str) -> list[Host]:
    """Parse nmap/masscan XML into :class:`Host` objects.

    Skips hosts reported ``down``, ignores mac addresses, and keeps only open
    tcp ports. masscan XML follows the same schema but may omit ``<service>``.
    """
    root = ET.fromstring(xml_text)
    hosts: list[Host] = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") == "down":
            continue

        address = ""
        address_type = "ipv4"
        for addr in host_el.findall("address"):
            addrtype = addr.get("addrtype", "")
            if addrtype == "mac":
                continue
            address = addr.get("addr", "")
            address_type = addrtype or address_type
            break
        if not address:
            continue

        hostnames: list[str] = []
        hn_el = host_el.find("hostnames")
        if hn_el is not None:
            for hn in hn_el.findall("hostname"):
                name = hn.get("name", "")
                if name and name not in hostnames:
                    hostnames.append(name)

        services: list[Service] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                if port_el.get("protocol", "tcp") != "tcp":
                    continue
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                try:
                    portid = int(port_el.get("portid", ""))
                except (TypeError, ValueError):
                    continue

                svc = Service(port=portid, protocol="tcp", state="open")
                svc_el = port_el.find("service")
                if svc_el is not None:
                    svc.name = svc_el.get("name", "")
                    svc.product = svc_el.get("product", "")
                    svc.version = svc_el.get("version", "")
                    svc.extrainfo = svc_el.get("extrainfo", "")
                    svc.tunnel = svc_el.get("tunnel", "")
                services.append(svc)

        hosts.append(
            Host(
                address=address,
                address_type=address_type,
                hostnames=hostnames,
                services=services,
            )
        )

    return hosts


def scheme_for_service(svc: Service) -> str | None:
    """Guess the web scheme for a service, or ``None`` if it is not web.

    Non-web ssl services (smtp/imap/ssh/...) return ``None``. Otherwise ssl/tls
    tunnels and https/ssl-flavoured names imply https, http-flavoured names
    imply http, and unknowns default by whether the port is in ``SECURE_PORTS``.
    """
    name = (svc.name or "").lower()
    if name in _NON_WEB_SERVICES:
        return None

    tunnel = (svc.tunnel or "").lower()
    if tunnel in ("ssl", "tls") or "https" in name or "ssl" in name:
        return "https"
    if "http" in name:
        return "http"
    if not name:
        return "https" if svc.port in SECURE_PORTS else "http"
    # Known-but-unclassified name: fall back to port heuristic.
    return "https" if svc.port in SECURE_PORTS else "http"


def build_url(scheme: str, host: str, port: int) -> str:
    """Build a URL, bracketing IPv6 hosts and omitting default ports."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if default:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _iter_ips(token: str) -> list[str]:
    """Expand a single token (CIDR or IP) into a list of addresses."""
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        try:
            return [str(ipaddress.ip_address(token))]
        except ValueError:
            return []
    if net.num_addresses <= 2:  # /31, /32 (and v6 equivalents): keep every address
        return [str(ip) for ip in net]
    return [str(ip) for ip in net.hosts()]


def expand_targets(target: str, ports: str) -> list[Endpoint]:
    """Build the full IP x port endpoint grid directly, bypassing nmap.

    Intended for networks with a SYN-proxy/firewall (e.g. Cisco Meraki) that make
    every TCP port look open: there a port scan is worthless, so we probe every
    candidate over HTTP and let the responder be the only source of truth. The
    scheme is guessed from the port (https for SECURE_PORTS, else http); the prober
    retries the opposite scheme on connection failure.
    """
    port_list = parse_port_list(ports)
    endpoints: list[Endpoint] = []
    seen: set[str] = set()
    for token in target.split():
        for ip in _iter_ips(token):
            for port in port_list:
                scheme = "https" if port in SECURE_PORTS else "http"
                url = build_url(scheme, ip, port)
                if url in seen:
                    continue
                seen.add(url)
                endpoints.append(
                    Endpoint(url=url, scheme=scheme, ip=ip, port=port, host=ip)
                )
    return endpoints


def build_endpoints(
    hosts: list[Host], *, include_hostnames: bool = True
) -> list[Endpoint]:
    """Expand hosts into deduped web endpoints (one per name+service).

    The name set is the host address plus, when ``include_hostnames`` is set,
    its resolved hostnames. Endpoints are deduplicated by URL and carry the
    nmap-derived service metadata.
    """
    endpoints: list[Endpoint] = []
    seen: set[str] = set()

    for host in hosts:
        names: list[str] = [host.address]
        if include_hostnames:
            for hn in host.hostnames:
                if hn and hn not in names:
                    names.append(hn)

        for svc in host.services:
            scheme = scheme_for_service(svc)
            if scheme is None:
                continue
            for name in names:
                url = build_url(scheme, name, svc.port)
                if url in seen:
                    continue
                seen.add(url)
                endpoints.append(
                    Endpoint(
                        url=url,
                        scheme=scheme,
                        ip=host.address,
                        port=svc.port,
                        host=name,
                        nmap_service=svc.name,
                        nmap_product=svc.product,
                        nmap_version=svc.version,
                    )
                )

    return endpoints
