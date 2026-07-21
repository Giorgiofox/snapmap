"""Async HTTP prober — pure network layer.

Takes the endpoints derived from the nmap scan and probes each one over HTTP(S):
follows redirects, records the response metadata, fingerprints technologies and
(best-effort) grabs the TLS parameters and favicon hash. This module is strictly
network-facing: it never touches credential matching or issue generation.
"""

from __future__ import annotations

import asyncio
import base64
import html
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .fingerprint import fingerprint, security_headers
from .models import Endpoint, Options

try:  # optional dependency — favicon hashing is skipped if absent
    import mmh3
except ImportError:  # pragma: no cover - mmh3 is expected but optional
    mmh3 = None  # type: ignore[assignment]

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WS_RE = re.compile(r"\s+")
_INSECURE_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}


def _flip_scheme(scheme: str) -> str:
    """Return the opposite web scheme."""
    return "https" if scheme == "http" else "http"


def _rebuild_url(url: str, scheme: str) -> str:
    """Rebuild ``url`` with a different scheme, preserving host:port and path."""
    parts = urlsplit(url)
    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, parts.fragment))


def _extract_title(body: bytes) -> str:
    """Pull the <title> text out of an HTML body, stripped and whitespace-collapsed."""
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    raw = html.unescape(m.group(1).decode("utf-8", errors="replace"))
    return _WS_RE.sub(" ", raw).strip()


def _grab_tls(host: str, port: int, timeout: float) -> dict:
    """Blocking TLS handshake helper (run via ``asyncio.to_thread``).

    Connects with certificate verification disabled and reports the negotiated
    protocol version and cipher. ``insecure`` flags legacy protocol versions.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            version = ssock.version()
            cipher = ssock.cipher()
    return {
        "version": version,
        "cipher": cipher[0] if cipher else None,
        "insecure": version in _INSECURE_TLS,
    }


async def _probe_one(
    client: httpx.AsyncClient,
    ep: Endpoint,
    opts: Options,
    sem: asyncio.Semaphore,
    log,
) -> None:
    """Probe a single endpoint, mutating it in place."""
    async with sem:
        resp = None
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                resp = await client.get(ep.url)
                break
            except (httpx.ConnectError, httpx.ConnectTimeout, ssl.SSLError) as exc:
                last_error = exc
                if attempt == 0:
                    new_scheme = _flip_scheme(ep.scheme)
                    ep.url = _rebuild_url(ep.url, new_scheme)
                    ep.scheme = new_scheme
                    continue
            except Exception as exc:  # any other transport error → give up
                last_error = exc
                break

        ep.probed = True
        if resp is None:
            ep.error = str(last_error) if last_error else "request failed"
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.content

        ep.status = resp.status_code
        ep.reason = resp.reason_phrase or ""
        ep.final_url = str(resp.url)
        ep.redirects = [str(r.url) for r in resp.history]
        ep.response_headers = headers
        ep.server = headers.get("server", "")
        ep.content_type = headers.get("content-type", "")
        clen = headers.get("content-length")
        try:
            ep.content_length = int(clen) if clen is not None else len(body)
        except ValueError:
            ep.content_length = len(body)
        ep.title = _extract_title(body)
        ep.technologies = fingerprint(headers, body, ep.nmap_product, ep.nmap_service)
        ep.security_headers = security_headers(headers)

        if opts.do_tls and ep.scheme == "https":
            await _grab_tls_for(ep, opts)

        if opts.do_favicon:
            await _grab_favicon(client, ep)


async def _grab_tls_for(ep: Endpoint, opts: Options) -> None:
    """Best-effort TLS grab for an https endpoint."""
    parts = urlsplit(ep.final_url or ep.url)
    host = parts.hostname or ep.host or ep.ip
    port = parts.port or ep.port or 443
    try:
        ep.tls = await asyncio.to_thread(_grab_tls, host, port, opts.timeout)
    except Exception:
        pass  # best-effort, swallow errors


async def _grab_favicon(client: httpx.AsyncClient, ep: Endpoint) -> None:
    """Best-effort favicon hash (mmh3 of base64-encoded bytes)."""
    if mmh3 is None:
        return
    try:
        fav_url = urljoin(ep.final_url or ep.url, "/favicon.ico")
        resp = await client.get(fav_url)
        if resp.status_code == 200 and resp.content:
            ep.favicon_hash = mmh3.hash(base64.encodebytes(resp.content))
    except Exception:
        pass  # best-effort, swallow errors


async def probe_all(endpoints: list[Endpoint], opts: Options, log=print) -> None:
    """Probe every endpoint over HTTP(S), mutating each in place.

    Uses a single shared :class:`httpx.AsyncClient` and bounds concurrency with a
    semaphore. On a connect/SSL failure a single retry with the opposite scheme is
    attempted; on success the endpoint's ``url``/``scheme`` are updated. Failures
    set ``ep.error`` and leave ``ep.status`` as ``None``.
    """
    if not endpoints:
        return

    headers = {"User-Agent": opts.user_agent}
    headers.update(opts.headers)
    sem = asyncio.Semaphore(opts.concurrency)

    log(f"[prober] probing {len(endpoints)} endpoint(s), concurrency={opts.concurrency}")

    async with httpx.AsyncClient(
        verify=opts.verify_tls,
        follow_redirects=opts.follow_redirects,
        timeout=opts.timeout,
        proxy=opts.proxy,
        headers=headers,
    ) as client:
        await asyncio.gather(
            *(_probe_one(client, ep, opts, sem, log) for ep in endpoints)
        )
