"""Orchestration: run the prober, derive creds/issues, then screenshot.

The pipeline mutates the endpoints in place. Networking lives in ``prober``,
default-credential matching in ``creds`` and finding generation in ``issues``;
this module just wires them together in the right order.
"""

from __future__ import annotations

from . import creds, issues, prober, screenshot
from .models import Endpoint, Options


async def process(endpoints: list[Endpoint], opts: Options, log=print) -> None:
    """Probe, enrich (creds + issues) and optionally screenshot every endpoint."""
    await prober.probe_all(endpoints, opts, log)

    for ep in endpoints:
        if not ep.alive:
            continue
        ep.cred_candidates = creds.match_products(
            ep.nmap_product,
            ep.server,
            ep.title,
            " ".join(ep.technologies),
            ep.nmap_service,
        )
        ep.issues = issues.generate_issues(ep)
        ep.interest = issues.interest_score(ep.issues)

    if opts.screenshots:
        await screenshot.capture_all(endpoints, opts, log)
