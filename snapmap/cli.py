"""Command-line entry point for Snapmap.

Subcommands:
  scan TARGET      run nmap against a target, then probe/screenshot/report.
  report [--nmap]  ingest an existing nmap/masscan XML (file or stdin), then
                   probe/screenshot/report.
  update-creds     refresh the local default-credentials database.

``main`` wires the CLI arguments into an :class:`Options`, drives the async
pipeline via ``asyncio.run`` and writes the requested output formats.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime

from . import (
    __version__,
    creds,
    issues,
    nmap_scan,
    pipeline,
    report,
)
from .models import Endpoint, Options
from .ports import resolve_ports

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- #
# colored help
# --------------------------------------------------------------------------- #
def _color_enabled() -> bool:
    force = os.environ.get("SNAPMAP_FORCE_COLOR")
    if force not in (None, "", "0"):
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


_COLOR = _color_enabled()


def _c(code: str, text: str) -> str:
    """Wrap ``text`` in an ANSI SGR code when colour output is enabled."""
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


class ColorHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Help formatter adding ANSI colour to section headings and option strings."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=44, width=100)

    def start_section(self, heading):
        super().start_section(_c("1;36", heading) if heading else heading)

    def _format_action_invocation(self, action):
        return _c("32", super()._format_action_invocation(action))


BANNER = (
    _c("1;36", "snapmap") + _c("36", f" v{__version__}")
    + _c("2", "  ·  nmap → web recon → single self-contained HTML report")
)

EPILOG = "\n".join([
    _c("1;36", "Examples:"),
    _c("2", "  # Fast sweep of a subnet into a project folder (nmap + screenshots + report + json/csv)"),
    _c("32", "  snapmap scan 10.0.0.0/24 --project MinneapolisHQ"),
    "",
    _c("2", "  # Whole /22 across the web port list, skipping host discovery"),
    _c("32", "  snapmap scan 10.180.0.0/22 -Pn --ports web --project ClientX"),
    "",
    _c("2", "  # Ingest an existing nmap/masscan XML (from a file or stdin)"),
    _c("32", "  snapmap report --nmap scan.xml -o report.html"),
    _c("32", "  cat scan.xml | snapmap report --project OldScan"),
    "",
    _c("2", "  # Refresh the bundled default-credentials database"),
    _c("32", "  snapmap update-creds"),
    "",
    _c("2", "Port aliases: small · medium · web · large · xlarge   "
            "(or a custom list/range, e.g. 80,443,8000-8100)"),
])


# --------------------------------------------------------------------------- #
# logging
# --------------------------------------------------------------------------- #
def make_logger(silent: bool):
    """Return a timestamped stderr logger honoring ``--silent`` (errors always show)."""

    def log(*args, error: bool = False) -> None:
        if silent and not error:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}]", *args, file=sys.stderr, flush=True)

    return log


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #
def _add_common(p: argparse.ArgumentParser) -> None:
    """Options shared by ``scan`` and ``report`` (probing + reporting knobs)."""
    out = p.add_argument_group("output")
    out.add_argument("-p", "--project", metavar="NAME",
                     help="project name; all outputs go into a folder named NAME/ "
                          "(handy for engagements spanning several subnets/configs)")
    out.add_argument("-o", "--output", default="snapmap_report.html",
                     help="HTML report path (default: snapmap_report.html)")
    out.add_argument("--json", dest="json_out", metavar="FILE",
                     help="also write a JSON export")
    out.add_argument("--csv", dest="csv_out", metavar="FILE",
                     help="also write a CSV export")
    out.add_argument("--group-by", choices=["host", "subnet", "none"],
                     default="host", help="default report grouping (default: host)")
    out.add_argument("--report-all", action="store_true",
                     help="include non-responsive endpoints in the HTML report "
                          "(default: only endpoints that returned an HTTP response)")

    prb = p.add_argument_group("probing")
    prb.add_argument("--concurrency", type=int, default=20,
                     help="max concurrent HTTP probes (default: 20)")
    prb.add_argument("--timeout", type=float, default=15.0,
                     help="per-request timeout in seconds (default: 15)")
    prb.add_argument("--no-redirect", dest="follow_redirects", action="store_false",
                     help="do not follow HTTP redirects")
    prb.add_argument("--proxy", help="HTTP(S) proxy URL")
    prb.add_argument("-H", "--header", action="append", default=[], metavar="K:V",
                     help="extra request header (repeatable)")
    prb.add_argument("--no-tls", dest="do_tls", action="store_false",
                     help="skip TLS inspection")
    prb.add_argument("--no-favicon", dest="do_favicon", action="store_false",
                     help="skip favicon hashing")

    shot = p.add_argument_group("screenshots")
    shot.add_argument("--no-screenshot", dest="screenshots", action="store_false",
                      help="disable Playwright screenshots")
    shot.add_argument("--full-page", action="store_true",
                      help="capture full-page screenshots")
    shot.add_argument("--screenshot-delay", type=int, default=0, metavar="MS",
                      help="wait N ms before shooting (default: 0)")
    shot.add_argument("--screenshot-timeout", type=int, default=20000, metavar="MS",
                      help="screenshot navigation timeout ms (default: 20000)")

    p.add_argument("--no-hostnames", dest="include_hostnames", action="store_false",
                   help="do not create endpoints for discovered hostnames")
    p.add_argument("--silent", action="store_true",
                   help="suppress info logging (errors still shown)")


def _add_nmap_opts(p: argparse.ArgumentParser) -> None:
    """nmap-specific options (only meaningful for ``scan``)."""
    g = p.add_argument_group("nmap")
    g.add_argument("--ports", default="web",
                   help="ports/alias to scan (default: web)")
    g.add_argument("--rate", type=int, default=5000,
                   help="nmap --min-rate (default: 5000)")
    g.add_argument("--timing", type=int, default=4,
                   help="nmap -T timing template (default: 4)")
    g.add_argument("-Pn", "--no-ping", dest="no_ping", action="store_true",
                   help="skip host discovery (nmap -Pn)")
    g.add_argument("--no-sv", dest="service_detection", action="store_false",
                   help="disable nmap service/version detection")
    g.add_argument("--fast", action="store_true",
                   help="fast mode: host discovery on, skip version detection, bump timing to -T5")
    g.add_argument("--direct", action="store_true",
                   help="skip nmap and probe the IP x port grid directly over HTTP; best for "
                        "SYN-proxy networks (e.g. Cisco Meraki) where every port looks open")
    g.add_argument("--sudo", action="store_true", help="run nmap with sudo")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snapmap",
        description=BANNER,
        epilog=EPILOG,
        formatter_class=ColorHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"snapmap {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="nmap-scan a target, then probe and report",
                          formatter_class=ColorHelpFormatter)
    scan.add_argument("target", metavar="TARGET",
                      help="target(s) for nmap (host/CIDR/range, space-separated ok)")
    _add_nmap_opts(scan)
    _add_common(scan)

    rep = sub.add_parser("report", help="ingest existing nmap/masscan XML, then probe and report",
                         formatter_class=ColorHelpFormatter)
    rep.add_argument("--nmap", metavar="FILE",
                     help="nmap/masscan XML file (default: read from stdin)")
    _add_common(rep)

    upd = sub.add_parser("update-creds", help="refresh the default-credentials database",
                         formatter_class=ColorHelpFormatter)
    upd.add_argument("--url", help=f"source URL (default: {creds.DEFAULT_CREDS_URL})")

    crd = sub.add_parser("creds", help="search the bundled default-credentials database",
                         formatter_class=ColorHelpFormatter)
    crd.add_argument("query", metavar="QUERY",
                     help="product/vendor keyword, e.g. 'hp', 'laserjet', 'grafana'")

    return parser


def options_from_args(args: argparse.Namespace) -> Options:
    """Populate an :class:`Options` from parsed CLI arguments."""
    opts = Options()

    # nmap (scan only; report leaves these at defaults)
    opts.ports = getattr(args, "ports", opts.ports)
    opts.rate = getattr(args, "rate", opts.rate)
    opts.timing = getattr(args, "timing", opts.timing)
    opts.no_ping = getattr(args, "no_ping", opts.no_ping)
    opts.service_detection = getattr(args, "service_detection", opts.service_detection)
    opts.sudo = getattr(args, "sudo", opts.sudo)
    if getattr(args, "fast", False):
        opts.service_detection = False
        opts.timing = max(opts.timing, 5)

    opts.include_hostnames = args.include_hostnames

    # probing
    opts.concurrency = args.concurrency
    opts.timeout = args.timeout
    opts.follow_redirects = args.follow_redirects
    opts.proxy = args.proxy
    opts.headers = parse_headers(args.header)
    opts.do_tls = args.do_tls
    opts.do_favicon = args.do_favicon

    # screenshots
    opts.screenshots = args.screenshots
    opts.full_page = args.full_page
    opts.screenshot_delay = args.screenshot_delay
    opts.screenshot_timeout = args.screenshot_timeout

    # report
    opts.project = getattr(args, "project", None)
    opts.report_all = getattr(args, "report_all", False)
    opts.group_by = args.group_by
    opts.output = args.output
    opts.json_out = args.json_out
    opts.csv_out = args.csv_out

    # SYN-proxy-friendly defaults for --direct (unless the user overrode them)
    if getattr(args, "direct", False):
        if args.timeout == 15.0:
            opts.timeout = 4.0
        if args.concurrency == 20:
            opts.concurrency = 100

    return opts


def apply_project(opts: Options, log) -> None:
    """If a project name is set, route every output into a folder named after it.

    The folder is completed with JSON + CSV exports by default so an engagement
    directory is self-contained and easy to review later.
    """
    if not opts.project:
        return
    folder = opts.project
    os.makedirs(folder, exist_ok=True)
    opts.output = os.path.join(folder, os.path.basename(opts.output) or "snapmap_report.html")
    opts.json_out = os.path.join(
        folder, os.path.basename(opts.json_out) if opts.json_out else "snapmap_results.json")
    opts.csv_out = os.path.join(
        folder, os.path.basename(opts.csv_out) if opts.csv_out else "snapmap_results.csv")
    log(f"project '{opts.project}': writing outputs to {folder}{os.sep}")


def parse_headers(raw: list[str]) -> dict[str, str]:
    """Parse repeated ``-H`` values of the form ``Key: value`` or ``Key:value``."""
    headers: dict[str, str] = {}
    for item in raw or []:
        if ":" not in item:
            continue
        key, _, value = item.partition(":")
        key = key.strip()
        if key:
            headers[key] = value.strip()
    return headers


# --------------------------------------------------------------------------- #
# shared reporting / summary
# --------------------------------------------------------------------------- #
def write_outputs(endpoints: list[Endpoint], opts: Options, meta: dict, log) -> None:
    alive = [ep for ep in endpoints if ep.alive]
    # The HTML report focuses on responsive endpoints; dead candidates are noise
    # (especially on SYN-proxy networks). JSON/CSV keep the full record.
    report_eps = endpoints if opts.report_all else alive
    report.write_html(report_eps, meta, opts.output)
    log(f"wrote HTML report ({len(report_eps)} endpoints) -> {opts.output}")
    if opts.json_out:
        report.write_json(endpoints, opts.json_out, meta)
        log(f"wrote JSON -> {opts.json_out}")
    if opts.csv_out:
        report.write_csv(endpoints, opts.csv_out)
        log(f"wrote CSV -> {opts.csv_out}")
    if opts.project:
        shots_dir = os.path.join(opts.project, "screenshots")
        n = report.save_screenshots(alive, shots_dir)
        if n:
            log(f"saved {n} screenshot(s) -> {shots_dir}{os.sep}")


def print_summary(endpoints: list[Endpoint], log) -> None:
    """Print counts and the top issues by severity to stderr."""
    alive = sum(1 for ep in endpoints if ep.alive)
    log(f"{len(endpoints)} endpoints, {alive} alive")

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for ep in endpoints:
        for iss in ep.issues:
            if iss.severity in counts:
                counts[iss.severity] += 1
    top = ", ".join(f"{sev}={counts[sev]}" for sev in SEVERITY_ORDER if counts[sev])
    log(f"issues: {top}" if top else "issues: none")


def make_meta(target: str, opts: Options, nmap_cmd: str,
              endpoints: list[Endpoint]) -> dict:
    return {
        "target": target,
        "project": opts.project or "",
        "ports": resolve_ports(opts.ports),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "tool_version": __version__,
        "nmap_cmd": nmap_cmd,
        "group_by": opts.group_by,
        "total": len(endpoints),
        "alive": sum(1 for ep in endpoints if ep.alive),
    }


# --------------------------------------------------------------------------- #
# subcommand handlers
# --------------------------------------------------------------------------- #
def cmd_scan(args: argparse.Namespace, log) -> int:
    opts = options_from_args(args)
    apply_project(opts, log)

    if getattr(args, "direct", False):
        endpoints = nmap_scan.expand_targets(args.target, opts.ports)
        log(f"direct HTTP sweep (no nmap): {len(endpoints)} candidate endpoint(s)")
        nmap_cmd = "direct HTTP sweep (no nmap)"
    else:
        if not nmap_scan.nmap_available():
            log("error: nmap not found on PATH; install nmap, use --direct, or the "
                "'report' subcommand with an existing XML", error=True)
            return 2
        out_base = os.path.join(opts.project, "nmap_scan") if opts.project else None
        try:
            xml = nmap_scan.run_nmap(
                args.target,
                opts.ports,
                rate=opts.rate,
                timing=opts.timing,
                no_ping=opts.no_ping,
                service_detection=opts.service_detection,
                extra_args=opts.nmap_extra,
                sudo=opts.sudo,
                out_base=out_base,
                log=log,
            )
        except nmap_scan.NmapNotFound:
            log("error: nmap not found on PATH", error=True)
            return 2
        except Exception as exc:  # RuntimeError on scan failure
            log(f"error: nmap failed: {exc}", error=True)
            return 1

        if out_base:
            try:
                with open(f"{out_base}.xml", "w", encoding="utf-8") as fh:
                    fh.write(xml)
                log(f"saved nmap output -> {out_base}.xml/.nmap/.gnmap")
            except OSError as exc:
                log(f"warning: could not save nmap XML: {exc}", error=True)

        hosts = nmap_scan.parse_nmap_xml(xml)
        endpoints = nmap_scan.build_endpoints(hosts, include_hostnames=opts.include_hostnames)
        log(f"{len(hosts)} host(s), {len(endpoints)} candidate endpoint(s)")
        nmap_cmd = f"nmap -p {opts.ports} {args.target}"

    asyncio.run(pipeline.process(endpoints, opts, log))
    meta = make_meta(args.target, opts, nmap_cmd, endpoints)
    write_outputs(endpoints, opts, meta, log)
    print_summary(endpoints, log)
    return 0


def cmd_report(args: argparse.Namespace, log) -> int:
    opts = options_from_args(args)
    apply_project(opts, log)
    if args.nmap:
        try:
            with open(args.nmap, "r", encoding="utf-8", errors="replace") as fh:
                xml = fh.read()
        except OSError as exc:
            log(f"error: cannot read {args.nmap}: {exc}", error=True)
            return 1
    else:
        log("reading XML from stdin ...")
        xml = sys.stdin.read()

    if not xml.strip():
        log("error: no XML input provided", error=True)
        return 1

    hosts = nmap_scan.parse_nmap_xml(xml)
    endpoints = nmap_scan.build_endpoints(hosts, include_hostnames=opts.include_hostnames)
    log(f"{len(hosts)} host(s), {len(endpoints)} candidate endpoint(s)")

    asyncio.run(pipeline.process(endpoints, opts, log))

    target = args.nmap or "<stdin>"
    meta = make_meta(target, opts, "", endpoints)
    write_outputs(endpoints, opts, meta, log)
    print_summary(endpoints, log)
    return 0


def cmd_update_creds(args: argparse.Namespace, log) -> int:
    try:
        added, total = creds.update_db(url=args.url)
    except Exception as exc:
        log(f"error: could not update creds database: {exc}", error=True)
        return 1
    log(f"updated creds database: {added} new entr(y/ies), {total} written")
    products, entries = creds.db_stats()
    log(f"creds database now: {products} product(s), {entries} credential(s)")
    return 0


def cmd_creds(args: argparse.Namespace, log) -> int:
    results = creds.search(args.query)
    if not results:
        log(f"no default credentials found for '{args.query}'", error=True)
        return 1
    n_products = len({c.product for c in results})
    print(f"{'PRODUCT':32} {'USERNAME':24} PASSWORD")
    print(f"{'-' * 32} {'-' * 24} {'-' * 12}")
    for c in results:
        print(f"{c.product[:31]:32} {(c.username or '<blank>')[:23]:24} {c.password or '<blank>'}")
    log(f"{len(results)} credential(s) across {n_products} product(s)")
    return 0


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    log = make_logger(getattr(args, "silent", False))

    if args.command == "scan":
        return cmd_scan(args, log)
    if args.command == "report":
        return cmd_report(args, log)
    if args.command == "update-creds":
        return cmd_update_creds(args, log)
    if args.command == "creds":
        return cmd_creds(args, log)

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
