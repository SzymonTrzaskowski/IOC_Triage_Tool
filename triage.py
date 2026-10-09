#!/usr/bin/env python3
"""IOC Triage Tool — CLI entry point for SOC/CSIRT first-pass IOC lookups."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from core.abuseipdb import AbuseIPDBClient
from core.cache import IocCache
from core.classifier import (
    IocType,
    TriageResult,
    Verdict,
    VT_NOT_FOUND_NOTE,
    classify_abuseipdb,
    classify_virustotal,
    combine_verdicts,
    detect_type,
    format_abuse_cell,
    format_vt_cell,
    normalize_ioc,
)
from core.virustotal import VirusTotalClient
from reports.report_generator import verdict_style, write_report

VT_MIN_INTERVAL_SECONDS = 16.0
DEFAULT_BATCH_CAP = 20
MAX_BATCH_CAP = 50
console = Console()


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Parsed namespace.
    """
    parser = argparse.ArgumentParser(
        description="IOC Triage Tool — first-pass reputation lookup "
        "(VirusTotal + AbuseIPDB).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ioc", help="Single indicator (IP, domain, hash, or URL).")
    group.add_argument(
        "--file",
        dest="file_path",
        help="Text file with one IOC per line.",
    )
    parser.add_argument(
        "--export-md",
        dest="export_md",
        help="Write a Markdown report to this path.",
    )
    return parser.parse_args(argv)


def load_iocs(args: argparse.Namespace) -> list[str]:
    """Collect IOC strings from --ioc or --file.

    Args:
        args: Parsed CLI arguments.

    Returns:
        List of non-empty, non-comment lines.
    """
    if args.ioc:
        return [args.ioc]
    path = Path(args.file_path)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        sys.exit(1)
    return parse_ioc_lines(path.read_text(encoding="utf-8"))


def parse_ioc_lines(text: str) -> list[str]:
    """Parse one-IOC-per-line text, ignoring blanks and comments.

    Args:
        text: Raw textarea or file contents.

    Returns:
        IOC strings in file order.
    """
    iocs: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        iocs.append(stripped)
    return iocs


def count_uncached(raw_iocs: list[str], cache: IocCache) -> int:
    """Count IOCs that would miss the 24h cache.

    Args:
        raw_iocs: Raw IOC strings.
        cache: Local cache.

    Returns:
        Number of cache misses (including unrecognized types, which skip VT).
    """
    misses = 0
    for raw in raw_iocs:
        ioc_type = detect_type(raw)
        if ioc_type == IocType.UNKNOWN:
            continue
        ioc = normalize_ioc(raw, ioc_type)
        if cache.get(ioc_type, ioc) is None:
            misses += 1
    return misses


def payload_to_result(
    ioc: str,
    ioc_type: IocType,
    payload: dict,
    from_cache: bool = False,
) -> TriageResult:
    """Convert a cached or live payload dict into ``TriageResult``.

    Args:
        ioc: Normalized IOC.
        ioc_type: Detected type.
        payload: Combined lookup payload.
        from_cache: Whether the payload came from cache.

    Returns:
        Fully classified triage result.
    """
    vt_malicious = int(payload.get("vt_malicious") or 0)
    vt_suspicious = int(payload.get("vt_suspicious") or 0)
    vt_total = int(payload.get("vt_total") or 0)
    abuse_score = payload.get("abuse_score")
    if abuse_score is not None:
        abuse_score = int(abuse_score)
    error_text = str(payload.get("error") or "")
    vt_not_found = bool(payload.get("vt_not_found")) or (
        "not found" in error_text.lower()
    )
    has_vt_report = bool(payload.get("vt_report")) or (
        int(payload.get("vt_total") or 0) > 0 and not vt_not_found
    )
    if vt_not_found:
        vt_verdict: Optional[Verdict] = Verdict.UNKNOWN
    elif has_vt_report:
        vt_verdict = classify_virustotal(
            vt_malicious,
            vt_suspicious,
            has_report=True,
        )
    else:
        vt_verdict = None
    abuse_verdict = classify_abuseipdb(abuse_score)
    note = payload.get("error")
    if vt_not_found and abuse_verdict is None:
        note = VT_NOT_FOUND_NOTE
    vt_hits = vt_malicious + vt_suspicious
    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=combine_verdicts(vt_verdict, abuse_verdict),
        vt_verdict=vt_verdict,
        abuse_verdict=abuse_verdict,
        detection_count=vt_hits,
        vt_malicious=vt_malicious,
        vt_suspicious=vt_suspicious,
        vt_total=vt_total,
        abuse_score=abuse_score,
        country=payload.get("country"),
        related=list(payload.get("related") or []),
        vt_link=payload.get("vt_link"),
        error=note,
        from_cache=from_cache,
    )


def merge_lookups(
    vt: Optional[dict],
    abuse: Optional[dict],
) -> dict:
    """Merge VirusTotal and AbuseIPDB payloads.

    Args:
        vt: VT lookup dict or None.
        abuse: AbuseIPDB lookup dict or None.

    Returns:
        Combined payload suitable for cache and ``TriageResult``.
    """
    combined: dict = {
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_total": 0,
        "related": [],
        "vt_report": False,
        "vt_not_found": False,
    }
    errors: list[str] = []
    if vt:
        if vt.get("error"):
            message = str(vt["error"])
            if "not found" in message.lower():
                combined["vt_not_found"] = True
            else:
                errors.append(message)
        else:
            combined["vt_report"] = True
            combined["vt_malicious"] = int(vt.get("vt_malicious") or 0)
            combined["vt_suspicious"] = int(vt.get("vt_suspicious") or 0)
            combined["vt_total"] = int(vt.get("vt_total") or 0)
            combined["vt_link"] = vt.get("vt_link")
            if vt.get("country"):
                combined["country"] = vt.get("country")
            combined["related"].extend(vt.get("related") or [])
    if abuse:
        if abuse.get("error"):
            errors.append(str(abuse["error"]))
        else:
            combined["abuse_score"] = abuse.get("abuse_score")
            if abuse.get("country") and not combined.get("country"):
                combined["country"] = abuse.get("country")
            combined["related"].extend(abuse.get("related") or [])
    # unique related
    seen: set[str] = set()
    unique: list[str] = []
    for item in combined["related"]:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    combined["related"] = unique[:8]
    if errors:
        combined["error"] = "; ".join(errors)
    return combined


def triage_one(
    raw: str,
    cache: IocCache,
    vt_client: VirusTotalClient,
    abuse_client: AbuseIPDBClient,
    last_vt_request: list[float],
) -> TriageResult:
    """Triage a single IOC with cache, APIs, and VT rate limiting.

    Args:
        raw: Raw IOC string.
        cache: Local 24h cache.
        vt_client: VirusTotal client.
        abuse_client: AbuseIPDB client.
        last_vt_request: Mutable one-element list holding last VT request time.

    Returns:
        Classified ``TriageResult``.
    """
    ioc_type = detect_type(raw)
    if ioc_type == IocType.UNKNOWN:
        return TriageResult(
            ioc=raw.strip(),
            ioc_type=IocType.UNKNOWN,
            verdict=Verdict.UNKNOWN,
            error="Unrecognized IOC type",
        )
    ioc = normalize_ioc(raw, ioc_type)
    cached = cache.get(ioc_type, ioc)
    if cached is not None:
        return payload_to_result(ioc, ioc_type, cached, from_cache=True)

    if vt_client.enabled:
        _throttle_vt(last_vt_request)
        vt_payload = vt_client.lookup(ioc_type, ioc)
        last_vt_request[0] = time.monotonic()
    else:
        vt_payload = None

    abuse_payload = None
    if ioc_type == IocType.IP and abuse_client.enabled:
        abuse_payload = abuse_client.lookup(ioc)

    combined = merge_lookups(vt_payload, abuse_payload)
    cache.set(ioc_type, ioc, combined)
    return payload_to_result(ioc, ioc_type, combined, from_cache=False)


def _throttle_vt(last_vt_request: list[float]) -> None:
    """Sleep so VirusTotal stays within 4 requests per minute.

    Args:
        last_vt_request: Mutable timestamp of the last real VT HTTP call.
    """
    last = last_vt_request[0]
    if last <= 0:
        return
    elapsed = time.monotonic() - last
    remaining = VT_MIN_INTERVAL_SECONDS - elapsed
    if remaining > 0:
        console.print(
            f"[dim]Rate limit: waiting {remaining:.1f}s before next "
            "VirusTotal request...[/dim]"
        )
        time.sleep(remaining)


def render_table(results: list[TriageResult]) -> None:
    """Print a colored Rich table of triage results.

    Args:
        results: Completed rows.
    """
    table = Table(title="IOC Triage Tool", show_lines=True)
    table.add_column("IOC", overflow="fold")
    table.add_column("Type")
    table.add_column("Verdict")
    table.add_column("VirusTotal")
    table.add_column("AbuseIPDB")
    table.add_column("Country")
    table.add_column("Notes", overflow="fold")
    for row in results:
        notes: list[str] = []
        if row.from_cache:
            notes.append("cache")
        if row.error:
            notes.append(row.error)
        table.add_row(
            row.ioc,
            row.ioc_type.value,
            f"[{verdict_style(row.verdict)}]{row.verdict.value}[/]",
            format_vt_cell(row),
            format_abuse_cell(row),
            row.country or "—",
            ", ".join(notes) if notes else "—",
        )
    console.print(table)


def main(argv: Optional[list[str]] = None) -> int:
    """Run the CLI.

    Args:
        argv: Optional argument list.

    Returns:
        Process exit code.
    """
    load_dotenv()
    args = parse_args(argv)
    iocs = load_iocs(args)
    if not iocs:
        console.print("[yellow]No IOCs to process.[/yellow]")
        return 0

    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    vt_client = VirusTotalClient(vt_key)
    abuse_client = AbuseIPDBClient(abuse_key)
    if not vt_client.enabled:
        console.print(
            "[yellow]Warning:[/yellow] VT_API_KEY missing — skipping VirusTotal."
        )
    if not abuse_client.enabled:
        console.print(
            "[yellow]Warning:[/yellow] ABUSEIPDB_API_KEY missing — "
            "skipping AbuseIPDB."
        )

    cache = IocCache()
    last_vt_request = [0.0]
    results: list[TriageResult] = []
    for raw in iocs:
        results.append(
            triage_one(raw, cache, vt_client, abuse_client, last_vt_request)
        )

    render_table(results)
    if args.export_md:
        dest = Path(args.export_md)
        write_report(results, dest)
        console.print(f"[green]Markdown report written to[/green] {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
