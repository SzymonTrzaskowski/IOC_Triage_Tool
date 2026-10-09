"""Markdown report generation for ticket-ready IOC triage output."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.classifier import (
    TriageResult,
    Verdict,
    format_abuse_cell,
    format_vt_cell,
)


def generate_markdown(results: list[TriageResult]) -> str:
    """Build a Markdown report from triage results.

    Args:
        results: Completed triage rows.

    Returns:
        Markdown document ready to paste into a ticket.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        "# IOC Triage Report",
        "",
        f"Generated: {generated}",
        "",
        "| IOC | Type | Verdict | VirusTotal | AbuseIPDB | Country | Related | VT link |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in results:
        related = ", ".join(row.related) if row.related else "—"
        country = row.country or "—"
        link = f"[report]({row.vt_link})" if row.vt_link else "—"
        ioc_md = f"`{row.ioc}`"
        lines.append(
            f"| {ioc_md} | {row.ioc_type.value} | **{row.verdict.value}** | "
            f"{format_vt_cell(row)} | {format_abuse_cell(row)} | {country} | "
            f"{related} | {link} |"
        )
    lines.extend(["", "## Details", ""])
    for row in results:
        lines.extend(_detail_section(row))
    return "\n".join(lines) + "\n"


def write_report(results: list[TriageResult], path: Path) -> None:
    """Write a Markdown report to ``path``.

    Args:
        results: Completed triage rows.
        path: Destination file.
    """
    path.write_text(generate_markdown(results), encoding="utf-8")


def _detail_section(row: TriageResult) -> list[str]:
    """Render a per-IOC detail block.

    Args:
        row: Single triage result.

    Returns:
        Markdown lines for this IOC.
    """
    vt_raw = format_vt_cell(row)
    if row.vt_total:
        hits = row.vt_malicious + row.vt_suspicious
        vt_raw = (
            f"{row.vt_verdict.value if row.vt_verdict else '—'} — "
            f"{hits}/{row.vt_total} VirusTotal engines flagged malicious/suspicious"
        )
    abuse = format_abuse_cell(row)
    related = (
        ", ".join(f"`{item}`" for item in row.related) if row.related else "none"
    )
    error = f"\n- Note: {row.error}" if row.error else ""
    cache = "yes" if row.from_cache else "no"
    return [
        f"### `{row.ioc}`",
        "",
        f"- Type: `{row.ioc_type.value}`",
        f"- Final verdict: **{row.verdict.value}** (worse of VirusTotal and AbuseIPDB)",
        f"- VirusTotal: {vt_raw}",
        f"- AbuseIPDB: {abuse}",
        f"- Country: {row.country or 'n/a'}",
        f"- Related domains/hashes: {related}",
        f"- VirusTotal link: {row.vt_link or 'n/a'}",
        f"- From 24h cache: {cache}{error}",
        "",
    ]


def verdict_style(verdict: Verdict) -> str:
    """Return a rich markup style name for a verdict.

    Args:
        verdict: Classification verdict.

    Returns:
        Rich style string.
    """
    mapping = {
        Verdict.CLEAN: "bold green",
        Verdict.SUSPICIOUS: "bold yellow",
        Verdict.MALICIOUS: "bold red",
        Verdict.UNKNOWN: "bold grey50",
    }
    return mapping[verdict]
