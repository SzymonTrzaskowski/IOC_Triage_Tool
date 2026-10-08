"""Markdown report generation for ticket-ready IOC triage output."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.classifier import TriageResult, Verdict


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
        "| IOC | Type | Verdict | VT detections | Country | Related | VirusTotal |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in results:
        related = ", ".join(row.related) if row.related else "—"
        country = row.country or "—"
        vt_cell = (
            f"{row.vt_malicious + row.vt_suspicious}/{row.vt_total} malicious"
            if row.vt_total
            else "—"
        )
        link = f"[report]({row.vt_link})" if row.vt_link else "—"
        ioc_md = f"`{row.ioc}`"
        lines.append(
            f"| {ioc_md} | {row.ioc_type.value} | **{row.verdict.value}** | "
            f"{vt_cell} | {country} | {related} | {link} |"
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
    vt_raw = (
        f"{row.vt_malicious + row.vt_suspicious}/{row.vt_total} silników VT "
        "oznaczyło jako malicious/suspicious"
        if row.vt_total
        else "brak danych VirusTotal"
    )
    abuse = (
        f"{row.abuse_score}"
        if row.abuse_score is not None
        else "n/d"
    )
    related = ", ".join(f"`{item}`" for item in row.related) if row.related else "brak"
    error = f"\n- Błąd: {row.error}" if row.error else ""
    cache = "tak" if row.from_cache else "nie"
    return [
        f"### `{row.ioc}`",
        "",
        f"- Typ: `{row.ioc_type.value}`",
        f"- Werdykt: **{row.verdict.value}** (łącznie {row.detection_count} silników)",
        f"- Wykrycia: {vt_raw}",
        f"- AbuseIPDB confidence: {abuse}",
        f"- Kraj: {row.country or 'n/d'}",
        f"- Powiązane domeny/hashe: {related}",
        f"- Link VirusTotal: {row.vt_link or 'n/d'}",
        f"- Z cache (24h): {cache}{error}",
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
        Verdict.UNKNOWN: "bold bright_black",
    }
    return mapping[verdict]
