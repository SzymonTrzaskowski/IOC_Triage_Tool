"""Unit tests for Markdown report generation."""

from __future__ import annotations

from pathlib import Path

from core.classifier import IocType, TriageResult, Verdict, VT_NOT_FOUND_NOTE
from reports.report_generator import generate_markdown, write_report


def _sample_row() -> TriageResult:
    """Return a malicious IP result used across assertions."""
    return TriageResult(
        ioc="203.0.113.10",
        ioc_type=IocType.IP,
        verdict=Verdict.MALICIOUS,
        vt_verdict=Verdict.MALICIOUS,
        abuse_verdict=Verdict.MALICIOUS,
        detection_count=5,
        vt_malicious=5,
        vt_suspicious=0,
        vt_total=70,
        abuse_score=88,
        country="NL",
        related=["c2.example.net"],
        vt_link="https://www.virustotal.com/gui/ip-address/203.0.113.10",
    )


def test_markdown_contains_verdict_counts_and_link() -> None:
    """Report includes IOC, verdict, engine ratio, country, related, VT URL."""
    md = generate_markdown([_sample_row()])
    assert "`203.0.113.10`" in md
    assert "**Malicious**" in md
    assert "5/70" in md
    assert "NL" in md
    assert "c2.example.net" in md
    assert "https://www.virustotal.com/gui/ip-address/203.0.113.10" in md
    assert "Malicious 88%" in md


def test_markdown_includes_unknown_verdict() -> None:
    """Unknown is written into the Markdown report, not Clean."""
    row = TriageResult(
        ioc="https://x.pl/",
        ioc_type=IocType.URL,
        verdict=Verdict.UNKNOWN,
        error=VT_NOT_FOUND_NOTE,
    )
    md = generate_markdown([row])
    assert "**Unknown**" in md
    assert VT_NOT_FOUND_NOTE in md


def test_write_report(tmp_path: Path) -> None:
    """write_report persists UTF-8 markdown to the given path."""
    dest = tmp_path / "report.md"
    write_report([_sample_row()], dest)
    text = dest.read_text(encoding="utf-8")
    assert text.startswith("# IOC Triage Report")
    assert "IOC Triage Report" in text
