"""Streamlit UI for first-pass IOC triage."""

from __future__ import annotations

import os
import streamlit as st
from dotenv import load_dotenv

from core.abuseipdb import AbuseIPDBClient
from core.cache import IocCache
from core.classifier import (
    TriageResult,
    Verdict,
    format_abuse_cell,
    format_vt_cell,
)
from reports.report_generator import generate_markdown
from triage import (
    DEFAULT_BATCH_CAP,
    MAX_BATCH_CAP,
    VT_MIN_INTERVAL_SECONDS,
    count_uncached,
    parse_ioc_lines,
    triage_one,
)
from core.virustotal import VirusTotalClient

_VERDICT_COLORS = {
    Verdict.CLEAN: "#16a34a",
    Verdict.SUSPICIOUS: "#ca8a04",
    Verdict.MALICIOUS: "#dc2626",
    Verdict.UNKNOWN: "#6b7280",
}


def _clients() -> tuple[VirusTotalClient, AbuseIPDBClient]:
    """Build API clients from environment variables.

    Returns:
        VirusTotal and AbuseIPDB clients (possibly disabled).
    """
    load_dotenv()
    vt = VirusTotalClient(os.getenv("VT_API_KEY"))
    abuse = AbuseIPDBClient(os.getenv("ABUSEIPDB_API_KEY"))
    return vt, abuse


def _badge(verdict: Verdict) -> str:
    """Return an HTML span for a verdict.

    Args:
        verdict: Classification verdict.

    Returns:
        HTML snippet.
    """
    color = _VERDICT_COLORS[verdict]
    return (
        f'<span style="color:{color};font-weight:700">{verdict.value}</span>'
    )


def main() -> None:
    """Render the Streamlit IOC triage page."""
    st.set_page_config(page_title="IOC Triage Tool", layout="wide")
    st.title("IOC Triage Tool")
    st.caption(
        "First-pass SOC/CSIRT lookup: VirusTotal + AbuseIPDB. "
        "Final verdict is the worse of the two sources."
    )

    if "results" not in st.session_state:
        st.session_state.results = []

    vt_client, abuse_client = _clients()
    if not vt_client.enabled:
        st.warning("VT_API_KEY missing — skipping VirusTotal.")
    if not abuse_client.enabled:
        st.warning("ABUSEIPDB_API_KEY missing — skipping AbuseIPDB.")

    cap = st.sidebar.number_input(
        "Batch cap",
        min_value=1,
        max_value=MAX_BATCH_CAP,
        value=DEFAULT_BATCH_CAP,
        help="Maximum IOCs per run. Protects the free VirusTotal quota.",
    )

    pasted = st.text_area(
        "IOCs (one per line)",
        height=180,
        placeholder="8.8.8.8\nexample.com\nhttps://example.com/login",
    )
    uploaded = st.file_uploader("Or upload a text file", type=["txt", "csv", "log"])

    text = pasted
    if uploaded is not None:
        text = uploaded.getvalue().decode("utf-8", errors="replace")

    iocs = parse_ioc_lines(text)
    cache = IocCache()
    uncached = count_uncached(iocs, cache) if iocs else 0
    estimate_s = uncached * VT_MIN_INTERVAL_SECONDS

    if iocs:
        st.info(
            f"{len(iocs)} IOC(s) parsed, {uncached} not in cache. "
            f"Estimated VirusTotal wait: ~{estimate_s:.0f}s "
            f"({uncached} × {VT_MIN_INTERVAL_SECONDS:.0f}s)."
        )

    run = st.button("Run triage", type="primary", disabled=not iocs)

    if run:
        batch = iocs
        if len(batch) > cap:
            st.warning(
                f"Batch truncated from {len(batch)} to {cap} IOCs "
                f"(raise the cap in the sidebar, max {MAX_BATCH_CAP})."
            )
            batch = batch[: int(cap)]
        results: list[TriageResult] = []
        last_vt = [0.0]
        progress = st.progress(0.0, text="Looking up IOCs…")
        for index, raw in enumerate(batch):
            results.append(
                triage_one(raw, cache, vt_client, abuse_client, last_vt)
            )
            progress.progress(
                (index + 1) / len(batch),
                text=f"Looked up {index + 1}/{len(batch)}",
            )
        st.session_state.results = results
        progress.empty()

    results = st.session_state.results
    if not results:
        return

    rows = []
    for row in results:
        rows.append(
            {
                "IOC": row.ioc,
                "Type": row.ioc_type.value,
                "Verdict": row.verdict.value,
                "VirusTotal": format_vt_cell(row),
                "AbuseIPDB": format_abuse_cell(row),
                "Country": row.country or "—",
                "Notes": row.error or ("cache" if row.from_cache else "—"),
            }
        )
    st.subheader("Results")
    st.dataframe(rows, use_container_width=True, hide_index=True)

    for row in results:
        with st.expander(f"{row.ioc} — {row.verdict.value}"):
            st.markdown(_badge(row.verdict), unsafe_allow_html=True)
            st.write(
                {
                    "type": row.ioc_type.value,
                    "virustotal": format_vt_cell(row),
                    "abuseipdb": format_abuse_cell(row),
                    "country": row.country,
                    "related": row.related,
                    "vt_link": row.vt_link,
                    "from_cache": row.from_cache,
                    "note": row.error,
                }
            )

    st.download_button(
        "Download Markdown report",
        data=generate_markdown(results),
        file_name="ioc_triage_report.md",
        mime="text/markdown",
    )


if __name__ == "__main__":
    main()
