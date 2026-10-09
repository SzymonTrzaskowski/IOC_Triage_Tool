# IOC Triage Tool

SOC and CSIRT analysts usually paste indicators of compromise into VirusTotal, AbuseIPDB, and similar sites at the start of an incident. This tool automates that **first triage step**: it detects the IOC type, queries public threat-intel APIs, classifies each source separately, and produces a terminal table plus a Markdown report ready to paste into a ticket.

## Stack

- Python 3.10+
- [httpx](https://www.python-httpx.org/) — HTTP for VirusTotal v3 and AbuseIPDB
- [python-dotenv](https://github.com/theskumar/python-dotenv) — API keys from `.env`
- [rich](https://github.com/Textualize/rich) — color table in the terminal
- [streamlit](https://streamlit.io/) — local web UI
- [pytest](https://pytest.org/) — tests with mocked HTTP (no live API calls)

## Install

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
# source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # Windows
# cp .env.example .env   # macOS / Linux
```

Put keys in `.env` (do not commit that file).

## Free API keys

1. **VirusTotal** — [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)  
   Free tier: **4 requests per minute**. The tool waits ~16s between real VT calls (cache hits do not count).
2. **AbuseIPDB** — [https://www.abuseipdb.com/api](https://www.abuseipdb.com/api)

A missing key skips that integration with a warning instead of crashing.

## CLI

```bash
python triage.py --ioc 8.8.8.8
python triage.py --file examples/sample_iocs.txt --export-md ticket.md
```

A small ready-made list lives in [`examples/sample_iocs.txt`](examples/sample_iocs.txt): two public DNS IPs, `example.com`, its URL, and the EICAR test hash (usually **Malicious** on VirusTotal). Use that file in the CLI or upload it in the web UI.

## Web UI

On Windows, double-click [`start_ui.bat`](start_ui.bat). It uses the project `.venv` and opens http://localhost:8501. Closing that console window stops the server. Optional: right-click the `.bat` → **Send to → Desktop (create shortcut)**.

Or from a terminal:

```bash
streamlit run ui_app.py
```

Paste IOCs or upload a file (try `examples/sample_iocs.txt`). Results stay in session state so downloading Markdown does not clear the table. Before a run, the UI estimates wait time (`uncached IOCs × 16s`) and caps the batch (default 20, max 50). The first uncached run of the sample file can take about a minute because of the VirusTotal rate limit.

## Verdicts

VirusTotal and AbuseIPDB are **separate columns**. The final verdict is the **worse** of the two (not a summed engine count).

**VirusTotal** (malicious + suspicious engines), only when a report exists:

- **Clean** — 0 engines
- **Suspicious** — 1–3 engines
- **Malicious** — 4+ engines
- **Unknown** — HTTP 404 / never scanned (this is not Clean)

**AbuseIPDB** (IP only, when a score exists):

- **Clean** — 0–24
- **Suspicious** — 25–74
- **Malicious** — 75–100

Severity order: Malicious > Suspicious > Unknown > Clean. Example: VT Clean `0/70` + AbuseIPDB `88%` → final **Malicious**.

URLs are canonicalized before cache and before the VirusTotal URL id (`https://X.pl`, `https://x.pl/`, and `https://x.pl:443/` are the same IOC).

Results are cached in `.cache/ioc_cache.json` for **24 hours**.

```bash
pytest
```

## How it works

```
start_ui.bat / streamlit  →  ui_app.py
python triage.py          →  CLI
                          →  detect_type (regex)
                          →  JSON cache (24h)
                          →  VirusTotal v3  (+ AbuseIPDB for IPs)
                          →  per-source verdicts  →  worse-of  →  table / Markdown
```

- [`start_ui.bat`](start_ui.bat) — double-click launcher for the local web UI
- [`ui_app.py`](ui_app.py) — Streamlit UI
- [`triage.py`](triage.py) — CLI entry point
- [`examples/sample_iocs.txt`](examples/sample_iocs.txt) — small sample list for a first run
- [`core/classifier.py`](core/classifier.py) — IOC type, URL normalization, VT/AbuseIPDB verdicts
- [`core/virustotal.py`](core/virustotal.py) / [`core/abuseipdb.py`](core/abuseipdb.py) — API clients; network errors do not abort the batch
- [`core/cache.py`](core/cache.py) — JSON cache to protect the free API quota
- [`reports/report_generator.py`](reports/report_generator.py) — ticket-ready Markdown
