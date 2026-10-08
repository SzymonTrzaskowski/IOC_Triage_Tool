# IOC Triage Tool

Analitycy SOC i CSIRT na starcie incydentu ręcznie wklejają wskaźniki kompromitacji (IOC) do VirusTotal, AbuseIPDB i podobnych serwisów. To narzędzie CLI automatyzuje **pierwszy krok triage’u**: rozpoznaje typ IOC, odpytuje publiczne API threat intelligence, klasyfikuje wynik (Clean / Suspicious / Malicious) i generuje tabelę plus raport Markdown gotowy do wklejenia w ticket.

## Stack

- Python 3.10+
- [httpx](https://www.python-httpx.org/) — HTTP do VirusTotal v3 i AbuseIPDB
- [python-dotenv](https://github.com/theskumar/python-dotenv) — klucze z `.env`
- [rich](https://github.com/Textualize/rich) — kolorowa tabela w terminalu
- [pytest](https://pytest.org/) — testy z zamockowanym HTTP

## Instalacja

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

Uzupełnij klucze w `.env` (nie commituj tego pliku).

## Darmowe klucze API

1. **VirusTotal** — konto i klucz: [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)  
   Darmowy tier: **4 zapytania na minutę**. Narzędzie wstawia ~16 s przerwy między rzeczywistymi requestami VT (trafienia z cache nie liczą się do limitu).
2. **AbuseIPDB** — rejestracja i klucz: [https://www.abuseipdb.com/api](https://www.abuseipdb.com/api)

Brak klucza nie wywala programu: dana integracja jest pomijana z ostrzeżeniem.

## Przykłady użycia

Pojedynczy IOC:

```bash
python triage.py --ioc 8.8.8.8
```

Lista z pliku i eksport raportu:

```bash
python triage.py --file iocs.txt --export-md ticket.md
```

Przykładowy `iocs.txt`:

```
# jeden IOC na linię
8.8.8.8
example.com
https://example.com/login
d41d8cd98f00b204e9800998ecf8427e
```

Przykładowy output terminala:

```
                          IOC Triage Tool
┏━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ IOC        ┃ Type   ┃ Verdict    ┃ VT detections              ┃ Country ┃ Notes        ┃
┡━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ 8.8.8.8    │ ip     │ Clean      │ 0/70 silników VT oznaczyło │ US      │ AbuseIPDB 0% │
│            │        │            │ jako malicious             │         │              │
└────────────┴────────┴────────────┴────────────────────────────┴─────────┴──────────────┘
```

Werdykt:

- **Clean** — jest raport (np. z VirusTotal) i 0 silników oznacza IOC
- **Suspicious** — 1–3 silniki (VT `malicious` + `suspicious`; AbuseIPDB +1 przy score ≥ 25)
- **Malicious** — 4+ silników
- **Unknown** — VirusTotal zwraca 404 (IOC nigdy nie był skanowany) i nie ma innego źródła z danymi; to **nie** jest Clean

URL-e są kanonizowane przed cache i przed ID VirusTotal (`https://X.pl`, `https://x.pl/` i `https://x.pl:443/` to ten sam IOC).

Wyniki są cache’owane lokalnie w `.cache/ioc_cache.json` przez **24 godziny**.

Testy (bez prawdziwego HTTP):

```bash
pytest
```

## Jak to działa

```
triage.py  →  detect_type (regex)
           →  cache JSON (24h)
           →  VirusTotal v3  (+ AbuseIPDB dla IP)
           →  classify  →  tabela rich  →  opcjonalny Markdown
```

- [`core/classifier.py`](core/classifier.py) — typ IOC (URL → IP → hash MD5/SHA1/SHA256 → domena) i progi werdyktu
- [`core/virustotal.py`](core/virustotal.py) / [`core/abuseipdb.py`](core/abuseipdb.py) — klienci API, timeouty i błędy sieci bez crasha całego przebiegu
- [`core/cache.py`](core/cache.py) — persystencja JSON, żeby nie spalać darmowego limitu przy powtórnym sprawdzeniu
- [`reports/report_generator.py`](reports/report_generator.py) — raport: IOC, typ, werdykt, liczby silników, kraj, powiązane wskaźniki, link do GUI VirusTotal
