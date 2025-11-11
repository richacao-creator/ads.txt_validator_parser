# ads.txt Validator Parser

`ads.txt_validator_parser` bundles two complementary tools:

- `ads_txt_checker.py` — command-line validator that fetches a publisher's
  `ads.txt`, reports formatting issues, highlights invalid authority IDs, and can
  emit a CSV snapshot of the parsed data.
- `ads_dashboard.py` — lightweight HTTP dashboard that surfaces the same
  dataset in a browser table and exposes an on-demand CSV download link.

## Requirements

Everything runs on the Python standard library. Python 3.9+ is recommended
because the implementation uses modern typing helpers introduced in 3.9.

## CLI Usage

Run the checker by passing a domain name:

```
python3 ads_txt_checker.py example.com
```

The tool attempts to download `https://example.com/ads.txt` first and falls back
to HTTP if HTTPS fails. Use `--http-only` to skip the HTTPS attempt, and adjust
`--timeout` (seconds) if needed.

To produce a CSV report of the parsed data, supply `--csv-output`:

```
python3 ads_txt_checker.py cnn.com --csv-output cnn_ads.csv
```

The report contains the line number, normalized exchange domain, publisher ID,
relationship, optional authority ID, any duplicate reference, and aggregated
error messages for each ads.txt line that parsed or produced validation errors.

Exit codes:

- `0`: No issues detected
- `1`: Network/retrieval failure or CSV write error
- `2`: Parsed successfully but validation issues were found

Example output:

```
ads.txt URL: https://example.com/ads.txt
Valid records: 24
Errors:
  - L12: relationship 'DIRECTT' is invalid (expected one of ['DIRECT', 'RESELLER'])
Duplicate entries:
  - L48 duplicates L15: google.com, pub-123456, DIRECT
CSV report written to example_ads.csv
```

## Dashboard Usage

Start the dashboard server:

```
python3 ads_dashboard.py --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/` in your browser, enter a domain, and submit. The
page renders the parsed rows directly in a grid and provides a CSV download link
based on the latest results. Use `Ctrl+C` in the terminal to stop the server.
Add `--verbose` if you want HTTP request logging in the console.
