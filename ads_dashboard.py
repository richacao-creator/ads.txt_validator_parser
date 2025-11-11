#!/usr/bin/env python3
"""ads_dashboard.py

Lightweight HTTP server that exposes a dashboard for inspecting ads.txt data.
The dashboard lets users submit a publisher domain, view parsed rows, validation
errors, and download the structured data as a CSV file.
"""

from __future__ import annotations

import argparse
import html
import http.server
import io
import sys
import threading
import urllib.parse
from typing import Optional

from ads_txt_checker import (
    AdsTxtReport,
    fetch_ads_txt,
    format_report,
    parse_ads_txt,
    report_to_csv,
)

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>ads.txt Dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    form {{ margin-bottom: 1rem; }}
    input[type=text] {{ padding: 0.5rem; width: 300px; }}
    button {{ padding: 0.5rem 1rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4rem; font-size: 0.85rem; }}
    th {{ background: #f5f5f5; }}
    .errors {{ color: #c0392b; }}
    .download-row th {{ text-align: left; }}
  </style>
</head>
<body>
  <form method=\"get\" action=\"/\">
    <label for=\"domain\">Publisher domain:</label>
    <input id=\"domain\" name=\"domain\" type=\"text\" value=\"{domain}\" placeholder=\"example.com\" required />
    <button type=\"submit\">Inspect</button>
  </form>
  {content}
</body>
</html>
"""

TABLE_TEMPLATE = """<table>
  <thead>
    <tr class=\"download-row\">
      <th colspan=\"7\"><a href=\"/download?domain={domain_encoded}\">Download CSV</a></th>
    </tr>
    <tr>
      <th>Line</th>
      <th>Exchange Domain</th>
      <th>Publisher ID</th>
      <th>Relationship</th>
      <th>Authority ID</th>
      <th>Duplicate of Line</th>
      <th>Errors</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
"""

ROW_TEMPLATE = """<tr>
  <td>{line}</td>
  <td>{exchange}</td>
  <td>{publisher}</td>
  <td>{relationship}</td>
  <td>{authority}</td>
  <td>{duplicate}</td>
  <td class=\"errors\">{errors}</td>
</tr>
"""

ERROR_TEMPLATE = """<div class="errors"><strong>{message}</strong></div>"""

# Simple in-memory cache to avoid re-fetching during a session.
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, tuple[str, AdsTxtReport]] = {}


class AdsDashboardHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AdsDashboard/1.0"

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.handle_dashboard(parsed)
        elif parsed.path == "/download":
            self.handle_download(parsed)
        else:
            self.send_error(404, "Not Found")

    def handle_dashboard(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        domain = query.get("domain", [""])[0].strip()

        if not domain:
            content = ""
            self._respond_html(DASHBOARD_TEMPLATE.format(domain="", content=content))
            return

        try:
            url, report = self._get_report(domain)
            table_html = self._render_table(domain, url, report)
            body = DASHBOARD_TEMPLATE.format(domain=html.escape(domain), content=table_html)
        except Exception as exc:  # pragma: no cover - defensive fallback
            error_html = ERROR_TEMPLATE.format(message=html.escape(str(exc)))
            body = DASHBOARD_TEMPLATE.format(domain=html.escape(domain), content=error_html)

        self._respond_html(body)

    def handle_download(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        domain = query.get("domain", [""])[0].strip()
        if not domain:
            self.send_error(400, "domain query parameter is required")
            return

        try:
            _, report = self._get_report(domain)
        except Exception as exc:  # pragma: no cover - defensive fallback
            self.send_error(500, f"Failed to generate report: {exc}")
            return

        csv_content = report_to_csv(report).encode("utf-8")
        filename = f"{domain.replace('.', '_')}_ads.csv"

        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f"attachment; filename={filename}")
        self.send_header("Content-Length", str(len(csv_content)))
        self.end_headers()
        self.wfile.write(csv_content)

    def _get_report(self, domain: str) -> tuple[str, AdsTxtReport]:
        with _CACHE_LOCK:
            if domain in _CACHE:
                return _CACHE[domain]

        url, body = fetch_ads_txt(domain, http_only=False, timeout=self.server.timeout)
        report = parse_ads_txt(body)
        with _CACHE_LOCK:
            _CACHE[domain] = (url, report)
        return url, report

    def _render_table(self, domain: str, url: str, report: AdsTxtReport) -> str:
        from ads_txt_checker import iter_csv_rows  # local import to avoid circular

        rows_html = []
        for row in iter_csv_rows(report):
            rows_html.append(
                ROW_TEMPLATE.format(
                    line=row["line_number"],
                    exchange=html.escape(row["exchange_domain"]),
                    publisher=html.escape(row["publisher_id"]),
                    relationship=html.escape(row["relationship"]),
                    authority=html.escape(row["authority_id"]),
                    duplicate=row["duplicate_of_line"],
                    errors=html.escape(row["errors"]),
                )
            )

        status = html.escape(format_report(report, url))
        return TABLE_TEMPLATE.format(
            url=html.escape(url),
            domain_encoded=urllib.parse.quote(domain),
            status=status,
            rows="".join(rows_html) or "<tr><td colspan=7>No rows to display.</td></tr>",
        )

    def _respond_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    # Suppress default logging noise unless verbose mode enabled.
    def log_message(self, format: str, *args) -> None:  # pragma: no cover - reduce noise
        if getattr(self.server, "verbose", False):
            super().log_message(format, *args)


def run_server(host: str, port: int, verbose: bool) -> None:
    handler = AdsDashboardHandler
    server = http.server.ThreadingHTTPServer((host, port), handler)
    server.timeout = 15.0
    server.verbose = verbose
    print(f"ads.txt dashboard available at http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the ads.txt dashboard server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--verbose", action="store_true", help="Enable HTTP request logging")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    run_server(args.host, args.port, args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
