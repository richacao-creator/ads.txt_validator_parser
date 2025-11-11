#!/usr/bin/env python3
"""
ads_txt_checker.py

Simple CLI tool that fetches a publisher's ads.txt file, parses the entries,
and reports basic validation issues such as malformed rows or duplicates.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
from pathlib import Path
from collections import defaultdict
import io
import ipaddress
import sys
import textwrap
import urllib.error
import urllib.request
from typing import Dict, Iterable, List, Optional, Tuple

# Relationship values defined by the IAB Tech Lab ads.txt specification.
VALID_RELATIONSHIPS = {"DIRECT", "RESELLER"}


@dataclasses.dataclass(frozen=True)
class AdsTxtRecord:
    exchange_domain: str
    publisher_id: str
    relationship: str
    authority_id: Optional[str]
    raw_line_number: int


@dataclasses.dataclass
class AdsTxtReport:
    records: List[AdsTxtRecord]
    errors: List[str]
    duplicates: List[Tuple[int, int, AdsTxtRecord]]
    line_errors: Dict[int, List[str]]

    def has_issues(self) -> bool:
        return bool(self.errors or self.duplicates)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch, parse, and validate an ads.txt file for a publisher domain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              ads_txt_checker.py example.com
              ads_txt_checker.py --http-only publisher.org
              ads_txt_checker.py cnn.com --csv-output cnn_ads.csv
            """
        ),
    )
    parser.add_argument(
        "domain",
        help="Publisher domain to inspect (e.g. example.com).",
    )
    parser.add_argument(
        "--http-only",
        action="store_true",
        help="Do not attempt HTTPS before HTTP when retrieving ads.txt.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        help="Optional path to write a CSV report summarizing each ads.txt line.",
    )
    return parser


def fetch_ads_txt(domain: str, http_only: bool, timeout: float) -> Tuple[str, str]:
    """
    Retrieve the contents of /ads.txt for the given domain.

    Returns a tuple containing the resolved URL and the raw text payload.
    Raises urllib.error.URLError if retrieval fails.
    """
    candidates = []
    if not http_only:
        candidates.append(f"https://{domain}/ads.txt")
    candidates.append(f"http://{domain}/ads.txt")

    last_error: Optional[Exception] = None
    for url in candidates:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ads-txt-checker/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status >= 400:
                    raise urllib.error.HTTPError(
                        url, response.status, response.reason, response.headers, None
                    )
                body = response.read().decode("utf-8", errors="replace")
                return url, body
        except Exception as exc:  # pragma: no cover - aggregate errors
            last_error = exc
            continue
    assert last_error is not None
    raise last_error


def parse_ads_txt(raw_text: str) -> AdsTxtReport:
    records: List[AdsTxtRecord] = []
    errors: List[str] = []
    line_errors: Dict[int, List[str]] = defaultdict(list)
    seen_entries: dict[Tuple[str, str, str, Optional[str]], AdsTxtRecord] = {}
    duplicates: List[Tuple[int, int, AdsTxtRecord]] = []

    for line_number, raw_line in enumerate(raw_text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Remove end-of-line comments.
        stripped = stripped.split("#", 1)[0].strip()

        fields = [field.strip() for field in stripped.split(",")]

        if len(fields) not in (3, 4):
            message = (
                f"L{line_number}: expected 3 or 4 comma-separated fields, found {len(fields)}"
            )
            errors.append(message)
            line_errors[line_number].append(message)
            continue

        exchange_domain, publisher_id, relationship = fields[:3]
        authority_id = fields[3] if len(fields) == 4 else None

        if not exchange_domain:
            message = f"L{line_number}: empty exchange domain"
            errors.append(message)
            line_errors[line_number].append(message)
        if not publisher_id:
            message = f"L{line_number}: empty publisher account id"
            errors.append(message)
            line_errors[line_number].append(message)
        relationship_upper = relationship.upper()
        if relationship_upper not in VALID_RELATIONSHIPS:
            message = (
                f"L{line_number}: relationship '{relationship}' is invalid "
                f"(expected one of {sorted(VALID_RELATIONSHIPS)})"
            )
            errors.append(message)
            line_errors[line_number].append(message)

        if authority_id and not is_valid_authority_id(authority_id):
            message = (
                f"L{line_number}: authority id '{authority_id}' is not a valid domain or IP address"
            )
            errors.append(message)
            line_errors[line_number].append(message)

        record = AdsTxtRecord(
            exchange_domain=exchange_domain.lower(),
            publisher_id=publisher_id,
            relationship=relationship_upper,
            authority_id=authority_id,
            raw_line_number=line_number,
        )

        key = (record.exchange_domain, record.publisher_id, record.relationship, record.authority_id)
        if key in seen_entries:
            original = seen_entries[key]
            duplicates.append((original.raw_line_number, line_number, record))
        else:
            seen_entries[key] = record
            records.append(record)

    return AdsTxtReport(records=records, errors=errors, duplicates=duplicates, line_errors=dict(line_errors))


def is_valid_authority_id(value: str) -> bool:
    """
    Validate that the authority id, when present, resembles either a domain, an IP address,
    or a TAG certification authority identifier (16 hexadecimal characters).
    """
    candidate = value.strip()
    if not candidate:
        return False

    # Accept common TAG IDs (16 hex characters, case-insensitive)
    tag_id = candidate.replace("-", "")
    if len(tag_id) in (16, 32) and all(ch in "0123456789abcdefABCDEF" for ch in tag_id):
        return True

    # Try IPv4 / IPv6
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    # Validate domains: at least two labels, alphanumeric or hyphen, no surrounding hyphen.
    labels = candidate.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in label.lower()):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def iter_csv_rows(report: AdsTxtReport):
    duplicate_lookup = {dup_line: original_line for original_line, dup_line, _ in report.duplicates}
    records_by_line = {record.raw_line_number: record for record in report.records}
    line_numbers = sorted({*records_by_line.keys(), *report.line_errors.keys()})

    for line_number in line_numbers:
        record = records_by_line.get(line_number)
        error_messages = "; ".join(report.line_errors.get(line_number, []))
        yield {
            "line_number": line_number,
            "exchange_domain": record.exchange_domain if record else "",
            "publisher_id": record.publisher_id if record else "",
            "relationship": record.relationship if record else "",
            "authority_id": record.authority_id or "" if record else "",
            "duplicate_of_line": duplicate_lookup.get(line_number, ""),
            "errors": error_messages,
        }


def write_csv_report(report: AdsTxtReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "line_number",
                "exchange_domain",
                "publisher_id",
                "relationship",
                "authority_id",
                "duplicate_of_line",
                "errors",
            ],
        )
        writer.writeheader()
        for row in iter_csv_rows(report):
            writer.writerow(row)


def report_to_csv(report: AdsTxtReport) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "line_number",
            "exchange_domain",
            "publisher_id",
            "relationship",
            "authority_id",
            "duplicate_of_line",
            "errors",
        ],
    )
    writer.writeheader()
    for row in iter_csv_rows(report):
        writer.writerow(row)
    return buffer.getvalue()


def format_report(report: AdsTxtReport, url: str) -> str:
    lines: List[str] = [
        f"ads.txt URL: {url}",
        f"Valid records: {len(report.records)}",
    ]
    if report.errors:
        lines.append("Errors:")
        lines.extend(f"  - {message}" for message in report.errors)
    if report.duplicates:
        lines.append("Duplicate entries:")
        for first_line, duplicate_line, record in report.duplicates:
            lines.append(
                f"  - L{duplicate_line} duplicates L{first_line}: "
                f"{record.exchange_domain}, {record.publisher_id}, {record.relationship}"
            )
    if not report.has_issues():
        lines.append("No issues detected.")
    return "\n".join(lines)


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        url, body = fetch_ads_txt(args.domain, args.http_only, args.timeout)
    except urllib.error.URLError as exc:
        print(f"Failed to retrieve ads.txt for {args.domain}: {exc}", file=sys.stderr)
        return 1

    report = parse_ads_txt(body)
    print(format_report(report, url))

    if args.csv_output:
        try:
            write_csv_report(report, args.csv_output)
            print(f"CSV report written to {args.csv_output}")
        except OSError as exc:
            print(f"Failed to write CSV report: {exc}", file=sys.stderr)
            return 1

    return 0 if not report.has_issues() else 2


if __name__ == "__main__":
    sys.exit(main())
