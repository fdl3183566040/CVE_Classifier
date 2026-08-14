from __future__ import annotations

import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path


def is_not_empty(value: str | None) -> bool:
    return bool(value and value.strip())


def get_year(date_string: str | None) -> str | None:
    if not is_not_empty(date_string):
        return None

    try:
        return datetime.fromisoformat(
            date_string.replace("Z", "+00:00")
        ).strftime("%Y")
    except ValueError:
        return None


def analyze_cve(input_path: Path) -> None:
    total = 0

    state_counter = Counter()
    published_year_counter = Counter()

    has_description = 0
    has_cvss_v40 = 0
    has_cvss_v31 = 0
    has_cvss_v30 = 0
    has_cwe = 0

    with input_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        reader = csv.DictReader(f)

        for row in reader:
            total += 1

            state = row.get("state") or "UNKNOWN"
            state_counter[state] += 1

            year = get_year(
                row.get("date_published")
            )

            if year:
                published_year_counter[year] += 1

            if is_not_empty(
                row.get("description")
            ):
                has_description += 1

            if is_not_empty(
                row.get("cna_cvss_v40_vector")
            ):
                has_cvss_v40 += 1

            if is_not_empty(
                row.get("cna_cvss_v31_vector")
            ):
                has_cvss_v31 += 1

            if is_not_empty(
                row.get("cna_cvss_v30_vector")
            ):
                has_cvss_v30 += 1

            if is_not_empty(
                row.get("cwe_ids")
            ):
                has_cwe += 1

    def percent(value: int) -> float:
        if total == 0:
            return 0.0

        return value / total * 100

    print()
    print("========== CVE DATA SUMMARY ==========")
    print(f"Total records: {total:,}")

    print()
    print("States:")
    for state, count in state_counter.most_common():
        print(
            f"  {state:<20} "
            f"{count:>8,} "
            f"({percent(count):6.2f}%)"
        )

    print()
    print("Field coverage:")

    fields = [
        ("English description", has_description),
        ("CNA CVSS v4.0", has_cvss_v40),
        ("CNA CVSS v3.1", has_cvss_v31),
        ("CNA CVSS v3.0", has_cvss_v30),
        ("CNA CWE", has_cwe),
    ]

    for name, count in fields:
        print(
            f"  {name:<22} "
            f"{count:>8,} "
            f"({percent(count):6.2f}%)"
        )

    print()
    print("Published year:")

    for year in sorted(
        published_year_counter.keys()
    ):
        count = published_year_counter[year]

        print(
            f"  {year}: "
            f"{count:,}"
        )

    print()
    print("======================================")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze parsed CVE.org dataset"
        )
    )

    parser.add_argument(
        "--input",
        default="data/interim/cve_records.csv",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    analyze_cve(
        input_path=Path(args.input)
    )