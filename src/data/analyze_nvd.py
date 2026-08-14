from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path


def is_not_empty(value: str | None) -> bool:
    return bool(value and value.strip())


def analyze_nvd(input_path: Path) -> None:
    total = 0

    status_counter = Counter()

    has_description = 0
    has_cvss_v40 = 0
    has_cvss_v31 = 0
    has_cvss_v30 = 0
    has_cvss_v2 = 0
    has_cwe = 0

    with input_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        reader = csv.DictReader(f)

        for row in reader:
            total += 1

            status = (
                row.get("vuln_status")
                or "UNKNOWN"
            )

            status_counter[status] += 1

            if is_not_empty(
                row.get("nvd_description")
            ):
                has_description += 1

            if is_not_empty(
                row.get("nvd_cvss_v40_vector")
            ):
                has_cvss_v40 += 1

            if is_not_empty(
                row.get("nvd_cvss_v31_vector")
            ):
                has_cvss_v31 += 1

            if is_not_empty(
                row.get("nvd_cvss_v30_vector")
            ):
                has_cvss_v30 += 1

            if is_not_empty(
                row.get("nvd_cvss_v2_vector")
            ):
                has_cvss_v2 += 1

            if is_not_empty(
                row.get("nvd_cwe_primary")
            ):
                has_cwe += 1

    def percent(value: int) -> float:
        if total == 0:
            return 0.0

        return value / total * 100

    print()
    print("========== NVD DATA SUMMARY ==========")
    print(f"Total records: {total:,}")

    print()
    print("Vulnerability status:")

    for status, count in (
        status_counter.most_common()
    ):
        print(
            f"  {status:<20} "
            f"{count:>8,} "
            f"({percent(count):6.2f}%)"
        )

    print()
    print("Field coverage:")

    fields = [
        (
            "English description",
            has_description,
        ),
        (
            "NVD CVSS v4.0",
            has_cvss_v40,
        ),
        (
            "NVD CVSS v3.1",
            has_cvss_v31,
        ),
        (
            "NVD CVSS v3.0",
            has_cvss_v30,
        ),
        (
            "NVD CVSS v2",
            has_cvss_v2,
        ),
        (
            "NVD CWE",
            has_cwe,
        ),
    ]

    for name, count in fields:
        print(
            f"  {name:<22} "
            f"{count:>8,} "
            f"({percent(count):6.2f}%)"
        )

    print()
    print("======================================")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze parsed NVD dataset"
        )
    )

    parser.add_argument(
        "--input",
        default=(
            "data/interim/"
            "nvd_records.csv"
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    analyze_nvd(
        input_path=Path(args.input)
    )