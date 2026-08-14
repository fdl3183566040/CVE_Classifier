from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path
from typing import Any


CVSS_V31_METRICS = [
    "AV",
    "AC",
    "PR",
    "UI",
    "S",
    "C",
    "I",
    "A",
]


def is_not_empty(value: str | None) -> bool:
    return bool(value and value.strip())


def parse_year(date_string: str | None) -> int | None:
    if not is_not_empty(date_string):
        return None

    try:
        dt = datetime.fromisoformat(
            date_string.replace("Z", "+00:00")
        )
        return dt.year
    except ValueError:
        return None


def parse_cvss_vector(
    vector: str | None,
) -> dict[str, str] | None:
    if not is_not_empty(vector):
        return None

    parts = vector.split("/")

    if not parts:
        return None

    if parts[0] != "CVSS:3.1":
        return None

    result: dict[str, str] = {}

    for part in parts[1:]:
        if ":" not in part:
            continue

        key, value = part.split(":", 1)
        result[key] = value

    for metric in CVSS_V31_METRICS:
        if metric not in result:
            return None

    return result


def is_valid_record(
    row: dict[str, str],
    start_year: int,
    end_year: int,
) -> bool:
    if row.get("state") != "PUBLISHED":
        return False

    if row.get("nvd_matched") != "1":
        return False

    if not is_not_empty(
        row.get("description")
    ):
        return False

    if (
        row.get("vuln_status")
        == "Rejected"
    ):
        return False

    year = parse_year(
        row.get("date_published")
    )

    if year is None:
        return False

    if not (
        start_year
        <= year
        <= end_year
    ):
        return False

    if not is_not_empty(
        row.get("nvd_cvss_v31_vector")
    ):
        return False

    return True


def build_cvss_v31_dataset(
    input_path: Path,
    output_path: Path,
    start_year: int,
    end_year: int,
) -> None:
    total = 0
    kept = 0

    filtered_state = 0
    filtered_description = 0
    filtered_match = 0
    filtered_status = 0
    filtered_year = 0
    filtered_cvss = 0
    filtered_invalid_vector = 0

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "cve_id",
        "description",
        "date_published",
        "nvd_vuln_status",
        "cvss_vector",
        "cvss_score",
        "cvss_severity",
        "cwe",

        "AV",
        "AC",
        "PR",
        "UI",
        "S",
        "C",
        "I",
        "A",
    ]

    with input_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as input_file, output_path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as output_file:

        reader = csv.DictReader(
            input_file
        )

        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for row in reader:
            total += 1

            if row.get("state") != "PUBLISHED":
                filtered_state += 1
                continue

            if not is_not_empty(
                row.get("description")
            ):
                filtered_description += 1
                continue

            if row.get("nvd_matched") != "1":
                filtered_match += 1
                continue

            if (
                row.get("vuln_status")
                == "Rejected"
            ):
                filtered_status += 1
                continue

            year = parse_year(
                row.get("date_published")
            )

            if (
                year is None
                or year < start_year
                or year > end_year
            ):
                filtered_year += 1
                continue

            vector = row.get(
                "nvd_cvss_v31_vector"
            )

            if not is_not_empty(vector):
                filtered_cvss += 1
                continue

            metrics = parse_cvss_vector(
                vector
            )

            if metrics is None:
                filtered_invalid_vector += 1
                continue

            output_row: dict[str, Any] = {
                "cve_id": row.get("cve_id"),
                "description": (
                    row.get("description")
                ),
                "date_published": (
                    row.get("date_published")
                ),
                "nvd_vuln_status": (
                    row.get("vuln_status")
                ),

                "cvss_vector": vector,

                "cvss_score": (
                    row.get(
                        "nvd_cvss_v31_score"
                    )
                ),

                "cvss_severity": (
                    row.get(
                        "nvd_cvss_v31_severity"
                    )
                ),

                "cwe": (
                    row.get(
                        "nvd_cwe_primary"
                    )
                ),
            }

            for metric in CVSS_V31_METRICS:
                output_row[metric] = (
                    metrics[metric]
                )

            writer.writerow(
                output_row
            )

            kept += 1

    print()
    print(
        "========== CVSS V3.1 DATASET =========="
    )

    print(
        f"Input records:           "
        f"{total:,}"
    )

    print(
        f"Kept records:            "
        f"{kept:,}"
    )

    print()
    print("Filtered:")

    print(
        f"  Non-published:          "
        f"{filtered_state:,}"
    )

    print(
        f"  Missing description:    "
        f"{filtered_description:,}"
    )

    print(
        f"  No NVD match:           "
        f"{filtered_match:,}"
    )

    print(
        f"  NVD rejected:           "
        f"{filtered_status:,}"
    )

    print(
        f"  Outside year range:     "
        f"{filtered_year:,}"
    )

    print(
        f"  Missing CVSS v3.1:      "
        f"{filtered_cvss:,}"
    )

    print(
        f"  Invalid CVSS vector:    "
        f"{filtered_invalid_vector:,}"
    )

    print()
    print(
        f"Output: {output_path}"
    )

    print(
        "========================================"
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Build processed CVSS v3.1 "
            "classification dataset"
        )
    )

    parser.add_argument(
        "--input",
        default=(
            "data/interim/"
            "cve_nvd_merged.csv"
        ),
    )

    parser.add_argument(
        "--output",
        default=(
            "data/processed/"
            "cvss_v31.csv"
        ),
    )

    parser.add_argument(
        "--start-year",
        type=int,
        default=2024,
    )

    parser.add_argument(
        "--end-year",
        type=int,
        default=2025,
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    build_cvss_v31_dataset(
        input_path=Path(args.input),
        output_path=Path(args.output),
        start_year=args.start_year,
        end_year=args.end_year,
    )