from __future__ import annotations

import argparse
import csv
from pathlib import Path


def load_nvd_records(
    path: Path,
) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        reader = csv.DictReader(f)

        for row in reader:
            cve_id = row.get("cve_id")

            if cve_id:
                records[cve_id] = row

    return records


def merge_datasets(
    cve_path: Path,
    nvd_path: Path,
    output_path: Path,
) -> None:

    print("[INFO] Loading NVD records...")

    nvd_records = load_nvd_records(
        nvd_path
    )

    print(
        f"[INFO] NVD records loaded: "
        f"{len(nvd_records):,}"
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    total = 0
    matched = 0
    unmatched = 0

    with cve_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as cve_file:

        reader = csv.DictReader(
            cve_file
        )

        cve_fields = (
            reader.fieldnames or []
        )

        nvd_fields: list[str] = []

        if nvd_records:
            first_nvd = next(
                iter(nvd_records.values())
            )

            nvd_fields = [
                field
                for field in first_nvd.keys()
                if field != "cve_id"
            ]

        fieldnames = (
            cve_fields
            + nvd_fields
            + ["nvd_matched"]
        )

        with output_path.open(
            "w",
            encoding="utf-8-sig",
            newline="",
        ) as output_file:

            writer = csv.DictWriter(
                output_file,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            for cve_row in reader:
                total += 1

                cve_id = cve_row.get(
                    "cve_id"
                )

                nvd_row = (
                    nvd_records.get(cve_id)
                    if cve_id
                    else None
                )

                merged = dict(cve_row)

                if nvd_row:
                    matched += 1

                    for field in nvd_fields:
                        merged[field] = (
                            nvd_row.get(
                                field,
                                "",
                            )
                        )

                    merged[
                        "nvd_matched"
                    ] = "1"

                else:
                    unmatched += 1

                    for field in nvd_fields:
                        merged[field] = ""

                    merged[
                        "nvd_matched"
                    ] = "0"

                writer.writerow(
                    merged
                )

    print()
    print("========== MERGE SUMMARY ==========")

    print(
        f"CVE.org records: "
        f"{total:,}"
    )

    print(
        f"Matched NVD:     "
        f"{matched:,}"
    )

    print(
        f"Unmatched:       "
        f"{unmatched:,}"
    )

    if total:
        print(
            f"Match rate:      "
            f"{matched / total * 100:.2f}%"
        )

    print()
    print(
        f"Output: {output_path}"
    )

    print(
        "==================================="
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Merge CVE.org and NVD "
            "records by CVE ID"
        )
    )

    parser.add_argument(
        "--cve",
        default=(
            "data/interim/"
            "cve_records.csv"
        ),
    )

    parser.add_argument(
        "--nvd",
        default=(
            "data/interim/"
            "nvd_records.csv"
        ),
    )

    parser.add_argument(
        "--output",
        default=(
            "data/interim/"
            "cve_nvd_merged.csv"
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    merge_datasets(
        cve_path=Path(args.cve),
        nvd_path=Path(args.nvd),
        output_path=Path(
            args.output
        ),
    )