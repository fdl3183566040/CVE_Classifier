from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path


def parse_date(value: str) -> datetime:
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def split_dataset(
    input_path: Path,
    output_dir: Path,
) -> None:
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    train_path = output_dir / "train.csv"
    val_path = output_dir / "val.csv"
    test_path = output_dir / "test.csv"

    train_rows = []
    val_rows = []
    test_rows = []

    with input_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        reader = csv.DictReader(f)

        fieldnames = reader.fieldnames

        if fieldnames is None:
            raise RuntimeError(
                "CSV has no header"
            )

        for row in reader:
            date_value = row.get(
                "date_published"
            )

            if not date_value:
                continue

            published = parse_date(
                date_value
            )

            year = published.year
            month = published.month

            if (
                year == 2024
                or (
                    year == 2025
                    and month <= 6
                )
            ):
                train_rows.append(row)

            elif (
                year == 2025
                and 7 <= month <= 9
            ):
                val_rows.append(row)

            elif (
                year == 2025
                and 10 <= month <= 12
            ):
                test_rows.append(row)

    def write_csv(
        path: Path,
        rows: list[dict[str, str]],
    ) -> None:
        with path.open(
            "w",
            encoding="utf-8-sig",
            newline="",
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
            )

            writer.writeheader()
            writer.writerows(rows)

    write_csv(
        train_path,
        train_rows,
    )

    write_csv(
        val_path,
        val_rows,
    )

    write_csv(
        test_path,
        test_rows,
    )

    total = (
        len(train_rows)
        + len(val_rows)
        + len(test_rows)
    )

    print()
    print(
        "========== TEMPORAL SPLIT =========="
    )

    print(
        f"Train: {len(train_rows):,}"
    )

    print(
        f"Val:   {len(val_rows):,}"
    )

    print(
        f"Test:  {len(test_rows):,}"
    )

    print(
        f"Total: {total:,}"
    )

    if total:
        print()

        print(
            f"Train ratio: "
            f"{len(train_rows) / total * 100:.2f}%"
        )

        print(
            f"Val ratio:   "
            f"{len(val_rows) / total * 100:.2f}%"
        )

        print(
            f"Test ratio:  "
            f"{len(test_rows) / total * 100:.2f}%"
        )

    print()
    print(
        f"Output: {output_dir}"
    )

    print(
        "===================================="
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Temporal split for CVSS v3.1 dataset"
        )
    )

    parser.add_argument(
        "--input",
        default=(
            "data/processed/"
            "cvss_v31.csv"
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=(
            "data/splits/"
            "cvss_v31"
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    split_dataset(
        input_path=Path(args.input),
        output_dir=Path(args.output_dir),
    )