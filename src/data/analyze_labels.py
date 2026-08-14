from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path


METRICS = [
    "AV",
    "AC",
    "PR",
    "UI",
    "S",
    "C",
    "I",
    "A",
]


def analyze_labels(input_path: Path) -> None:
    counters = {
        metric: Counter()
        for metric in METRICS
    }

    total = 0

    with input_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        reader = csv.DictReader(f)

        for row in reader:
            total += 1

            for metric in METRICS:
                value = row.get(metric)

                if value:
                    counters[metric][value] += 1

    print()
    print("========== LABEL DISTRIBUTION ==========")
    print(f"Total records: {total:,}")

    for metric in METRICS:
        counter = counters[metric]

        print()
        print(f"[{metric}]")

        for label, count in counter.most_common():
            percent = (
                count / total * 100
                if total
                else 0.0
            )

            print(
                f"  {label:<5} "
                f"{count:>8,} "
                f"({percent:6.2f}%)"
            )

        if counter:
            largest = max(counter.values())
            smallest = min(counter.values())

            ratio = (
                largest / smallest
                if smallest
                else 0
            )

            print(
                f"  Imbalance ratio: "
                f"{ratio:.2f}:1"
            )

    print()
    print("========================================")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze CVSS v3.1 label distribution"
        )
    )

    parser.add_argument(
        "--input",
        default=(
            "data/processed/"
            "cvss_v31.csv"
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    analyze_labels(
        input_path=Path(args.input)
    )