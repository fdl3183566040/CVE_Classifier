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


def analyze_file(path: Path) -> None:
    counters = {
        metric: Counter()
        for metric in METRICS
    }

    total = 0

    with path.open(
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
    print(f"========== {path.name.upper()} ==========")
    print(f"Total: {total:,}")

    for metric in METRICS:
        print()
        print(f"[{metric}]")

        counter = counters[metric]

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


def analyze_split(
    split_dir: Path,
) -> None:
    for filename in [
        "train.csv",
        "val.csv",
        "test.csv",
    ]:
        path = split_dir / filename

        if not path.exists():
            raise FileNotFoundError(path)

        analyze_file(path)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze label distributions "
            "for temporal train/val/test splits"
        )
    )

    parser.add_argument(
        "--split-dir",
        default=(
            "data/splits/"
            "cvss_v31"
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    analyze_split(
        split_dir=Path(
            args.split_dir
        )
    )