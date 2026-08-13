from __future__ import annotations

import argparse
import calendar
from datetime import datetime
from pathlib import Path

from src.data.download_nvd import download_nvd


def iter_months(start: str, end: str):
    start_dt = datetime.strptime(start, "%Y-%m")
    end_dt = datetime.strptime(end, "%Y-%m")

    year = start_dt.year
    month = start_dt.month

    while (year, month) <= (end_dt.year, end_dt.month):
        yield year, month

        month += 1

        if month == 13:
            month = 1
            year += 1


def download_range(
    start: str,
    end: str,
    output_dir: Path,
    sleep_seconds: float,
):
    for year, month in iter_months(start, end):

        month_dir = output_dir / str(year)

        month_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        filename = month_dir / f"{year}-{month:02d}.json"

        if filename.exists():
            print(
                f"[SKIP] {filename} already exists"
            )
            continue

        last_day = calendar.monthrange(
            year,
            month,
        )[1]

        start_date = (
            f"{year}-{month:02d}-01"
            f"T00:00:00.000"
        )

        end_date = (
            f"{year}-{month:02d}-{last_day:02d}"
            f"T23:59:59.999"
        )

        print()
        print(
            f"[INFO] Downloading "
            f"{year}-{month:02d}"
        )

        download_nvd(
            pub_start_date=start_date,
            pub_end_date=end_date,
            output_dir=month_dir,
            sleep_seconds=sleep_seconds,
            output_path=filename,
        )


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--start",
        required=True,
        help="Start month, e.g. 2024-01",
    )

    parser.add_argument(
        "--end",
        required=True,
        help="End month, e.g. 2025-12",
    )

    parser.add_argument(
        "--output-dir",
        default="data/raw/nvd",
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=6.0,
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    download_range(
        start=args.start,
        end=args.end,
        output_dir=Path(args.output_dir),
        sleep_seconds=args.sleep,
    )