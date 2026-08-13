from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv
from tqdm import tqdm


BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_OUTPUT_DIR = Path("data/raw/nvd")


def build_headers() -> dict[str, str]:
    load_dotenv()

    headers = {
        "User-Agent": "CVE-Classifier/1.0"
    }

    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        headers["apiKey"] = api_key

    return headers


def request_page(
    session: requests.Session,
    params: dict,
    headers: dict,
    max_retries: int = 5,
) -> dict:

    for attempt in range(max_retries):
        try:
            response = session.get(
                BASE_URL,
                params=params,
                headers=headers,
                timeout=60,
            )

            if response.status_code == 200:
                return response.json()

            print(
                f"[WARN] HTTP {response.status_code}: "
                f"{response.headers.get('message', response.text[:200])}"
            )

        except requests.RequestException as exc:
            print(f"[WARN] Request failed: {exc}")

        sleep_seconds = 2 ** attempt

        print(
            f"[INFO] retrying in "
            f"{sleep_seconds} seconds..."
        )

        time.sleep(sleep_seconds)

    raise RuntimeError(
        f"NVD request failed after {max_retries} retries"
    )


def download_nvd(
    pub_start_date: str,
    pub_end_date: str,
    output_dir: Path,
    sleep_seconds: float = 6.0,
    output_path: Path | None = None,
):
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    headers = build_headers()

    session = requests.Session()

    start_index = 0

    base_params = {
        "pubStartDate": pub_start_date,
        "pubEndDate": pub_end_date,
    }

    print(
        f"[INFO] Downloading CVEs from "
        f"{pub_start_date} to {pub_end_date}"
    )

    first_params = {
        **base_params,
        "startIndex": start_index,
    }

    first_page = request_page(
        session=session,
        params=first_params,
        headers=headers,
    )

    total_results = first_page["totalResults"]
    results_per_page = first_page["resultsPerPage"]

    print(
        f"[INFO] totalResults={total_results}, "
        f"resultsPerPage={results_per_page}"
    )

    all_vulnerabilities = []

    vulnerabilities = first_page.get(
        "vulnerabilities",
        [],
    )

    all_vulnerabilities.extend(vulnerabilities)

    start_index += len(vulnerabilities)

    progress = tqdm(
        total=total_results,
        initial=len(vulnerabilities),
        desc="Downloading",
    )

    while start_index < total_results:

        time.sleep(sleep_seconds)

        params = {
            **base_params,
            "startIndex": start_index,
        }

        page = request_page(
            session=session,
            params=params,
            headers=headers,
        )

        vulnerabilities = page.get(
            "vulnerabilities",
            [],
        )

        if not vulnerabilities:
            print(
                "[WARN] Empty page received; stopping."
            )
            break

        all_vulnerabilities.extend(
            vulnerabilities
        )

        count = len(vulnerabilities)

        start_index += count

        progress.update(count)

    progress.close()

    if output_path is None:
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = (
            f"nvd_"
            f"{pub_start_date[:10]}_"
            f"{pub_end_date[:10]}_"
            f"{timestamp}.json"
        )

        output_path = output_dir / filename

    result = {
        "metadata": {
            "downloaded_at": datetime.now().isoformat(),
            "pub_start_date": pub_start_date,
            "pub_end_date": pub_end_date,
            "total_results": len(all_vulnerabilities),
            "source": BASE_URL,
        },
        "vulnerabilities": all_vulnerabilities,
    }

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            result,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(
        f"[INFO] Saved {len(all_vulnerabilities)} "
        f"CVEs to {output_path}"
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Download CVE records from NVD API 2.0"
    )

    parser.add_argument(
        "--start",
        required=True,
        help=(
            "Publication start time, e.g. "
            "2025-01-01T00:00:00.000"
        ),
    )

    parser.add_argument(
        "--end",
        required=True,
        help=(
            "Publication end time, e.g. "
            "2025-01-31T23:59:59.999"
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=6.0,
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    download_nvd(
        pub_start_date=args.start,
        pub_end_date=args.end,
        output_dir=Path(args.output_dir),
        sleep_seconds=args.sleep,
    )