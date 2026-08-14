from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def get_english_description(cve: dict[str, Any]) -> str | None:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            value = item.get("value")
            if value:
                return value.strip()

    return None


def cvss_priority(metric: dict[str, Any]) -> tuple[int, int]:
    source = (metric.get("source") or "").lower()
    metric_type = (metric.get("type") or "").lower()

    is_nvd = source == "nvd@nist.gov"
    is_primary = metric_type == "primary"
    is_secondary = metric_type == "secondary"

    if is_nvd and is_primary:
        return 0, 0

    if is_primary:
        return 1, 0

    if is_secondary:
        return 2, 0

    return 3, 0


def choose_cvss_metric(
    metrics: list[dict[str, Any]],
) -> dict[str, Any] | None:

    if not metrics:
        return None

    return sorted(
        metrics,
        key=cvss_priority,
    )[0]


def extract_cvss(
    cve: dict[str, Any],
    key: str,
) -> dict[str, Any]:

    metrics = cve.get("metrics", {}).get(key, [])

    selected = choose_cvss_metric(metrics)

    result = {
        "vector": None,
        "score": None,
        "severity": None,
        "source": None,
        "type": None,
    }

    if not selected:
        return result

    cvss_data = selected.get("cvssData", {})

    result["vector"] = cvss_data.get("vectorString")
    result["score"] = cvss_data.get("baseScore")
    result["severity"] = cvss_data.get("baseSeverity")
    result["source"] = selected.get("source")
    result["type"] = selected.get("type")

    return result


def get_cwes(
    cve: dict[str, Any],
) -> tuple[str | None, list[str]]:

    primary: str | None = None
    all_cwes: list[str] = []

    for weakness in cve.get("weaknesses", []):
        weakness_type = (
            weakness.get("type") or ""
        ).lower()

        for description in weakness.get(
            "description",
            [],
        ):
            value = description.get("value")

            if not value:
                continue

            if not value.startswith("CWE-"):
                continue

            if value not in all_cwes:
                all_cwes.append(value)

            if (
                weakness_type == "primary"
                and primary is None
            ):
                primary = value

    if primary is None and all_cwes:
        primary = all_cwes[0]

    return primary, all_cwes


def parse_vulnerability(
    vulnerability: dict[str, Any],
) -> dict[str, Any] | None:

    cve = vulnerability.get("cve", {})

    cve_id = cve.get("id")

    if not cve_id:
        return None

    cvss_v40 = extract_cvss(
        cve,
        "cvssMetricV40",
    )

    cvss_v31 = extract_cvss(
        cve,
        "cvssMetricV31",
    )

    cvss_v30 = extract_cvss(
        cve,
        "cvssMetricV30",
    )

    cvss_v2 = extract_cvss(
        cve,
        "cvssMetricV2",
    )

    cwe_primary, cwe_all = get_cwes(cve)

    return {
        "cve_id": cve_id,

        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),

        "nvd_description": (
            get_english_description(cve)
        ),

        "nvd_cvss_v40_vector": (
            cvss_v40["vector"]
        ),
        "nvd_cvss_v40_score": (
            cvss_v40["score"]
        ),
        "nvd_cvss_v40_severity": (
            cvss_v40["severity"]
        ),
        "nvd_cvss_v40_source": (
            cvss_v40["source"]
        ),
        "nvd_cvss_v40_type": (
            cvss_v40["type"]
        ),

        "nvd_cvss_v31_vector": (
            cvss_v31["vector"]
        ),
        "nvd_cvss_v31_score": (
            cvss_v31["score"]
        ),
        "nvd_cvss_v31_severity": (
            cvss_v31["severity"]
        ),
        "nvd_cvss_v31_source": (
            cvss_v31["source"]
        ),
        "nvd_cvss_v31_type": (
            cvss_v31["type"]
        ),

        "nvd_cvss_v30_vector": (
            cvss_v30["vector"]
        ),
        "nvd_cvss_v30_score": (
            cvss_v30["score"]
        ),
        "nvd_cvss_v30_severity": (
            cvss_v30["severity"]
        ),
        "nvd_cvss_v30_source": (
            cvss_v30["source"]
        ),
        "nvd_cvss_v30_type": (
            cvss_v30["type"]
        ),

        "nvd_cvss_v2_vector": (
            cvss_v2["vector"]
        ),
        "nvd_cvss_v2_score": (
            cvss_v2["score"]
        ),
        "nvd_cvss_v2_severity": (
            cvss_v2["severity"]
        ),
        "nvd_cvss_v2_source": (
            cvss_v2["source"]
        ),
        "nvd_cvss_v2_type": (
            cvss_v2["type"]
        ),

        "nvd_cwe_primary": cwe_primary,
        "nvd_cwe_all": "|".join(cwe_all),
    }


def load_nvd_file(
    path: Path,
) -> list[dict[str, Any]]:

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        OSError,
    ) as exc:
        print(
            f"[WARN] Failed to read {path}: {exc}"
        )
        return []

    vulnerabilities = data.get(
        "vulnerabilities",
        [],
    )

    records: list[dict[str, Any]] = []

    for vulnerability in vulnerabilities:
        record = parse_vulnerability(
            vulnerability
        )

        if record is not None:
            records.append(record)

    return records


def find_json_files(
    input_dir: Path,
) -> list[Path]:

    return sorted(
        input_dir.rglob("*.json")
    )


def parse_directory(
    input_dir: Path,
    output_path: Path,
) -> None:

    files = find_json_files(input_dir)

    print(
        f"[INFO] Found {len(files)} NVD JSON files"
    )

    records_by_id: dict[
        str,
        dict[str, Any],
    ] = {}

    failed_files = 0

    for index, path in enumerate(
        files,
        start=1,
    ):
        records = load_nvd_file(path)

        if not records:
            failed_files += 1

        for record in records:
            records_by_id[
                record["cve_id"]
            ] = record

        print(
            f"[INFO] Parsed file "
            f"{index}/{len(files)}: {path.name}"
        )

    records = list(
        records_by_id.values()
    )

    records.sort(
        key=lambda x: x["cve_id"]
    )

    if not records:
        raise RuntimeError(
            "No NVD records parsed"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = list(
        records[0].keys()
    )

    with output_path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(records)

    print()
    print(
        f"[INFO] Unique CVE records: "
        f"{len(records):,}"
    )

    print(
        f"[INFO] Empty/failed files: "
        f"{failed_files}"
    )

    print(
        f"[INFO] Output: "
        f"{output_path}"
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Parse NVD CVE API JSON "
            "into structured CSV"
        )
    )

    parser.add_argument(
        "--input-dir",
        default="data/raw/nvd",
    )

    parser.add_argument(
        "--output",
        default=(
            "data/interim/"
            "nvd_records.csv"
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    parse_directory(
        input_dir=Path(args.input_dir),
        output_path=Path(args.output),
    )