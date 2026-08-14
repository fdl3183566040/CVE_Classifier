from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def get_english_description(cna: dict[str, Any]) -> str | None:
    descriptions = cna.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            value = item.get("value")
            if value:
                return value.strip()

    return None


def get_cwe_ids(cna: dict[str, Any]) -> list[str]:
    result: list[str] = []

    for problem_type in cna.get("problemTypes", []):
        for description in problem_type.get("descriptions", []):
            cwe_id = description.get("cweId")

            if cwe_id and cwe_id not in result:
                result.append(cwe_id)

    return result


def get_products(
    cna: dict[str, Any],
) -> tuple[list[str], list[str]]:
    vendors: list[str] = []
    products: list[str] = []

    for affected in cna.get("affected", []):
        vendor = affected.get("vendor")
        product = affected.get("product")

        if vendor and vendor not in vendors:
            vendors.append(vendor)

        if product and product not in products:
            products.append(product)

    return vendors, products


def get_reference_urls(cna: dict[str, Any]) -> list[str]:
    urls: list[str] = []

    for reference in cna.get("references", []):
        url = reference.get("url")

        if url and url not in urls:
            urls.append(url)

    return urls


def get_cna_cvss(cna: dict[str, Any]) -> dict[str, Any]:
    result = {
        "cvss_v40_vector": None,
        "cvss_v40_score": None,
        "cvss_v40_severity": None,
        "cvss_v31_vector": None,
        "cvss_v31_score": None,
        "cvss_v31_severity": None,
        "cvss_v30_vector": None,
        "cvss_v30_score": None,
        "cvss_v30_severity": None,
    }

    for metric in cna.get("metrics", []):

        if "cvssV4_0" in metric:
            cvss = metric["cvssV4_0"]

            if result["cvss_v40_vector"] is None:
                result["cvss_v40_vector"] = cvss.get(
                    "vectorString"
                )
                result["cvss_v40_score"] = cvss.get(
                    "baseScore"
                )
                result["cvss_v40_severity"] = cvss.get(
                    "baseSeverity"
                )

        if "cvssV3_1" in metric:
            cvss = metric["cvssV3_1"]

            if result["cvss_v31_vector"] is None:
                result["cvss_v31_vector"] = cvss.get(
                    "vectorString"
                )
                result["cvss_v31_score"] = cvss.get(
                    "baseScore"
                )
                result["cvss_v31_severity"] = cvss.get(
                    "baseSeverity"
                )

        if "cvssV3_0" in metric:
            cvss = metric["cvssV3_0"]

            if result["cvss_v30_vector"] is None:
                result["cvss_v30_vector"] = cvss.get(
                    "vectorString"
                )
                result["cvss_v30_score"] = cvss.get(
                    "baseScore"
                )
                result["cvss_v30_severity"] = cvss.get(
                    "baseSeverity"
                )

    return result


def parse_cve_record(path: Path) -> dict[str, Any] | None:
    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as f:
            record = json.load(f)

    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        OSError,
    ) as exc:
        print(
            f"[WARN] Failed to read {path}: {exc}"
        )
        return None

    metadata = record.get(
        "cveMetadata",
        {},
    )

    containers = record.get(
        "containers",
        {},
    )

    cna = containers.get(
        "cna",
        {},
    )

    cve_id = metadata.get("cveId")

    if not cve_id:
        print(
            f"[WARN] Missing cveId: {path}"
        )
        return None

    description = get_english_description(cna)

    cwe_ids = get_cwe_ids(cna)

    vendors, products = get_products(cna)

    references = get_reference_urls(cna)

    cvss = get_cna_cvss(cna)

    return {
        "cve_id": cve_id,
        "state": metadata.get("state"),
        "assigner_short_name": metadata.get(
            "assignerShortName"
        ),
        "date_reserved": metadata.get(
            "dateReserved"
        ),
        "date_published": metadata.get(
            "datePublished"
        ),
        "date_updated": metadata.get(
            "dateUpdated"
        ),
        "description": description,

        "cna_cvss_v40_vector": (
            cvss["cvss_v40_vector"]
        ),
        "cna_cvss_v40_score": (
            cvss["cvss_v40_score"]
        ),
        "cna_cvss_v40_severity": (
            cvss["cvss_v40_severity"]
        ),

        "cna_cvss_v31_vector": (
            cvss["cvss_v31_vector"]
        ),
        "cna_cvss_v31_score": (
            cvss["cvss_v31_score"]
        ),
        "cna_cvss_v31_severity": (
            cvss["cvss_v31_severity"]
        ),

        "cna_cvss_v30_vector": (
            cvss["cvss_v30_vector"]
        ),
        "cna_cvss_v30_score": (
            cvss["cvss_v30_score"]
        ),
        "cna_cvss_v30_severity": (
            cvss["cvss_v30_severity"]
        ),

        "cwe_ids": "|".join(cwe_ids),
        "vendors": "|".join(vendors),
        "products": "|".join(products),
        "reference_urls": "|".join(
            references
        ),

        "source_file": str(path),
    }


def find_cve_files(
    input_dir: Path,
) -> list[Path]:
    return sorted(
        input_dir.rglob("CVE-*.json")
    )


def parse_directory(
    input_dir: Path,
    output_path: Path,
) -> None:

    files = find_cve_files(
        input_dir
    )

    print(
        f"[INFO] Found {len(files)} "
        f"CVE JSON files"
    )

    records: list[dict[str, Any]] = []

    failed = 0

    for index, path in enumerate(
        files,
        start=1,
    ):
        record = parse_cve_record(
            path
        )

        if record is None:
            failed += 1
            continue

        records.append(record)

        if index % 5000 == 0:
            print(
                f"[INFO] Parsed "
                f"{index}/{len(files)}"
            )

    if not records:
        raise RuntimeError(
            "No CVE records parsed"
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

        writer.writerows(
            records
        )

    print()
    print(
        f"[INFO] Parsed records: "
        f"{len(records)}"
    )

    print(
        f"[INFO] Failed records: "
        f"{failed}"
    )

    print(
        f"[INFO] Output: "
        f"{output_path}"
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Parse official CVE JSON 5 records "
            "into structured CSV data"
        )
    )

    parser.add_argument(
        "--input-dir",
        default="data/raw/cve",
    )

    parser.add_argument(
        "--output",
        default=(
            "data/interim/"
            "cve_records.csv"
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    parse_directory(
        input_dir=Path(
            args.input_dir
        ),
        output_path=Path(
            args.output
        ),
    )