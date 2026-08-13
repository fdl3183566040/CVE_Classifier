from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


CVE_REPO_URL = "https://github.com/CVEProject/cvelistV5.git"


def run_command(command: list[str], cwd: Path | None = None) -> None:
    print(f"[CMD] {' '.join(command)}")

    subprocess.run(
        command,
        cwd=cwd,
        check=True,
    )


def download_cve_years(
    start_year: int,
    end_year: int,
    output_dir: Path,
    temp_repo_dir: Path,
) -> None:

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    years = list(
        range(start_year, end_year + 1)
    )

    print(
        f"[INFO] CVE years: "
        f"{', '.join(map(str, years))}"
    )

    # --------------------------------------------------
    # 1. 如果临时仓库不存在，则创建 sparse clone
    # --------------------------------------------------

    if not temp_repo_dir.exists():

        print("[INFO] Creating sparse CVE repository...")

        run_command(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                CVE_REPO_URL,
                str(temp_repo_dir),
            ]
        )

    else:
        print(
            f"[INFO] Existing repository found: "
            f"{temp_repo_dir}"
        )

    # --------------------------------------------------
    # 2. 初始化 sparse-checkout
    # --------------------------------------------------

    run_command(
        [
            "git",
            "sparse-checkout",
            "init",
            "--cone",
        ],
        cwd=temp_repo_dir,
    )

    # --------------------------------------------------
    # 3. 只指定需要的年份
    # --------------------------------------------------

    sparse_paths = [
        f"cves/{year}"
        for year in years
    ]

    run_command(
        [
            "git",
            "sparse-checkout",
            "set",
            *sparse_paths,
        ],
        cwd=temp_repo_dir,
    )

    # --------------------------------------------------
    # 4. 获取 main 分支
    # --------------------------------------------------

    run_command(
        [
            "git",
            "checkout",
            "main",
        ],
        cwd=temp_repo_dir,
    )

    # --------------------------------------------------
    # 5. 更新到最新版本
    # --------------------------------------------------

    run_command(
        [
            "git",
            "pull",
            "--ff-only",
            "origin",
            "main",
        ],
        cwd=temp_repo_dir,
    )

    # --------------------------------------------------
    # 6. 将指定年份复制到 data/raw/cve
    # --------------------------------------------------

    source_root = temp_repo_dir / "cves"

    for year in years:

        source_dir = source_root / str(year)
        destination_dir = output_dir / str(year)

        if not source_dir.exists():
            print(
                f"[WARN] CVE directory not found: "
                f"{source_dir}"
            )
            continue

        if destination_dir.exists():
            print(
                f"[SKIP] {destination_dir} "
                f"already exists"
            )
            continue

        print(
            f"[INFO] Copying CVE {year}: "
            f"{source_dir} -> {destination_dir}"
        )

        shutil.copytree(
            source_dir,
            destination_dir,
        )

    print()
    print("[INFO] CVE download completed.")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Download selected CVE years from "
            "CVEProject/cvelistV5 using sparse checkout"
        )
    )

    parser.add_argument(
        "--start-year",
        type=int,
        required=True,
        help="Start CVE ID year, e.g. 2024",
    )

    parser.add_argument(
        "--end-year",
        type=int,
        required=True,
        help="End CVE ID year, e.g. 2025",
    )

    parser.add_argument(
        "--output-dir",
        default="data/raw/cve",
        help="Output directory for CVE raw data",
    )

    parser.add_argument(
        "--repo-dir",
        default="data/raw/cve_repo",
        help="Temporary sparse Git repository",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.start_year > args.end_year:
        raise ValueError(
            "start-year must be <= end-year"
        )

    download_cve_years(
        start_year=args.start_year,
        end_year=args.end_year,
        output_dir=Path(args.output_dir),
        temp_repo_dir=Path(args.repo_dir),
    )