from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
)


TASKS = [
    "AV",
    "AC",
    "PR",
    "UI",
    "S",
    "C",
    "I",
    "A",
]


def load_split(path: Path) -> pd.DataFrame:
    df = pd.read_csv(
        path,
        encoding="utf-8-sig",
    )

    df = df.dropna(
        subset=["description"]
    ).copy()

    df["description"] = (
        df["description"]
        .astype(str)
        .str.strip()
    )

    return df


def evaluate_task(
    y_true,
    y_pred,
) -> dict[str, float]:
    precision, recall, f1, _ = (
        precision_recall_fscore_support(
            y_true,
            y_pred,
            average="macro",
            zero_division=0,
        )
    )

    _, _, weighted_f1, _ = (
        precision_recall_fscore_support(
            y_true,
            y_pred,
            average="weighted",
            zero_division=0,
        )
    )

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    return {
        "accuracy": float(accuracy),
        "macro_precision": float(precision),
        "macro_recall": float(recall),
        "macro_f1": float(f1),
        "weighted_f1": float(weighted_f1),
    }


def train_and_evaluate(
    train_path: Path,
    val_path: Path,
    test_path: Path,
    output_path: Path,
    max_features: int,
) -> None:

    print("[INFO] Loading datasets...")

    train_df = load_split(train_path)
    val_df = load_split(val_path)
    test_df = load_split(test_path)

    print(
        f"[INFO] Train: {len(train_df):,}"
    )
    print(
        f"[INFO] Val:   {len(val_df):,}"
    )
    print(
        f"[INFO] Test:  {len(test_df):,}"
    )

    print()
    print("[INFO] Fitting TF-IDF...")

    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.98,
        max_features=max_features,
        sublinear_tf=True,
    )

    x_train = vectorizer.fit_transform(
        train_df["description"]
    )

    x_val = vectorizer.transform(
        val_df["description"]
    )

    x_test = vectorizer.transform(
        test_df["description"]
    )

    print(
        f"[INFO] TF-IDF vocabulary: "
        f"{len(vectorizer.vocabulary_):,}"
    )

    print(
        f"[INFO] Train matrix: "
        f"{x_train.shape}"
    )

    results = {}

    for task in TASKS:
        print()
        print(
            f"========== TASK {task} =========="
        )

        y_train = train_df[task].astype(str)
        y_val = val_df[task].astype(str)
        y_test = test_df[task].astype(str)

        model = LogisticRegression(
            max_iter=1000,
            solver="lbfgs",
            class_weight="balanced",
            random_state=42,
        )

        print(
            f"[INFO] Training {task}..."
        )

        model.fit(
            x_train,
            y_train,
        )

        val_pred = model.predict(
            x_val
        )

        test_pred = model.predict(
            x_test
        )

        val_metrics = evaluate_task(
            y_val,
            val_pred,
        )

        test_metrics = evaluate_task(
            y_test,
            test_pred,
        )

        results[task] = {
            "val": val_metrics,
            "test": test_metrics,
        }

        print(
            f"Val  Macro-F1: "
            f"{val_metrics['macro_f1']:.4f}"
        )

        print(
            f"Test Macro-F1: "
            f"{test_metrics['macro_f1']:.4f}"
        )

        print(
            f"Test Accuracy: "
            f"{test_metrics['accuracy']:.4f}"
        )

    test_macro_f1_mean = sum(
        results[task]["test"]["macro_f1"]
        for task in TASKS
    ) / len(TASKS)

    val_macro_f1_mean = sum(
        results[task]["val"]["macro_f1"]
        for task in TASKS
    ) / len(TASKS)

    summary = {
        "model": "tfidf_logistic_regression_balanced",
        "tasks": TASKS,
        "tfidf": {
            "ngram_range": [1, 2],
            "min_df": 2,
            "max_df": 0.98,
            "max_features": max_features,
            "sublinear_tf": True,
        },
        "validation_mean_macro_f1": (
            val_macro_f1_mean
        ),
        "test_mean_macro_f1": (
            test_macro_f1_mean
        ),
        "results": results,
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            summary,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print()
    print(
        "========== FINAL SUMMARY =========="
    )

    print(
        f"Validation mean Macro-F1: "
        f"{val_macro_f1_mean:.4f}"
    )

    print(
        f"Test mean Macro-F1:       "
        f"{test_macro_f1_mean:.4f}"
    )

    print()
    print(
        f"Results saved to: "
        f"{output_path}"
    )

    print(
        "==================================="
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Train TF-IDF + Logistic Regression "
            "baseline for CVSS v3.1 classification"
        )
    )

    parser.add_argument(
        "--train",
        default=(
            "data/splits/"
            "cvss_v31/train.csv"
        ),
    )

    parser.add_argument(
        "--val",
        default=(
            "data/splits/"
            "cvss_v31/val.csv"
        ),
    )

    parser.add_argument(
        "--test",
        default=(
            "data/splits/"
            "cvss_v31/test.csv"
        ),
    )

    parser.add_argument(
        "--output",
        default=(
            "outputs/classical/"
            "tfidf_lr_balanced_results.json"
        ),
    )

    parser.add_argument(
        "--max-features",
        type=int,
        default=100000,
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    train_and_evaluate(
        train_path=Path(args.train),
        val_path=Path(args.val),
        test_path=Path(args.test),
        output_path=Path(args.output),
        max_features=args.max_features,
    )