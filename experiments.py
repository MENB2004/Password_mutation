import argparse
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from password_analyzer.experiment_runner import run_baseline_comparison_experiment
from password_analyzer.dataset_pipeline import (
    import_research_dataset,
    create_example_public_research_dataset,
)


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength & Predictable Mutation Analysis — Research Experiments Runner"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="data/synthetic_password_dataset_phase3.csv",
        help="Path to synthetic dataset CSV (default: data/synthetic_password_dataset_phase3.csv)",
    )
    parser.add_argument(
        "--outdir",
        type=str,
        default="results",
        help="Output directory for generated results, tables, and figures (default: results)",
    )
    parser.add_argument(
        "--import-public-dataset",
        type=str,
        default=None,
        help="Optional path to a public/research dataset CSV to analyze with privacy-preserving aggregation",
    )
    parser.add_argument(
        "--create-public-example",
        action="store_true",
        help="Generate an example public/research dataset file at data/public_research_dataset_example.csv",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("PASSWORD STRENGTH & PREDICTABLE MUTATION ANALYSIS — EXPERIMENTAL SUITE")
    print("=" * 80)

    if args.create_public_example:
        path = create_example_public_research_dataset("data/public_research_dataset_example.csv")
        print(f"[+] Created example public research dataset schema at: {path}")

    if args.import_public_dataset:
        print(f"\n[*] Importing public research dataset: {args.import_public_dataset}")
        report = import_research_dataset(args.import_public_dataset)
        print("\n--- Privacy-Preserving Aggregate Telemetry ---")
        print(report.summary_table().to_string(index=False))
        return

    print(f"\n[*] Running baseline comparison experiment using dataset: {args.dataset}")
    print(f"[*] Artifacts will be saved to: {args.outdir}/")

    df_comp, stats = run_baseline_comparison_experiment(
        dataset_path=args.dataset,
        output_dir=args.outdir,
    )

    print(f"\n[+] Successfully evaluated {len(df_comp)} passwords across all 5 models.")
    print("\n--- Model Benchmark Performance Summary ---")
    headers = ["Method", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "PR-AUC"]
    print(f"{headers[0]:<25} {headers[1]:<10} {headers[2]:<10} {headers[3]:<10} {headers[4]:<10} {headers[5]:<10} {headers[6]:<10}")
    print("-" * 85)
    for method, m in stats.items():
        print(
            f"{method:<25} {m['Accuracy']:<10.4f} {m['Precision']:<10.4f} {m['Recall']:<10.4f} "
            f"{m['F1-Score']:<10.4f} {m['ROC-AUC']:<10.4f} {m['Average Precision']:<10.4f}"
        )

    print("\n--- Generated Files ---")
    print(f" - CSV Results: {args.outdir}/baseline_comparison.csv")
    print(f" - Formal Report: {args.outdir}/BASELINE_COMPARISON_REPORT.md")
    print(f" - Graphs: {args.outdir}/baseline_*.png (8 publication figures)")
    print("\nExperiment run completed successfully.")


if __name__ == "__main__":
    main()
