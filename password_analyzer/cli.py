import sys
from .core import analyze_password, format_analysis
from .baseline_comparator import compare_password


def main():
    if len(sys.argv) < 2:
        print('Usage: python -m password_analyzer "Password123!"')
        print('   Or: python main.py "Password123!"')
        print('\nExamples to test:')
        print('  python -m password_analyzer "Password123!"')
        print('  python -m password_analyzer "vQ7mK2xR9zP4"')
        print('  python -m password_analyzer "P@ssword2026!"')
        raise SystemExit(1)

    password = sys.argv[1]
    res = analyze_password(password)
    comp = compare_password(password)

    print(format_analysis(res))
    print("\n" + "=" * 50)
    print("ESTABLISHED BASELINE COMPARISON (Task 1 & 7)")
    print("=" * 50)
    print(f"Conventional Score:           {comp.conventional_score:.1f}/100")
    print(f"Existing Estimator:           {comp.existing_estimator_name}")
    print(f"Existing Estimator Score:     {comp.existing_estimator_score}/4 ({comp.existing_estimator_category})")
    print(f"Estimated Crack Time:         {comp.existing_estimator_crack_time_display}")
    if comp.existing_estimator_warning:
        print(f"Estimator Warning:            {comp.existing_estimator_warning}")
    print(f"Proposed MVS:                 {comp.mvs:.1f}/100")
    print(f"Proposed Empirical MVS:       {comp.empirical_mvs:.1f}/100")
    print(f"Proposed PSI:                 {comp.psi:.1f}/100")
    print(f"Calibrated Classification:    {comp.our_classification}")
    print("\n--- Model Assessment Explanation ---")
    print(comp.explanation)
    print("=" * 50)


if __name__ == "__main__":
    main()
