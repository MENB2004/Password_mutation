import math
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import pandas as pd

from .core import (
    analyze_password,
    DEFAULT_WEIGHTS,
    CALIBRATED_H_REF,
    CALIBRATED_PSI_THRESHOLD,
    character_set_size,
    entropy,
)

# Optional local zxcvbn import with graceful fallback
try:
    import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    zxcvbn = None
    HAS_ZXCVBN = False

ZXCVBN_SCORE_CATEGORIES = {
    0: "Very Weak (Too guessable)",
    1: "Weak (Very guessable)",
    2: "Fair (Somewhat guessable)",
    3: "Good (Safely unguessable)",
    4: "Strong (Very unguessable)",
}


@dataclass
class BaselineComparison:
    """Comparison record between conventional entropy, existing estimator (zxcvbn),

    and the proposed MVS / PSI framework.
    """
    password: str
    length: int
    character_pool: int
    entropy: float
    conventional_score: float
    mvs: float
    empirical_mvs: float
    psi: float
    empirical_psi: float
    calibrated_psi: float
    our_classification: str
    existing_estimator_name: str
    existing_estimator_score: int          # 0-4
    existing_estimator_normalized: float   # 0-100 (score * 25.0)
    existing_estimator_guesses_log10: float
    existing_estimator_crack_time_display: str
    existing_estimator_category: str
    existing_estimator_warning: Optional[str]
    existing_estimator_suggestions: List[str]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_existing_estimator_assessment(password: str) -> Dict[str, Any]:
    """Obtain a local assessment using Dropbox zxcvbn without making network calls.

    If zxcvbn is not installed, returns a heuristic fallback.
    """
    if HAS_ZXCVBN and zxcvbn is not None:
        res = zxcvbn.zxcvbn(password)
        score = int(res.get("score", 0))
        guesses = float(res.get("guesses", 1))
        guesses_log10 = float(res.get("guesses_log10", math.log10(max(1.0, guesses))))
        crack_times = res.get("crack_times_display", {})
        crack_time = crack_times.get(
            "offline_slow_hashing_1e4_per_second",
            crack_times.get("online_no_throttling_10_per_second", "instant")
        )
        feedback = res.get("feedback", {})
        warning = feedback.get("warning") or None
        suggestions = feedback.get("suggestions") or []
        category = ZXCVBN_SCORE_CATEGORIES.get(score, "Unknown")
        return {
            "name": "Dropbox zxcvbn",
            "score": score,
            "normalized": float(score * 25.0),
            "guesses_log10": guesses_log10,
            "crack_time": str(crack_time),
            "category": category,
            "warning": warning,
            "suggestions": suggestions,
        }

    # Heuristic fallback if zxcvbn library is absent
    pool = character_set_size(password)
    h = entropy(password)
    score = min(4, max(0, int(h // 20)))
    return {
        "name": "Heuristic Estimator (zxcvbn not installed)",
        "score": score,
        "normalized": float(score * 25.0),
        "guesses_log10": h * 0.30103,
        "crack_time": "Estimated offline",
        "category": ZXCVBN_SCORE_CATEGORIES.get(score, "Unknown"),
        "warning": None,
        "suggestions": ["Install zxcvbn for full dictionary matching."],
    }


def generate_explanation(analysis, est_res: Dict[str, Any]) -> str:
    """Generate a human-readable scientific explanation of why the password received its score."""
    p = analysis.dictionary_base
    muts = analysis.mutations
    h = analysis.entropy_bits

    if p or muts or analysis.mvs > 0:
        base_desc = f"dictionary root '{p}'" if p else "predictable structural pattern"
        mut_desc = f"alongside predictable mutations ({', '.join(muts)})" if muts else "with no subsequent mutations"
        return (
            f"Although this password achieves a theoretical Shannon entropy of {h:.2f} bits, "
            f"the detection of {base_desc} {mut_desc} "
            f"increases its Mutation Vulnerability Score (MVS: {analysis.mvs:.1f}/100). "
            f"Consequently, the Password Security Index discounts the score to {analysis.psi:.1f}/100 "
            f"({analysis.risk_category}). Existing estimator ({est_res['name']}) scores it "
            f"{est_res['score']}/4 ('{est_res['category']}')."
        )
    elif analysis.password_length < 8:
        return (
            f"This password is critically short ({analysis.password_length} characters). "
            f"Regardless of character diversity, short passwords have an exhausted search space "
            f"and can be rapidly brute-forced. It achieves {h:.2f} bits of theoretical entropy and PSI: {analysis.psi:.1f}/100 "
            f"({analysis.risk_category}). Existing estimator ({est_res['name']}) scores it "
            f"{est_res['score']}/4 ('{est_res['category']}')."
        )
    else:
        return (
            f"No dictionary base was detected in this password. The password exhibits non-predictable, "
            f"pseudo-random character distribution, receiving an MVS of {analysis.mvs:.1f}/100. "
            f"Its security is primarily governed by character pool diversity and length, "
            f"yielding PSI: {analysis.psi:.1f}/100 ({analysis.risk_category}). "
            f"Existing estimator ({est_res['name']}) scores it {est_res['score']}/4 ('{est_res['category']}')."
        )


def compare_password(password: str,
                     weights: Optional[Dict[str, float]] = None,
                     h_ref: float = 80.0) -> BaselineComparison:
    """Compare a single password across Conventional Entropy, Existing Estimator (zxcvbn),

    Proposed MVS, and Proposed PSI.
    """
    analysis = analyze_password(password, weights=weights, h_ref=h_ref)
    est_res = get_existing_estimator_assessment(password)

    # Conventional length/diversity score (0-100)
    # Conventional meters award ~25 points for length >=8, and ~25 per character class
    types_count = sum(1 for v in analysis.character_types.values() if v)
    len_pts = min(25.0, (analysis.password_length / 12.0) * 25.0)
    class_pts = (types_count / 4.0) * 75.0
    conv_score = min(100.0, len_pts + class_pts)

    explanation = generate_explanation(analysis, est_res)

    return BaselineComparison(
        password=password,
        length=analysis.password_length,
        character_pool=analysis.character_set_size,
        entropy=round(analysis.entropy_bits, 2),
        conventional_score=round(conv_score, 1),
        mvs=round(analysis.mvs, 1),
        empirical_mvs=round(analysis.empirical_mvs, 1),
        psi=round(analysis.psi, 1),
        empirical_psi=round(analysis.empirical_psi, 1),
        calibrated_psi=round(analysis.calibrated_psi, 1),
        our_classification=analysis.calibrated_classification,
        existing_estimator_name=est_res["name"],
        existing_estimator_score=est_res["score"],
        existing_estimator_normalized=round(est_res["normalized"], 1),
        existing_estimator_guesses_log10=round(est_res["guesses_log10"], 2),
        existing_estimator_crack_time_display=est_res["crack_time"],
        existing_estimator_category=est_res["category"],
        existing_estimator_warning=est_res["warning"],
        existing_estimator_suggestions=est_res["suggestions"],
        explanation=explanation,
    )


def compare_benchmark_passwords(weights: Optional[Dict[str, float]] = None,
                                h_ref: float = 80.0) -> List[BaselineComparison]:
    """Compare the three canonical benchmark passwords:

    1. 'Password123!' (Predictable suffix mutation)
    2. 'vQ7mK2xR9zP4' (Random-like control)
    3. 'P@ssword2026!' (Complex combination mutation)
    """
    benchmarks = ["Password123!", "vQ7mK2xR9zP4", "P@ssword2026!"]
    return [compare_password(pw, weights=weights, h_ref=h_ref) for pw in benchmarks]


def build_comparison_dataframe(comparisons: List[BaselineComparison]) -> pd.DataFrame:
    """Build a structured pandas DataFrame summarizing comparison metrics."""
    rows = []
    for c in comparisons:
        rows.append({
            "Password": c.password,
            "Length": c.length,
            "Pool (N)": c.character_pool,
            "Entropy (H bits)": c.entropy,
            "Conventional Score": c.conventional_score,
            "Proposed MVS": c.mvs,
            "Empirical MVS": c.empirical_mvs,
            "Proposed PSI": c.psi,
            "Empirical PSI": c.empirical_psi,
            "Calibrated PSI (H_ref=50)": c.calibrated_psi,
            "Existing Estimator (Score)": f"{c.existing_estimator_score}/4 ({c.existing_estimator_category})",
            "Existing Estimator Crack Time": c.existing_estimator_crack_time_display,
            "Proposed Classification": c.our_classification,
        })
    return pd.DataFrame(rows)
