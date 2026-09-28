import math
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

# Small educational dictionary. For the research version, replace/extend this
# with a properly licensed dataset.
COMMON_WORDS = {
    "password", "admin", "welcome", "qwerty", "letmein", "monkey",
    "dragon", "football", "iloveyou", "hello", "login", "master",
    "summer", "winter", "spring", "autumn", "computer", "security",
    "india", "kerala", "college", "student", "secret", "pass",
}

# Common leetspeak substitutions used by the mutation detector.
SUBSTITUTIONS = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "@": "a",
    "$": "s",
    "5": "s",
    "7": "t",
}

DEFAULT_WEIGHTS = {
    "capitalization": 0.15,
    "substitution": 0.20,
    "numeric_suffix": 0.20,
    "symbol_suffix": 0.10,
    "dictionary_base": 0.35,
}

# Empirical probabilities from Phase 3 dataset (n_dictionary=105, n_total=330)
# Laplace-smoothed empirical frequencies: p_hat = (k + 1) / (n + 2)
DEFAULT_EMPIRICAL_PROBABILITIES: Dict[str, float] = {
    "capitalization": 46 / 107,     # ~0.42990654
    "substitution": 46 / 107,       # ~0.42990654
    "numeric_suffix": 31 / 107,     # ~0.28971963
    "symbol_suffix": 31 / 107,      # ~0.28971963
    "dictionary_base": 106 / 332,   # ~0.31927711
}

# Information content / Surprisal in bits: I = -log2(p_hat)
DEFAULT_SURPRISAL_BITS: Dict[str, float] = {
    key: -math.log2(p) for key, p in DEFAULT_EMPIRICAL_PROBABILITIES.items()
}

# Phase 4 Weight Sensitivity Profiles
WEIGHT_PROFILES: Dict[str, Dict[str, float]] = {
    "Baseline": {
        "capitalization": 0.15,
        "substitution": 0.20,
        "numeric_suffix": 0.20,
        "symbol_suffix": 0.10,
        "dictionary_base": 0.35,
    },
    "Dictionary-heavy": {
        "capitalization": 0.10,
        "substitution": 0.15,
        "numeric_suffix": 0.15,
        "symbol_suffix": 0.10,
        "dictionary_base": 0.50,
    },
    "Mutation-heavy": {
        "capitalization": 0.20,
        "substitution": 0.25,
        "numeric_suffix": 0.25,
        "symbol_suffix": 0.10,
        "dictionary_base": 0.20,
    },
    "Equal": {
        "capitalization": 0.20,
        "substitution": 0.20,
        "numeric_suffix": 0.20,
        "symbol_suffix": 0.20,
        "dictionary_base": 0.20,
    },
    "Suffix-heavy": {
        "capitalization": 0.15,
        "substitution": 0.10,
        "numeric_suffix": 0.30,
        "symbol_suffix": 0.20,
        "dictionary_base": 0.25,
    },
}

# Phase 5 Held-out Calibration parameters
CALIBRATED_H_REF: float = 50.0
CALIBRATED_PSI_THRESHOLD: float = 69.0


@dataclass
class PasswordAnalysis:
    password_length: int
    character_set_size: int
    search_space: int
    entropy_bits: float
    character_types: Dict[str, bool]
    dictionary_base: Optional[str]
    mutations: List[str]
    mutation_components: Dict[str, float]
    mvs: float
    entropy_normalized: float
    psi: float
    risk_category: str
    empirical_probabilities: Dict[str, float]
    surprisal_bits: Dict[str, float]
    empirical_mvs: float
    empirical_psi: float
    calibrated_psi: float
    calibrated_classification: str


def character_set_size(password: str) -> int:
    """Return the size of the character pool implied by the password."""
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32  # project assumption for printable symbols
    return size


def entropy(password: str) -> float:
    n = character_set_size(password)
    if not password or n == 0:
        return 0.0
    return len(password) * math.log2(n)


def normalize_substitutions(password: str) -> str:
    return "".join(SUBSTITUTIONS.get(c, c.lower()) for c in password)


def find_dictionary_base(password: str) -> Optional[str]:
    lower = password.lower()

    # Direct match or a dictionary word embedded in a password.
    for word in sorted(COMMON_WORDS, key=len, reverse=True):
        if word in lower:
            return word

    # Try reversing common substitutions.
    normalized = normalize_substitutions(password)
    for word in sorted(COMMON_WORDS, key=len, reverse=True):
        if word in normalized:
            return word

    return None


def detect_mutations(password: str, dictionary_base: Optional[str]) -> List[str]:
    mutations: List[str] = []

    if dictionary_base:
        base = dictionary_base
        normalized = normalize_substitutions(password)
        if password != password.lower() and (base in password.lower() or base in normalized):
            mutations.append("capitalization")

        if base not in password.lower() and base in normalized:
            mutations.append("character substitution")

        # Digits after a dictionary-like base (optionally followed by symbols).
        if re.search(r"\d+([!@#$%^&*?]+)?$", password):
            mutations.append("numeric suffix")

        # Common symbol addition.
        if re.search(r"[!@#$%^&*?]+$", password):
            mutations.append("symbol suffix")

    return mutations


def mutation_components(password: str, dictionary_base: Optional[str]) -> Dict[str, float]:
    lower = password.lower()
    normalized = normalize_substitutions(password)

    dictionary_score = 1.0 if dictionary_base else 0.0

    capitalization_score = 0.0
    if dictionary_base and (dictionary_base in lower or dictionary_base in normalized):
        # Title case / first-letter capitalization is especially predictable.
        if password == password[0].upper() + password[1:]:
            capitalization_score = 1.0
        elif any(c.isupper() for c in password):
            capitalization_score = 0.7

    substitution_score = 0.0
    if dictionary_base and dictionary_base not in lower and dictionary_base in normalized:
        substitution_score = 1.0

    numeric_score = 1.0 if (dictionary_base and re.search(r"\d+([!@#$%^&*?]+)?$", password)) else 0.0
    symbol_score = 1.0 if (dictionary_base and re.search(r"[!@#$%^&*?]+$", password)) else 0.0

    return {
        "capitalization": capitalization_score,
        "substitution": substitution_score,
        "numeric_suffix": numeric_score,
        "symbol_suffix": symbol_score,
        "dictionary_base": dictionary_score,
    }


def calculate_mvs(components: Dict[str, float],
                  weights: Optional[Dict[str, float]] = None) -> float:
    weights = weights or DEFAULT_WEIGHTS
    total_weight = sum(weights.values())
    if total_weight <= 0:
        raise ValueError("Weights must sum to a positive value.")

    # Normalize weights so experimentation can safely use arbitrary positive weights.
    normalized_weights = {
        key: value / total_weight for key, value in weights.items()
    }
    score = sum(components.get(key, 0.0) * normalized_weights.get(key, 0.0)
                for key in components)
    return 100.0 * score


def calculate_empirical_mvs(components: Dict[str, float],
                            weights: Optional[Dict[str, float]] = None,
                            probabilities: Optional[Dict[str, float]] = None) -> float:
    """Calculate empirical Mutation Vulnerability Score (MVS_emp).

    Formula: MVS_emp = 100 * [sum(w_i * p_hat_i * x_i)] / [sum(w_i * x_i)]
    If no pattern is active (e.g. random controls without dictionary base),
    returns 0.0.
    """
    weights = weights or DEFAULT_WEIGHTS
    probabilities = probabilities or DEFAULT_EMPIRICAL_PROBABILITIES

    weighted_p_sum = 0.0
    active_weight_sum = 0.0

    for key, score in components.items():
        if score > 0.0:
            w = weights.get(key, 0.0)
            p = probabilities.get(key, 0.0)
            weighted_p_sum += w * p * score
            active_weight_sum += w * score

    if active_weight_sum <= 0.0:
        return 0.0

    return 100.0 * (weighted_p_sum / active_weight_sum)


def calculate_psi(h_bits: float, mvs: float, h_ref: float = 80.0) -> float:
    """Experimental combined score.

    h_ref is a project parameter, not a universal security threshold.
    """
    if h_ref <= 0:
        raise ValueError("h_ref must be positive.")
    e_norm = min(h_bits / h_ref, 1.0)
    return max(0.0, min(100.0, 100.0 * e_norm * (1.0 - mvs / 100.0)))


def evaluate_calibrated_psi(h_bits: float,
                            mvs: float,
                            h_ref: float = CALIBRATED_H_REF,
                            threshold: float = CALIBRATED_PSI_THRESHOLD) -> Tuple[float, str]:
    """Evaluate PSI under the Phase 5 calibrated parameter set (H_ref=50, threshold=69.0).

    Returns (calibrated_psi, classification_label).
    """
    calibrated_psi = calculate_psi(h_bits, mvs, h_ref)
    if calibrated_psi >= threshold:
        classification = "Low Vulnerability (Synthetic Random-like Control)"
    else:
        classification = "Predictable Mutation (Vulnerable Family)"
    return calibrated_psi, classification


def risk_category(psi: float) -> str:
    if psi < 25:
        return "High predictability risk"
    if psi < 50:
        return "Moderate predictability risk"
    if psi < 75:
        return "Moderate security"
    return "Higher security"


def analyze_password(password: str,
                     weights: Optional[Dict[str, float]] = None,
                     h_ref: float = 80.0,
                     probabilities: Optional[Dict[str, float]] = None) -> PasswordAnalysis:
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    n = character_set_size(password)
    L = len(password)
    search_space = n ** L if n > 0 else 0
    h = entropy(password)

    types = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() for c in password),
    }

    base = find_dictionary_base(password)
    mutations = detect_mutations(password, base)
    components = mutation_components(password, base)
    mvs = calculate_mvs(components, weights)
    e_norm = min(h / h_ref, 1.0) if h_ref > 0 else 0.0
    psi = calculate_psi(h, mvs, h_ref)

    # Phase 3 Empirical Probability Model
    probs = probabilities or DEFAULT_EMPIRICAL_PROBABILITIES
    surprisal = {key: -math.log2(p) for key, p in probs.items()}
    emp_mvs = calculate_empirical_mvs(components, weights, probs)
    emp_psi = calculate_psi(h, emp_mvs, h_ref)

    # Phase 5 Calibrated Held-out Evaluation
    cal_psi, cal_class = evaluate_calibrated_psi(h, emp_mvs)

    return PasswordAnalysis(
        password_length=L,
        character_set_size=n,
        search_space=search_space,
        entropy_bits=h,
        character_types=types,
        dictionary_base=base,
        mutations=mutations,
        mutation_components=components,
        mvs=mvs,
        entropy_normalized=e_norm,
        psi=psi,
        risk_category=risk_category(psi),
        empirical_probabilities=probs,
        surprisal_bits=surprisal,
        empirical_mvs=emp_mvs,
        empirical_psi=emp_psi,
        calibrated_psi=cal_psi,
        calibrated_classification=cal_class,
    )


def format_analysis(result: PasswordAnalysis) -> str:
    data = asdict(result)
    lines = [
        "=== Password Mutation Analysis ===",
        f"Length: {data['password_length']}",
        f"Character-set size: {data['character_set_size']}",
        f"Search space: {data['search_space']:,}",
        f"Entropy: {data['entropy_bits']:.2f} bits",
        f"Dictionary base: {data['dictionary_base'] or 'Not detected'}",
        f"Mutations: {', '.join(data['mutations']) or 'None detected'}",
        "",
        "--- Baseline Fixed-Weights Model (Phase 1-2) ---",
        f"MVS: {data['mvs']:.2f}/100",
        f"Normalized entropy: {data['entropy_normalized']:.3f}",
        f"PSI: {data['psi']:.2f}/100",
        f"Risk category: {data['risk_category']}",
        "",
        "--- Empirical Probability Model (Phase 3) ---",
        f"Empirical MVS: {data['empirical_mvs']:.2f}/100",
        f"Empirical PSI: {data['empirical_psi']:.2f}/100",
        "",
        "--- Phase 5 Calibrated Held-out Evaluation ---",
        f"Calibrated PSI (H_ref={CALIBRATED_H_REF:.0f}): {data['calibrated_psi']:.2f}/100",
        f"Decision Threshold: {CALIBRATED_PSI_THRESHOLD:.1f}",
        f"Classification: {data['calibrated_classification']}",
    ]
    return "\n".join(lines)
