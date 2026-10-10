"""Core mathematical modeling and mutation analysis engine for password security.

Formulations:
  - Theoretical search space: S = N^L
  - Shannon entropy: H = L * log2(N)
  - Normalized entropy: E_norm = min(H / H_ref, 1.0)
  - Mutation Vulnerability Score: MVS = 100 * sum(w_i * x_i)
  - Laplace-smoothed empirical frequency: p_hat = (k + 1) / (n + 2)
  - Information surprisal (bits): I = -log2(p_hat)
  - Empirical MVS: MVS_emp = 100 * [sum(w_i * p_hat_i * x_i)] / [sum(w_i * x_i)]
  - Password Security Index: PSI = 100 * E_norm * (1 - MVS / 100)
  - Held-out Decision Rule: Vulnerable if Calibrated PSI < 69.0 (at H_ref = 50.0)

IMPORTANT SCIENTIFIC DISCLAIMER:
  Theoretical Shannon entropy assumes uniform independent random character selection.
  It reflects the maximum theoretical search space under brute-force assumptions, NOT
  actual resistance against targeted dictionary or rule-based cracking attacks.
"""

import math
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

# Curated reference dictionary of common root words, names, concepts, and seasons.
# Educational reference corpus; for research version, can be extended with licensed lists.
COMMON_WORDS = {
    # Core roots
    "password", "admin", "welcome", "qwerty", "letmein", "monkey",
    "dragon", "football", "iloveyou", "hello", "login", "master",
    "summer", "winter", "spring", "autumn", "computer", "security",
    "india", "kerala", "college", "student", "secret", "pass",
    # Common English words and root words
    "simple", "sample", "test", "testing", "user", "access", "account",
    "default", "system", "service", "internet", "online", "network",
    "baseball", "basketball", "soccer", "hockey", "tennis", "champion", "winner",
    "banana", "apple", "orange", "lemon", "cherry", "coffee", "cookie",
    "sunshine", "shadow", "super", "secure", "trust", "change",
    "friend", "family", "school", "office", "worker", "player",
    "flower", "matrix", "galaxy", "space", "number", "letter",
    "keyboard", "monitor", "screen", "mobile", "phone", "device",
    "tiger", "tigger", "lion", "animal", "monster", "batman", "superman",
    "princess", "queen", "king", "prince", "angel", "devil", "heaven",
    "money", "silver", "golden", "diamond", "crystal", "carmen", "mickey",
    "america", "canada", "london", "paris", "japan", "brazil",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "cat", "dog", "love",
}

# Common leetspeak substitutions mapped to normalized lowercase letters
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

# Baseline convex mutation weights (sum = 1.0)
DEFAULT_WEIGHTS: Dict[str, float] = {
    "capitalization": 0.15,
    "substitution": 0.20,
    "numeric_suffix": 0.20,
    "symbol_suffix": 0.10,
    "dictionary_base": 0.35,
}


def empirical_probability(k: int, n: int) -> float:
    """Calculate Laplace-smoothed empirical probability: p_hat = (k + 1) / (n + 2).

    Parameters:
      k: Observed count of the feature (must be non-negative integer <= n).
      n: Total sample size (must be non-negative integer).

    Returns:
      p_hat: Probability strictly in the open interval (0, 1).
    """
    if not isinstance(k, int) or not isinstance(n, int):
        raise TypeError("Counts k and n must be integers.")
    if n < 0:
        raise ValueError(f"Sample size n must be non-negative, got {n}.")
    if k < 0:
        raise ValueError(f"Observed count k must be non-negative, got {k}.")
    if k > n:
        raise ValueError(f"Observed count k ({k}) cannot exceed sample size n ({n}).")
    return (k + 1) / (n + 2)


def surprisal(p: float) -> float:
    """Calculate information content / surprisal in bits: I = -log2(p).

    Parameters:
      p: Probability in the interval (0, 1].

    Returns:
      Information content in bits (>= 0.0).
    """
    if not isinstance(p, (int, float)):
        raise TypeError("Probability p must be a float or int.")
    if math.isnan(p) or math.isinf(p) or not (0.0 < p <= 1.0):
        raise ValueError(f"Probability p must be in the open-closed interval (0, 1], got {p}.")
    return -math.log2(float(p))


# Empirical probabilities from Phase 3 dataset (n_dictionary=105, n_total=330)
# Derived via Laplace smoothing p_hat = (k + 1) / (n + 2)
DEFAULT_EMPIRICAL_PROBABILITIES: Dict[str, float] = {
    "capitalization": empirical_probability(45, 105),    # 46 / 107 ~ 0.42990654
    "substitution": empirical_probability(45, 105),      # 46 / 107 ~ 0.42990654
    "numeric_suffix": empirical_probability(30, 105),    # 31 / 107 ~ 0.28971963
    "symbol_suffix": empirical_probability(30, 105),     # 31 / 107 ~ 0.28971963
    "dictionary_base": empirical_probability(105, 330),  # 106 / 332 ~ 0.31927711
}

# Information content / Surprisal in bits: I = -log2(p_hat)
DEFAULT_SURPRISAL_BITS: Dict[str, float] = {
    key: surprisal(p) for key, p in DEFAULT_EMPIRICAL_PROBABILITIES.items()
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

# Reference entropy settings
DEFAULT_H_REF: float = 80.0
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
    """Return the size of the character pool implied by the password.

    Character class pool assumptions:
      - Lowercase letters ('a'-'z'): +26
      - Uppercase letters ('A'-'Z'): +26
      - Digits ('0'-'9'):            +10
      - Printable symbols:           +32 (standard ASCII symbol pool)

    Unicode characters:
      - Characters matching islower() add 26 if not already added.
      - Characters matching isupper() add 26 if not already added.
      - Other non-alphanumeric unicode characters add 32 to symbols.
    """
    if not password:
        return 0
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    return size


def entropy(password: str) -> float:
    """Calculate theoretical Shannon entropy in bits under uniform independent selection.

    H = L * log2(N)
    Returns 0.0 if the password is empty or character pool is 0.
    """
    n = character_set_size(password)
    if not password or n <= 0:
        return 0.0
    return len(password) * math.log2(n)


def normalize_substitutions(password: str) -> str:
    """Normalize common leetspeak substitutions to lowercase letters."""
    return "".join(SUBSTITUTIONS.get(c, c.lower()) for c in password)


def detect_repetitive_pattern(password: str) -> bool:
    """Detect if password contains excessive character repetition.

    E.g. 'aaaa', '111111111111', 'abababab'.
    """
    if len(password) < 3:
        return False
    if re.search(r"(.)\1{2,}", password):
        return True
    if len(password) >= 6 and len(set(password.lower())) <= 2:
        return True
    if len(password) >= 4 and len(set(password[i:i+2] for i in range(0, len(password)-1, 2))) <= 1:
        return True
    return False


def detect_sequential_pattern(password: str) -> bool:
    """Detect numeric or alphabetic sequential runs (e.g. '12345', 'abcdef', '98765').

    Requires a run of >= 5 consecutive characters, or >= 3 characters constituting
    at least 50% of the password length. This prevents short random adjacencies
    in long complex passwords from triggering false positives.
    """
    if len(password) < 3:
        return False
    low = password.lower()
    max_run, cur_run = 0, 0
    for i in range(len(low) - 1):
        c1, c2 = low[i], low[i+1]
        digit_seq = c1.isdigit() and c2.isdigit() and (int(c2) == (int(c1) + 1) % 10 or int(c2) == (int(c1) - 1) % 10)
        alpha_seq = c1.isalpha() and c2.isalpha() and (ord(c2) == ord(c1) + 1 or ord(c2) == ord(c1) - 1)
        if digit_seq or alpha_seq:
            cur_run = (cur_run + 1) if cur_run > 0 else 2
            max_run = max(max_run, cur_run)
        else:
            cur_run = 0

    return max_run >= 5 or (len(password) > 0 and max_run >= 3 and (max_run / len(password)) >= 0.5)


def detect_keyboard_pattern(password: str) -> bool:
    """Detect common keyboard spatial walks (e.g. 'qwerty', 'asdfgh', 'zxcvbn')."""
    lower = password.lower()
    walks = [
        "qwerty", "wertyu", "ertyui", "rtyuio", "tyuiop",
        "asdfgh", "sdfghj", "dfghjk", "fghjkl",
        "zxcvbn", "xcvbnm",
        "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
        "qazwsx", "wsxedc", "edcrfv",
    ]
    return any(w in lower for w in walks)


def _match_dictionary_word(target_text: str) -> Optional[str]:
    """Helper to match a word from COMMON_WORDS in target text safely.

    Words of length >= 4 match via substring inclusion.
    Words of length < 4 (e.g. 'cat', 'dog', 'may') match if exact match,
    at string start/end, or bounded by non-letters, preventing false positives
    inside arbitrary random character strings.
    """
    for word in sorted(COMMON_WORDS, key=len, reverse=True):
        if len(word) >= 4 and word in target_text:
            return word
        elif len(word) < 4:
            if target_text == word or target_text.startswith(word) or target_text.endswith(word):
                return word
            if re.search(r"(^|[^a-zA-Z])" + re.escape(word) + r"([^a-zA-Z]|$)", target_text):
                return word
    return None


def find_dictionary_base(password: str) -> Optional[str]:
    """Identify a dictionary root word in the password, if present.

    Inspects the lowercase representation first, then reverses common leetspeak substitutions.
    If no dictionary root is found, returns None. Random-looking strings and unsupported
    dictionary entries safely return None without being falsely classified.
    """
    if not password:
        return None

    lower = password.lower()

    # Direct match or embedded dictionary word
    direct_match = _match_dictionary_word(lower)
    if direct_match:
        return direct_match

    # Reversing common leetspeak substitutions
    normalized = normalize_substitutions(password)
    normalized_match = _match_dictionary_word(normalized)
    if normalized_match:
        return normalized_match

    return None


def mutation_components(password: str, dictionary_base: Optional[str]) -> Dict[str, float]:
    """Extract quantitative indicators x_i in [0.0, 1.0] for the 5 baseline features.

    Features:
      1. dictionary_base:  1.0 if dictionary base or trivial pattern is detected, else 0.0.
      2. capitalization:   1.0 if TitleCase / first-letter capital, 0.7 if mixed-case, else 0.0.
      3. substitution:     1.0 if leetspeak substitution applied to base, else 0.0.
      4. numeric_suffix:   1.0 if digits appended after base before optional symbols, else 0.0.
      5. symbol_suffix:    1.0 if punctuation / symbols appended at end of base, else 0.0.

    CRITICAL MODELING RULE:
      If NO dictionary base or trivial pattern is present, all mutation indicators are 0.0.
      Random character diversity (uppercase letters, digits, symbols) is NOT penalized.
    """
    if not password:
        return {
            "capitalization": 0.0,
            "substitution": 0.0,
            "numeric_suffix": 0.0,
            "symbol_suffix": 0.0,
            "dictionary_base": 0.0,
        }

    lower = password.lower()
    normalized = normalize_substitutions(password)

    has_trivial_pattern = (
        detect_repetitive_pattern(password) or
        detect_sequential_pattern(password) or
        detect_keyboard_pattern(password)
    )

    dictionary_score = 1.0 if (dictionary_base or has_trivial_pattern) else 0.0

    # 1. Capitalization (assessed relative to recognized base)
    capitalization_score = 0.0
    if dictionary_base:
        idx = lower.find(dictionary_base)
        if idx < 0:
            idx = normalized.find(dictionary_base)

        if idx >= 0:
            base_slice = password[idx:idx + len(dictionary_base)]
            letters = [c for c in base_slice if c.isalpha()]
            if letters:
                if letters[0].isupper() and all(c.islower() for c in letters[1:]):
                    capitalization_score = 1.0
                elif any(c.isupper() for c in letters) and any(c.islower() for c in letters):
                    capitalization_score = 0.7
        elif any(c.isupper() for c in password) and any(c.islower() for c in password):
            if password[0].isupper() and any(c.islower() for c in password[1:]):
                capitalization_score = 1.0
            else:
                capitalization_score = 0.7

    # 2. Character substitution (leetspeak on dictionary base)
    substitution_score = 0.0
    if dictionary_base and dictionary_base not in lower and dictionary_base in normalized:
        substitution_score = 1.0

    # 3. Numeric suffix (digits appended after base, before optional trailing symbols)
    numeric_score = 0.0
    symbol_match = re.search(r"[^a-zA-Z0-9]+$", password)
    without_symbols = password[:symbol_match.start()] if symbol_match else password

    if dictionary_base:
        low = without_symbols.lower()
        idx = low.find(dictionary_base)
        if idx < 0:
            norm = normalize_substitutions(without_symbols)
            idx = norm.find(dictionary_base)
        if idx >= 0:
            after_base = without_symbols[idx + len(dictionary_base):]
            if re.search(r"\d+$", after_base):
                numeric_score = 1.0
    elif has_trivial_pattern:
        # For trivial structural patterns (e.g. keyboard walk "qwerty123"), check if digits follow letters
        if re.search(r"[a-zA-Z]\d+$", without_symbols):
            numeric_score = 1.0

    # 4. Symbol suffix (trailing punctuation / symbols at end of password)
    symbol_score = 0.0
    if (dictionary_base or has_trivial_pattern) and symbol_match:
        symbol_score = 1.0

    return {
        "capitalization": capitalization_score,
        "substitution": substitution_score,
        "numeric_suffix": numeric_score,
        "symbol_suffix": symbol_score,
        "dictionary_base": dictionary_score,
    }


def detect_mutations(password: str, dictionary_base: Optional[str]) -> List[str]:
    """Detect qualitative human-interpretable mutation labels.

    Guaranteed 1-to-1 consistency with mutation_components():
      - 'capitalization' in mutations <==> mutation_components['capitalization'] > 0
      - 'character substitution' in mutations <==> mutation_components['substitution'] > 0
      - 'numeric suffix' in mutations <==> mutation_components['numeric_suffix'] > 0
      - 'symbol suffix' in mutations <==> mutation_components['symbol_suffix'] > 0
    Plus structural pattern tags if present ('repetitive characters', etc.).
    """
    if not password:
        return []

    comps = mutation_components(password, dictionary_base)
    mutations: List[str] = []

    if comps["capitalization"] > 0.0:
        mutations.append("capitalization")
    if comps["substitution"] > 0.0:
        mutations.append("character substitution")
    if comps["numeric_suffix"] > 0.0:
        mutations.append("numeric suffix")
    if comps["symbol_suffix"] > 0.0:
        mutations.append("symbol suffix")

    # Structural / repetitive patterns
    if detect_repetitive_pattern(password):
        mutations.append("repetitive characters")
    if detect_sequential_pattern(password):
        mutations.append("sequential characters")
    if detect_keyboard_pattern(password):
        mutations.append("keyboard sequence")

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for m in mutations:
        if m not in seen:
            seen.add(m)
            deduped.append(m)
    return deduped


def calculate_mvs(components: Dict[str, float],
                  weights: Optional[Dict[str, float]] = None) -> float:
    """Calculate the Mutation Vulnerability Score (MVS) in [0.0, 100.0].

    MVS = 100 * sum(w_i * x_i)

    Validates that weights are non-empty, non-negative, and sum to a positive finite value.
    Normalizes weights so custom weight sets sum safely to 1.0.
    """
    if weights is not None and len(weights) == 0:
        raise ValueError("Weights dictionary cannot be empty.")
    weights = DEFAULT_WEIGHTS if weights is None else weights
    if any(w < 0 for w in weights.values()):
        raise ValueError("Weights must be non-negative.")
    total_weight = sum(weights.values())
    if total_weight <= 0 or math.isnan(total_weight) or math.isinf(total_weight):
        raise ValueError("Weights must sum to a positive finite value.")

    normalized_weights = {
        key: value / total_weight for key, value in weights.items()
    }
    score = sum(max(0.0, min(1.0, components.get(key, 0.0))) * normalized_weights.get(key, 0.0)
                for key in normalized_weights)
    return max(0.0, min(100.0, 100.0 * score))


def calculate_empirical_mvs(components: Dict[str, float],
                            weights: Optional[Dict[str, float]] = None,
                            probabilities: Optional[Dict[str, float]] = None) -> float:
    """Calculate empirical Mutation Vulnerability Score (MVS_emp) in [0.0, 100.0].

    Formula: MVS_emp = 100 * [sum(w_i * p_hat_i * x_i)] / [sum(w_i * x_i)]
    If no pattern is active (e.g. random controls without dictionary base),
    returns 0.0.
    """
    if weights is not None and len(weights) == 0:
        raise ValueError("Weights dictionary cannot be empty.")
    weights = DEFAULT_WEIGHTS if weights is None else weights
    probabilities = probabilities or DEFAULT_EMPIRICAL_PROBABILITIES
    if any(w < 0 for w in weights.values()):
        raise ValueError("Weights must be non-negative.")

    weighted_p_sum = 0.0
    active_weight_sum = 0.0

    for key, raw_score in components.items():
        score = max(0.0, min(1.0, float(raw_score)))
        if score > 0.0:
            w = weights.get(key, 0.0)
            p = probabilities.get(key, 0.0)
            if math.isnan(p) or not (0.0 <= p <= 1.0):
                raise ValueError(f"Empirical probability for '{key}' must be in [0, 1], got {p}.")
            weighted_p_sum += w * p * score
            active_weight_sum += w * score

    if active_weight_sum <= 0.0:
        return 0.0

    return max(0.0, min(100.0, 100.0 * (weighted_p_sum / active_weight_sum)))


def calculate_psi(h_bits: float, mvs: float, h_ref: float = 80.0) -> float:
    """Calculate Password Security Index (PSI) in [0.0, 100.0].

    Formula:
      E_norm = min(H / H_ref, 1.0)
      PSI = 100 * E_norm * (1 - MVS / 100)

    Parameters:
      h_bits: Theoretical Shannon entropy in bits (>= 0.0).
      mvs: Mutation Vulnerability Score in [0.0, 100.0].
      h_ref: Reference entropy parameter (default 80.0 bits; calibrated to 50.0 in Phase 5).
             Must be a positive finite number.
    """
    if h_ref <= 0 or math.isnan(h_ref) or math.isinf(h_ref):
        raise ValueError(f"h_ref must be a positive finite number, got {h_ref}.")
    if math.isnan(h_bits) or math.isnan(mvs):
        raise ValueError("h_bits and mvs must be finite numbers.")

    h_clamped = max(0.0, float(h_bits))
    mvs_clamped = max(0.0, min(100.0, float(mvs)))
    e_norm = min(h_clamped / h_ref, 1.0)
    return max(0.0, min(100.0, 100.0 * e_norm * (1.0 - mvs_clamped / 100.0)))


def evaluate_calibrated_psi(h_bits: float,
                            mvs: float,
                            h_ref: float = CALIBRATED_H_REF,
                            threshold: float = CALIBRATED_PSI_THRESHOLD) -> Tuple[float, str]:
    """Evaluate PSI under the Phase 5 calibrated parameter set (H_ref=50.0, threshold=69.0).

    Returns (calibrated_psi, classification_label).
    """
    calibrated_psi = calculate_psi(h_bits, mvs, h_ref)
    if calibrated_psi >= threshold:
        classification = "Low Vulnerability (Synthetic Random-like Control)"
    else:
        classification = "Predictable Mutation (Vulnerable Family)"
    return calibrated_psi, classification


def risk_category(psi: float, length: int = 12, has_trivial_pattern: bool = False) -> str:
    """Determine qualitative risk tier based on PSI, length, and trivial structural patterns."""
    if length < 8 or has_trivial_pattern:
        return "High predictability risk"
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
    """Comprehensive password analysis producing theoretical, mutation, and calibrated scores.

    Parameters:
      password: Plaintext test password string.
      weights: Optional custom dictionary of feature weights.
      h_ref: Reference entropy parameter (default 80.0 bits).
      probabilities: Optional empirical probability dictionary.
    """
    if not isinstance(password, str):
        raise TypeError(f"password must be a string, got {type(password).__name__}")
    if h_ref <= 0 or math.isnan(h_ref) or math.isinf(h_ref):
        raise ValueError(f"h_ref must be a positive finite number, got {h_ref}.")
    if weights is not None and len(weights) == 0:
        raise ValueError("Weights dictionary cannot be empty.")

    n = character_set_size(password)
    L = len(password)
    # Search space S = N^L (capped calculation to prevent huge memory integer conversion)
    search_space = (n ** L) if (n > 0 and L > 0 and L <= 200) else (n ** min(L, 200) if n > 0 and L > 0 else 0)
    h = entropy(password)

    types = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() for c in password),
    }

    base = find_dictionary_base(password)
    components = mutation_components(password, base)
    mutations = detect_mutations(password, base)
    mvs = calculate_mvs(components, weights)
    e_norm = min(h / h_ref, 1.0)
    psi = calculate_psi(h, mvs, h_ref)

    has_trivial = (
        detect_repetitive_pattern(password) or
        detect_sequential_pattern(password) or
        detect_keyboard_pattern(password)
    )

    # Phase 3 Empirical Probability Model
    probs = probabilities or DEFAULT_EMPIRICAL_PROBABILITIES
    surprisal_dict = {key: surprisal(p) for key, p in probs.items()}
    emp_mvs = calculate_empirical_mvs(components, weights, probs)
    emp_psi = calculate_psi(h, emp_mvs, h_ref)

    # Phase 5 Calibrated Held-out Evaluation (uses CALIBRATED_H_REF = 50.0)
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
        risk_category=risk_category(psi, L, has_trivial_pattern=has_trivial),
        empirical_probabilities=probs,
        surprisal_bits=surprisal_dict,
        empirical_mvs=emp_mvs,
        empirical_psi=emp_psi,
        calibrated_psi=cal_psi,
        calibrated_classification=cal_class,
    )


def format_analysis(result: PasswordAnalysis) -> str:
    """Format PasswordAnalysis record as a human-readable report."""
    data = asdict(result)
    if data['password_length'] > 200:
        search_space_str = f"> 10^{int(data['password_length'] * math.log10(max(1, data['character_set_size'])))}"
    else:
        search_space_str = f"{data['search_space']:,}"
    lines = [
        "=== Password Mutation Analysis ===",
        f"Length: {data['password_length']}",
        f"Character-set size: {data['character_set_size']}",
        f"Search space: {search_space_str}",
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
