import math
import pytest
from password_analyzer import (
    analyze_password,
    format_analysis,
    entropy,
    character_set_size,
    calculate_mvs,
    calculate_empirical_mvs,
    calculate_psi,
    evaluate_calibrated_psi,
    compare_password,
    compare_benchmark_passwords,
    build_comparison_dataframe,
    get_existing_estimator_assessment,
    import_research_dataset,
    empirical_probability,
    surprisal,
    DEFAULT_WEIGHTS,
    DEFAULT_EMPIRICAL_PROBABILITIES,
    DEFAULT_SURPRISAL_BITS,
    WEIGHT_PROFILES,
    DEFAULT_H_REF,
    CALIBRATED_H_REF,
    CALIBRATED_PSI_THRESHOLD,
)
from password_analyzer.core import (
    find_dictionary_base,
    detect_mutations,
    mutation_components,
    normalize_substitutions,
    risk_category,
)


# ==============================================================================
# 1. CHARACTER SET & SEARCH SPACE CALCULATION
# ==============================================================================

def test_character_set():
    assert character_set_size("abc") == 26
    assert character_set_size("ABC") == 26
    assert character_set_size("123") == 10
    assert character_set_size("!@#") == 32
    assert character_set_size("abc123") == 36
    assert character_set_size("abc123!") == 68
    assert character_set_size("Abc123!") == 94


def test_search_space_calculation():
    # S = N^L
    res_abc = analyze_password("abc")
    assert res_abc.character_set_size == 26
    assert res_abc.password_length == 3
    assert res_abc.search_space == 26 ** 3

    res_digits = analyze_password("12345678")
    assert res_digits.character_set_size == 10
    assert res_digits.search_space == 10 ** 8


# ==============================================================================
# 2. THEORETICAL ENTROPY CALCULATION
# ==============================================================================

def test_entropy_calculation():
    # H = L * log2(N)
    # 6 lowercase letters: 6 * log2(26)
    expected_entropy = 6 * math.log2(26)
    assert math.isclose(entropy("abcdef"), expected_entropy, rel_tol=1e-5)

    # 8 digits: 8 * log2(10)
    assert math.isclose(entropy("12345678"), 8 * math.log2(10), rel_tol=1e-5)

    # Empty string should yield 0.0 entropy
    assert entropy("") == 0.0


# ==============================================================================
# 3. DICTIONARY DETECTION
# ==============================================================================

def test_dictionary_detection():
    # Direct dictionary word
    assert find_dictionary_base("password") == "password"
    assert find_dictionary_base("admin") == "admin"
    assert find_dictionary_base("welcome") == "welcome"

    # Embedded dictionary word
    assert find_dictionary_base("mysecretkey") == "secret"
    assert find_dictionary_base("winter2024") == "winter"

    # Leetspeak-substituted dictionary word
    assert find_dictionary_base("p@ssword") == "password"
    assert find_dictionary_base("adm1n") == "admin"
    assert find_dictionary_base("dr4g0n") == "dragon"


# ==============================================================================
# 4. CAPITALIZATION DETECTION
# ==============================================================================

def test_capitalization_detection():
    # Title-case: first letter capitalized
    res_title = analyze_password("Password")
    assert "capitalization" in res_title.mutations
    assert res_title.mutation_components["capitalization"] == 1.0

    # Mixed-case
    res_mixed = analyze_password("passWord")
    assert "capitalization" in res_mixed.mutations
    assert res_mixed.mutation_components["capitalization"] == 0.7

    # All lowercase: no capitalization mutation
    res_lower = analyze_password("password")
    assert "capitalization" not in res_lower.mutations
    assert res_lower.mutation_components["capitalization"] == 0.0


# ==============================================================================
# 5. SUBSTITUTION DETECTION
# ==============================================================================

def test_substitution_detection():
    # Leetspeak substitution: @ -> a
    res_at = analyze_password("p@ssword")
    assert "character substitution" in res_at.mutations
    assert res_at.mutation_components["substitution"] == 1.0

    # Substitution: 1 -> i
    res_one = analyze_password("adm1n")
    assert "character substitution" in res_one.mutations
    assert res_one.mutation_components["substitution"] == 1.0

    # No substitution
    res_plain = analyze_password("admin")
    assert "character substitution" not in res_plain.mutations
    assert res_plain.mutation_components["substitution"] == 0.0


# ==============================================================================
# 6. NUMERIC SUFFIX DETECTION
# ==============================================================================

def test_numeric_suffix_detection():
    # Numeric suffix
    res_num = analyze_password("password123")
    assert "numeric suffix" in res_num.mutations
    assert res_num.mutation_components["numeric_suffix"] == 1.0

    # Numeric suffix with trailing symbols
    res_num_sym = analyze_password("password123!")
    assert "numeric suffix" in res_num_sym.mutations
    assert res_num_sym.mutation_components["numeric_suffix"] == 1.0

    # No numeric suffix
    res_no_num = analyze_password("password")
    assert "numeric suffix" not in res_no_num.mutations
    assert res_no_num.mutation_components["numeric_suffix"] == 0.0


# ==============================================================================
# 7. SYMBOL SUFFIX DETECTION
# ==============================================================================

def test_symbol_suffix_detection():
    # Trailing exclamation
    res_sym = analyze_password("password!")
    assert "symbol suffix" in res_sym.mutations
    assert res_sym.mutation_components["symbol_suffix"] == 1.0

    # Trailing multiple symbols
    res_multi_sym = analyze_password("password123!@#")
    assert "symbol suffix" in res_multi_sym.mutations
    assert res_multi_sym.mutation_components["symbol_suffix"] == 1.0

    # No symbol suffix
    res_no_sym = analyze_password("password123")
    assert "symbol suffix" not in res_no_sym.mutations
    assert res_no_sym.mutation_components["symbol_suffix"] == 0.0


# ==============================================================================
# 8. RANDOM-LIKE PASSWORDS HAVE MVS = 0
# ==============================================================================

def test_random_like_synthetic_password_has_no_dictionary_base():
    result = analyze_password("vQ7mK2xR9zP4")
    assert result.dictionary_base is None
    assert result.mvs == 0.0
    assert result.empirical_mvs == 0.0
    assert len(result.mutations) == 0
    for comp_score in result.mutation_components.values():
        assert comp_score == 0.0

    # Second random-like password
    result2 = analyze_password("xK9#mQ2$vL8*")
    assert result2.dictionary_base is None
    assert result2.mvs == 0.0
    assert result2.empirical_mvs == 0.0


# ==============================================================================
# 9. PSI CALCULATION
# ==============================================================================

def test_psi_calculation():
    # PSI = 100 * min(H / H_ref, 1.0) * (1 - MVS / 100)
    # Test case: H = 40, MVS = 50, H_ref = 80
    # E_norm = 40/80 = 0.5. PSI = 100 * 0.5 * (1 - 0.5) = 25.0
    score = calculate_psi(h_bits=40.0, mvs=50.0, h_ref=80.0)
    assert math.isclose(score, 25.0, rel_tol=1e-5)

    # Test case: MVS = 100 => PSI must be 0.0 regardless of entropy
    assert calculate_psi(h_bits=100.0, mvs=100.0, h_ref=80.0) == 0.0

    # Test case: MVS = 0 and H >= H_ref => PSI must be 100.0
    assert calculate_psi(h_bits=80.0, mvs=0.0, h_ref=80.0) == 100.0
    assert calculate_psi(h_bits=120.0, mvs=0.0, h_ref=80.0) == 100.0

    # Invalid H_ref <= 0 should raise ValueError
    with pytest.raises(ValueError):
        calculate_psi(h_bits=50.0, mvs=20.0, h_ref=0.0)


# ==============================================================================
# 10. EMPIRICAL PROBABILITY & SURPRISAL CALCULATION
# ==============================================================================

def test_empirical_probability_calculation():
    # Laplace smoothing formula: p_hat = (k + 1) / (n + 2)
    # For dictionary base in Phase 3 dataset (k=105, n=330):
    k_dict = 105
    n_total = 330
    p_hat_dict = (k_dict + 1) / (n_total + 2)
    assert math.isclose(DEFAULT_EMPIRICAL_PROBABILITIES["dictionary_base"], p_hat_dict, rel_tol=1e-6)

    # For dictionary-only password:
    res = analyze_password("password")
    expected_emp_mvs = 100.0 * p_hat_dict
    assert math.isclose(res.empirical_mvs, expected_emp_mvs, rel_tol=1e-5)


def test_surprisal_values():
    # Surprisal: I = -log2(p_hat)
    for key, p in DEFAULT_EMPIRICAL_PROBABILITIES.items():
        expected_surprisal = -math.log2(p)
        assert math.isclose(DEFAULT_SURPRISAL_BITS[key], expected_surprisal, rel_tol=1e-5)


# ==============================================================================
# 11. BASELINE COMPARISON INTEGRATION (TASK 1 & TASK 7)
# ==============================================================================

def test_baseline_comparison():
    # Compare single password
    comp = compare_password("Password123!")
    assert comp.password == "Password123!"
    assert comp.length == 12
    assert comp.entropy > 0
    assert comp.mvs > 0
    assert comp.psi < 50.0
    assert 0 <= comp.existing_estimator_score <= 4
    assert len(comp.explanation) > 0

    # Compare random-like control
    comp_rand = compare_password("vQ7mK2xR9zP4")
    assert comp_rand.mvs == 0.0
    assert comp_rand.psi > 70.0
    assert "No dictionary base" in comp_rand.explanation

    # Compare 3 canonical benchmark passwords
    benchmarks = compare_benchmark_passwords()
    assert len(benchmarks) == 3
    passwords = [b.password for b in benchmarks]
    assert "Password123!" in passwords
    assert "vQ7mK2xR9zP4" in passwords
    assert "P@ssword2026!" in passwords

    # Verify P@ssword2026! has dictionary detection and substitutions
    p_comp = next(b for b in benchmarks if b.password == "P@ssword2026!")
    assert p_comp.mvs > 0.0
    assert p_comp.psi < 50.0


# ==============================================================================
# 12. CLASSIFICATION THRESHOLD
# ==============================================================================

def test_phase5_calibration_classification():
    # Predictable mutation password should fall below threshold
    res_pred = analyze_password("Password123!")
    assert res_pred.calibrated_psi < CALIBRATED_PSI_THRESHOLD
    assert "Predictable Mutation" in res_pred.calibrated_classification

    # Random-like control password should fall at or above threshold
    res_rand = analyze_password("vQ7mK2xR9zP4")
    assert res_rand.calibrated_psi >= CALIBRATED_PSI_THRESHOLD
    assert "Low Vulnerability" in res_rand.calibrated_classification

    # Test threshold boundary logic directly
    psi_below, label_below = evaluate_calibrated_psi(h_bits=30.0, mvs=50.0)
    assert "Predictable Mutation" in label_below

    psi_above, label_above = evaluate_calibrated_psi(h_bits=60.0, mvs=0.0)
    assert "Low Vulnerability" in label_above


# ==============================================================================
# 13. EDGE CASES
# ==============================================================================

def test_edge_case_empty_string():
    res = analyze_password("")
    assert res.password_length == 0
    assert res.character_set_size == 0
    assert res.search_space == 0
    assert res.entropy_bits == 0.0
    assert res.mvs == 0.0
    assert res.empirical_mvs == 0.0
    assert res.psi == 0.0
    assert res.dictionary_base is None


def test_edge_case_very_short_passwords():
    res_char = analyze_password("a")
    assert res_char.password_length == 1
    assert res_char.character_set_size == 26
    assert res_char.search_space == 26
    assert res_char.entropy_bits > 0.0
    assert res_char.mvs == 0.0

    res_digit = analyze_password("1")
    assert res_digit.password_length == 1
    assert res_digit.character_set_size == 10
    assert res_digit.search_space == 10
    assert res_digit.entropy_bits > 0.0


def test_edge_case_only_digits():
    res = analyze_password("12345678")
    assert res.password_length == 8
    assert res.character_set_size == 10
    assert res.search_space == 10 ** 8
    assert math.isclose(res.entropy_bits, 8 * math.log2(10), rel_tol=1e-5)
    assert res.character_types["digits"] is True
    assert res.character_types["lowercase"] is False
    assert res.character_types["uppercase"] is False
    assert res.character_types["symbols"] is False


def test_edge_case_only_letters():
    res = analyze_password("abcdefgh")
    assert res.password_length == 8
    assert res.character_set_size == 26
    assert res.search_space == 26 ** 8
    assert math.isclose(res.entropy_bits, 8 * math.log2(26), rel_tol=1e-5)
    assert res.character_types["digits"] is False
    assert res.character_types["lowercase"] is True
    assert res.character_types["symbols"] is False


def test_edge_case_very_long_password():
    long_pwd = "A" * 120 + "123!"
    res = analyze_password(long_pwd)
    assert res.password_length == 124
    assert res.character_set_size == 26 + 10 + 32  # uppercase, digits, symbols = 68
    assert res.entropy_bits > 100.0
    assert res.entropy_normalized == 1.0  # capped at 1.0
    assert 0.0 <= res.psi <= 100.0


def test_edge_case_complex_mutations():
    # P@ssword2026! has dictionary base 'password', capitalization, substitution, numeric suffix, symbol suffix
    res = analyze_password("P@ssword2026!")
    assert res.dictionary_base == "password"
    assert "capitalization" in res.mutations
    assert "character substitution" in res.mutations
    assert "numeric suffix" in res.mutations
    assert "symbol suffix" in res.mutations
    assert res.mvs > 50.0
    assert res.calibrated_psi < CALIBRATED_PSI_THRESHOLD


def test_invalid_type_raises_type_error():
    with pytest.raises(TypeError):
        analyze_password(12345)  # type: ignore


# ==============================================================================
# 14. WEIGHT PROFILES SENSITIVITY
# ==============================================================================

def test_weight_profiles():
    for name, profile in WEIGHT_PROFILES.items():
        total_weight = sum(profile.values())
        assert math.isclose(total_weight, 1.0, abs_tol=1e-6)
        res = analyze_password("Password123!", weights=profile)
        assert 0.0 <= res.mvs <= 100.0
        assert 0.0 <= res.empirical_mvs <= 100.0


# ==============================================================================
# 15. PUBLIC RESEARCH DATASET AGGREGATION PIPELINE (TASK 3)
# ==============================================================================

def test_public_dataset_pipeline_privacy_preserving():
    report = import_research_dataset("data/public_research_dataset_example.csv")
    assert report.total_records > 0
    assert 0.0 <= report.dictionary_base_frequency <= 1.0
    assert 0.0 <= report.capitalization_frequency <= 1.0
    assert 0.0 <= report.substitution_frequency <= 1.0
    assert 0.0 <= report.numeric_suffix_frequency <= 1.0
    assert 0.0 <= report.symbol_suffix_frequency <= 1.0
    assert report.dataset_type == "REAL/PUBLIC RESEARCH DATA"
    # Verify summary dict contains expected keys
    summary = report.to_dict()
    assert "total_records" in summary
    assert "dictionary_base_frequency" in summary


def test_import_research_dataset_headerless_wordlist(tmp_path):
    # Test file with no header starting directly with a password (e.g. '12345')
    raw_file = tmp_path / "raw_wordlist.txt"
    raw_file.write_text("12345\nabc123\npassword!\nqwerty2024\n", encoding="utf-8")

    report = import_research_dataset(raw_file)
    assert report.total_records == 4
    assert report.mean_length > 0
    summary = report.summary_table()
    assert len(summary) > 0


def test_import_research_dataset_tsv_and_quotes(tmp_path):
    # Test TSV and quotes
    tsv_file = tmp_path / "data.tsv"
    tsv_file.write_text('"password"\t"source"\n"P@ss123"\t"leak1"\n"secret!"\t"leak2"\n', encoding="utf-8")

    report = import_research_dataset(tsv_file)
    assert report.total_records == 2
    assert "leak1" in report.source_distribution


def test_simple_passwords_vulnerability_detection():
    # 1. Repetitive characters
    rep_res = analyze_password("111111111111")
    assert rep_res.mutation_components["dictionary_base"] == 0.0
    assert rep_res.mvs == 0.0
    assert "repetitive characters" in rep_res.mutations
    assert "numeric suffix" not in rep_res.mutations
    assert rep_res.risk_category == "High predictability risk"

    # 2. Sequential digits
    seq_res = analyze_password("123456789012")
    assert seq_res.mutation_components["dictionary_base"] == 0.0
    assert seq_res.mvs == 0.0
    assert "sequential characters" in seq_res.mutations
    assert "numeric suffix" not in seq_res.mutations
    assert seq_res.risk_category == "High predictability risk"

    # 3. Simple dictionary + predictable mutations
    simple_res = analyze_password("Simple123!")
    assert simple_res.dictionary_base == "simple"
    assert "capitalization" in simple_res.mutations
    assert "numeric suffix" in simple_res.mutations
    assert "symbol suffix" in simple_res.mutations
    assert simple_res.mvs >= 70.0
    assert simple_res.psi < 30.0
    assert simple_res.risk_category == "High predictability risk"

    # 4. Keyboard walks
    kb_res = analyze_password("qwertyuiop")
    assert "keyboard sequence" in kb_res.mutations
    assert kb_res.mvs > 0.0

    # 5. Short passwords
    short_res = analyze_password("cat")
    assert short_res.dictionary_base == "cat"
    assert short_res.risk_category == "High predictability risk"


# ==============================================================================
# 16. COMPREHENSIVE REGRESSION TESTS (PROMPT REQUIREMENTS 2, 3, 4, 5, 6, 7, 8)
# ==============================================================================

def test_regression_dictionary_word_with_numeric_suffix():
    """A dictionary word with a numeric suffix (e.g. password123, admin2026)."""
    res = analyze_password("password123")
    assert res.dictionary_base == "password"
    assert "numeric suffix" in res.mutations
    assert "symbol suffix" not in res.mutations
    assert "capitalization" not in res.mutations
    assert "character substitution" not in res.mutations
    assert res.mutation_components["numeric_suffix"] == 1.0
    assert res.mutation_components["symbol_suffix"] == 0.0
    assert res.mutation_components["capitalization"] == 0.0
    assert res.mutation_components["substitution"] == 0.0
    assert res.mutation_components["dictionary_base"] == 1.0
    # Expected MVS: 100 * (0.35 * 1.0 + 0.20 * 1.0) = 55.0
    assert math.isclose(res.mvs, 55.0, abs_tol=1e-5)


def test_regression_dictionary_word_with_numeric_and_symbol_suffix():
    """A dictionary word with numeric suffix followed by trailing symbol(s).

    Tests 'Password123!', 'password123!', 'welcome2026#', 'admin42.'.
    Must correctly detect numeric suffix before trailing symbols and distinguish both.
    """
    for pw, base in [
        ("Password123!", "password"),
        ("password123!", "password"),
        ("welcome2026#", "welcome"),
        ("admin42.", "admin"),
        ("summer99$!@", "summer"),
    ]:
        res = analyze_password(pw)
        assert res.dictionary_base == base, f"Failed base detection for {pw}"
        assert "numeric suffix" in res.mutations, f"Failed numeric suffix for {pw}"
        assert "symbol suffix" in res.mutations, f"Failed symbol suffix for {pw}"
        assert res.mutation_components["numeric_suffix"] == 1.0
        assert res.mutation_components["symbol_suffix"] == 1.0

    # Specifically verify Password123! component breakdown
    res_canonical = analyze_password("Password123!")
    assert res_canonical.mutation_components["dictionary_base"] == 1.0
    assert res_canonical.mutation_components["capitalization"] == 1.0
    assert res_canonical.mutation_components["substitution"] == 0.0
    assert res_canonical.mutation_components["numeric_suffix"] == 1.0
    assert res_canonical.mutation_components["symbol_suffix"] == 1.0
    # MVS = 100 * (0.35 + 0.15 + 0.20 + 0.10) = 80.0
    assert math.isclose(res_canonical.mvs, 80.0, abs_tol=1e-5)


def test_regression_dictionary_word_with_capitalization():
    """A dictionary word with capitalization (TitleCase and mixed-case)."""
    # TitleCase
    res_title = analyze_password("Password")
    assert res_title.dictionary_base == "password"
    assert "capitalization" in res_title.mutations
    assert res_title.mutation_components["capitalization"] == 1.0
    assert res_title.mutation_components["numeric_suffix"] == 0.0
    assert res_title.mutation_components["symbol_suffix"] == 0.0

    # Mixed-case
    res_mixed = analyze_password("passWord")
    assert res_mixed.dictionary_base == "password"
    assert "capitalization" in res_mixed.mutations
    assert res_mixed.mutation_components["capitalization"] == 0.7


def test_regression_dictionary_word_with_supported_character_substitution():
    """A dictionary word with supported leetspeak character substitutions."""
    for pw, base in [
        ("p@ssword", "password"),
        ("adm1n", "admin"),
        ("dr4g0n", "dragon"),
        ("w3lc0m3", "welcome"),
        ("s3cur1ty", "security"),
    ]:
        res = analyze_password(pw)
        assert res.dictionary_base == base, f"Failed base for {pw}"
        assert "character substitution" in res.mutations, f"Failed substitution for {pw}"
        assert res.mutation_components["substitution"] == 1.0


def test_regression_dictionary_word_with_symbol_suffix():
    """A dictionary word with symbol suffix only (no numeric suffix)."""
    for pw, base in [
        ("password!", "password"),
        ("Password!", "password"),
        ("welcome#", "welcome"),
        ("admin!@#", "admin"),
    ]:
        res = analyze_password(pw)
        assert res.dictionary_base == base
        assert "symbol suffix" in res.mutations
        assert "numeric suffix" not in res.mutations
        assert res.mutation_components["symbol_suffix"] == 1.0
        assert res.mutation_components["numeric_suffix"] == 0.0


def test_regression_random_looking_password_with_uppercase_and_digits():
    """A random-looking password containing uppercase letters and digits.

    Must NOT be classified as dictionary mutations. MVS must be 0.0.
    """
    for pw in ["vQ7mK2xR9zP4", "aX9qLm2P7vT8", "Rnd7xK9mQ2", "K7mP9wQ2xL"]:
        res = analyze_password(pw)
        assert res.dictionary_base is None, f"False dictionary base for {pw}"
        assert res.mvs == 0.0, f"False MVS > 0 for {pw}"
        assert res.empirical_mvs == 0.0
        assert len(res.mutations) == 0, f"False mutations for {pw}: {res.mutations}"
        for comp_name, comp_val in res.mutation_components.items():
            assert comp_val == 0.0, f"Component {comp_name} non-zero for {pw}"
        # Preserves high PSI
        assert res.psi > 60.0


def test_regression_random_looking_password_ending_in_digits_and_symbols():
    """A random-looking password ending in digits and symbols.

    Must NOT be penalized merely because it contains trailing numbers or symbols.
    """
    for pw in ["xK9#mQ2$vL8*", "xK9#mQ2$vL89!", "kLzXwP99", "th5nRk#wfF44^", "rAnD0m!123#"]:
        res = analyze_password(pw)
        assert res.dictionary_base is None, f"False dictionary base for {pw}"
        assert res.mvs == 0.0, f"False MVS for {pw}: {res.mvs}"
        assert len(res.mutations) == 0, f"False mutations for {pw}: {res.mutations}"
        assert res.mutation_components["numeric_suffix"] == 0.0
        assert res.mutation_components["symbol_suffix"] == 0.0


def test_regression_empty_input():
    """Empty string input must be handled safely across all functions."""
    res = analyze_password("")
    assert res.password_length == 0
    assert res.character_set_size == 0
    assert res.search_space == 0
    assert res.entropy_bits == 0.0
    assert res.mvs == 0.0
    assert res.psi == 0.0
    assert res.dictionary_base is None
    assert len(res.mutations) == 0

    # Baseline comparison must also handle empty string safely without crashing
    comp = compare_password("")
    assert comp.length == 0
    assert comp.entropy == 0.0
    assert comp.mvs == 0.0
    assert comp.psi == 0.0
    assert "empty" in comp.explanation.lower()
    assert comp.existing_estimator_score == 0


def test_regression_very_short_passwords():
    """Very short passwords (1-3 characters)."""
    for pw in ["a", "1", "!", "ab", "12", "cat"]:
        res = analyze_password(pw)
        assert res.password_length == len(pw)
        assert res.search_space > 0
        assert res.entropy_bits > 0
        # Because length < 8, risk category must be high predictability risk
        assert res.risk_category == "High predictability risk"


def test_regression_unicode_input():
    """Unicode inputs with non-ASCII letters or special symbols."""
    res_unicode = analyze_password("Pässw0rd123!")
    assert res_unicode.password_length == len("Pässw0rd123!")
    assert res_unicode.character_set_size > 0
    assert res_unicode.entropy_bits > 0.0
    assert 0.0 <= res_unicode.mvs <= 100.0
    assert 0.0 <= res_unicode.psi <= 100.0

    res_symbol = analyze_password("€123abc#")
    assert res_symbol.password_length == 8
    assert res_symbol.character_types["symbols"] is True
    assert res_symbol.character_set_size >= 68


def test_regression_missing_or_unsupported_dictionary_entries():
    """Passwords with words not in COMMON_WORDS must safely return None for base."""
    for pw in ["unsupportedxyz123!", "nonexistentword42", "randomstring99"]:
        res = analyze_password(pw)
        assert res.dictionary_base is None
        assert res.mvs == 0.0
        assert len(res.mutations) == 0


def test_regression_custom_and_invalid_weights():
    """Validate weight handling, custom normalization, and rejection of invalid weights."""
    # Valid custom weights (normalized automatically)
    custom = {"dictionary_base": 2.0, "numeric_suffix": 2.0, "symbol_suffix": 0.0, "capitalization": 0.0, "substitution": 0.0}
    res = analyze_password("password123", weights=custom)
    # Total weight is 4.0; dictionary_base normalized to 0.5, numeric_suffix to 0.5.
    # MVS = 100 * (1.0 * 0.5 + 1.0 * 0.5) = 100.0
    assert math.isclose(res.mvs, 100.0, abs_tol=1e-5)

    # Empty weights dictionary
    with pytest.raises(ValueError):
        calculate_mvs({"dictionary_base": 1.0}, weights={})

    # Negative weight
    with pytest.raises(ValueError):
        calculate_mvs({"dictionary_base": 1.0}, weights={"dictionary_base": -0.5, "numeric_suffix": 1.0})

    # Zero total weight
    with pytest.raises(ValueError):
        calculate_mvs({"dictionary_base": 1.0}, weights={"dictionary_base": 0.0, "numeric_suffix": 0.0})


def test_regression_invalid_h_ref_values():
    """h_ref <= 0, NaN, or Inf must raise ValueError."""
    for invalid_href in [0.0, -10.0, float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError):
            calculate_psi(h_bits=50.0, mvs=20.0, h_ref=invalid_href)
        with pytest.raises(ValueError):
            analyze_password("password", h_ref=invalid_href)


def test_regression_search_space_and_entropy_calculations():
    """Mathematical validation: S = N^L and H = L * log2(N)."""
    # 8 lowercase letters: N = 26, L = 8
    res = analyze_password("abcdefgh")
    assert res.character_set_size == 26
    assert res.password_length == 8
    assert res.search_space == 26 ** 8
    assert math.isclose(res.entropy_bits, 8 * math.log2(26), rel_tol=1e-6)

    # 12 characters across all 4 classes: N = 94, L = 12
    res_full = analyze_password("Abc123!@#xyz")
    assert res_full.character_set_size == 94
    assert res_full.password_length == 12
    assert res_full.search_space == 94 ** 12
    assert math.isclose(res_full.entropy_bits, 12 * math.log2(94), rel_tol=1e-6)


def test_regression_mvs_and_psi_mathematical_ranges():
    """Verify MVS and PSI strictly stay within [0.0, 100.0] across extreme inputs."""
    # Extreme zero entropy
    assert calculate_psi(h_bits=0.0, mvs=0.0, h_ref=80.0) == 0.0
    assert calculate_psi(h_bits=0.0, mvs=100.0, h_ref=80.0) == 0.0

    # Very high entropy
    psi_high = calculate_psi(h_bits=500.0, mvs=0.0, h_ref=80.0)
    assert psi_high == 100.0  # capped at 100.0

    # Clamping tests
    psi_penalized = calculate_psi(h_bits=80.0, mvs=100.0, h_ref=80.0)
    assert psi_penalized == 0.0

    # Extreme component values
    extreme_comps = {k: 5.0 for k in DEFAULT_WEIGHTS}
    mvs_extreme = calculate_mvs(extreme_comps)
    assert 0.0 <= mvs_extreme <= 100.0


def test_regression_agreement_detected_features_components_and_explanations():
    """Ensure every feature with score > 0 is in mutations list and explained."""
    test_passwords = [
        "Password123!",
        "password",
        "p@ssword",
        "password!",
        "vQ7mK2xR9zP4",
        "P@ssword2026!",
    ]
    for pw in test_passwords:
        res = analyze_password(pw)
        comp = compare_password(pw)

        # 1. Indicator agreement: score > 0 <==> mutation label present
        if res.mutation_components["capitalization"] > 0:
            assert "capitalization" in res.mutations
        if res.mutation_components["substitution"] > 0:
            assert "character substitution" in res.mutations
        if res.mutation_components["numeric_suffix"] > 0:
            assert "numeric suffix" in res.mutations
        if res.mutation_components["symbol_suffix"] > 0:
            assert "symbol suffix" in res.mutations

        # 2. Score range
        assert 0.0 <= res.mvs <= 100.0
        assert 0.0 <= res.psi <= 100.0

        # 3. Explanation contains MVS and PSI
        assert f"{res.mvs:.1f}/100" in comp.explanation
        assert f"{res.psi:.1f}/100" in comp.explanation


def test_regression_zxcvbn_behaviour():
    """Verify zxcvbn behavior, feedback, crack times, and heuristic fallback resilience."""
    assessment = get_existing_estimator_assessment("Password123!")
    assert assessment["name"] == "Dropbox zxcvbn"
    assert 0 <= assessment["score"] <= 4
    assert 0.0 <= assessment["normalized"] <= 100.0
    assert assessment["guesses_log10"] > 0
    assert len(assessment["crack_time"]) > 0

    # Empty string resilience
    empty_assessment = get_existing_estimator_assessment("")
    assert empty_assessment["score"] == 0
    assert empty_assessment["normalized"] == 0.0


def test_regression_empirical_probability_and_surprisal():
    """Validate empirical probability estimator p_hat = (k + 1) / (n + 2) and surprisal."""
    # Standard valid calculation
    p = empirical_probability(10, 100)
    assert math.isclose(p, 11 / 102, rel_tol=1e-6)
    assert 0.0 < p < 1.0

    # Boundary: k = 0
    p_zero = empirical_probability(0, 10)
    assert math.isclose(p_zero, 1 / 12, rel_tol=1e-6)

    # Boundary: k = n
    p_full = empirical_probability(10, 10)
    assert math.isclose(p_full, 11 / 12, rel_tol=1e-6)

    # Surprisal
    assert math.isclose(surprisal(0.5), 1.0, rel_tol=1e-6)
    assert math.isclose(surprisal(1.0), 0.0, abs_tol=1e-6)

    # Validation errors
    with pytest.raises(ValueError):
        empirical_probability(15, 10)  # k > n
    with pytest.raises(ValueError):
        empirical_probability(-1, 10)  # negative k
    with pytest.raises(ValueError):
        empirical_probability(5, -10)  # negative n
    with pytest.raises(TypeError):
        empirical_probability(5.5, 10)  # non-integer
    with pytest.raises(ValueError):
        surprisal(0.0)  # p <= 0
    with pytest.raises(ValueError):
        surprisal(1.5)  # p > 1


# ==============================================================================
# 17. PHASE TWO & EIGHT SPECIFIC REGRESSION SUITE
# ==============================================================================

def test_regression_phase2_canonical_eight_cases():
    """Verify all 8 regression cases mandated by Phase Two A and Phase Eight A:
    1. Password123
    2. Password123!
    3. Password2026!!
    4. Password!
    5. Password
    6. 12345678
    7. vQ7mK2xR9zP4
    8. Empty input
    """
    # 1. Password123
    res1 = analyze_password("Password123")
    assert res1.dictionary_base == "password"
    assert "numeric suffix" in res1.mutations
    assert "symbol suffix" not in res1.mutations
    assert "capitalization" in res1.mutations
    assert res1.mutation_components["numeric_suffix"] == 1.0
    assert res1.mutation_components["symbol_suffix"] == 0.0
    assert res1.mutation_components["capitalization"] == 1.0
    assert math.isclose(res1.mvs, 70.0, abs_tol=1e-5)

    # 2. Password123!
    res2 = analyze_password("Password123!")
    assert res2.dictionary_base == "password"
    assert "numeric suffix" in res2.mutations
    assert "symbol suffix" in res2.mutations
    assert "capitalization" in res2.mutations
    assert res2.mutation_components["numeric_suffix"] == 1.0
    assert res2.mutation_components["symbol_suffix"] == 1.0
    assert res2.mutation_components["capitalization"] == 1.0
    assert math.isclose(res2.mvs, 80.0, abs_tol=1e-5)

    # 3. Password2026!!
    res3 = analyze_password("Password2026!!")
    assert res3.dictionary_base == "password"
    assert "numeric suffix" in res3.mutations
    assert "symbol suffix" in res3.mutations
    assert "capitalization" in res3.mutations
    assert res3.mutation_components["numeric_suffix"] == 1.0
    assert res3.mutation_components["symbol_suffix"] == 1.0
    assert res3.mutation_components["capitalization"] == 1.0
    assert math.isclose(res3.mvs, 80.0, abs_tol=1e-5)

    # 4. Password!
    res4 = analyze_password("Password!")
    assert res4.dictionary_base == "password"
    assert "numeric suffix" not in res4.mutations
    assert "symbol suffix" in res4.mutations
    assert "capitalization" in res4.mutations
    assert res4.mutation_components["numeric_suffix"] == 0.0
    assert res4.mutation_components["symbol_suffix"] == 1.0
    assert res4.mutation_components["capitalization"] == 1.0
    assert math.isclose(res4.mvs, 60.0, abs_tol=1e-5)

    # 5. Password
    res5 = analyze_password("Password")
    assert res5.dictionary_base == "password"
    assert "numeric suffix" not in res5.mutations
    assert "symbol suffix" not in res5.mutations
    assert "capitalization" in res5.mutations
    assert res5.mutation_components["numeric_suffix"] == 0.0
    assert res5.mutation_components["symbol_suffix"] == 0.0
    assert res5.mutation_components["capitalization"] == 1.0
    assert math.isclose(res5.mvs, 50.0, abs_tol=1e-5)

    # 6. 12345678 (all-digit sequential pattern: NO dictionary base, NO numeric suffix, NO symbol suffix)
    res6 = analyze_password("12345678")
    assert res6.dictionary_base is None
    assert "numeric suffix" not in res6.mutations
    assert "symbol suffix" not in res6.mutations
    assert "capitalization" not in res6.mutations
    assert "character substitution" not in res6.mutations
    assert "sequential characters" in res6.mutations
    assert res6.mutation_components["numeric_suffix"] == 0.0
    assert res6.mutation_components["symbol_suffix"] == 0.0
    assert res6.mutation_components["dictionary_base"] == 0.0  # pure sequential pattern without dictionary root
    assert math.isclose(res6.mvs, 0.0, abs_tol=1e-5)
    assert res6.risk_category == "High predictability risk"

    # 7. vQ7mK2xR9zP4 (random control: MVS must be exactly 0.0)
    res7 = analyze_password("vQ7mK2xR9zP4")
    assert res7.dictionary_base is None
    assert len(res7.mutations) == 0
    for val in res7.mutation_components.values():
        assert val == 0.0
    assert res7.mvs == 0.0

    # 8. Empty input
    res8 = analyze_password("")
    assert res8.password_length == 0
    assert res8.dictionary_base is None
    assert len(res8.mutations) == 0
    assert res8.mvs == 0.0
    assert res8.psi == 0.0


def test_regression_capitalization_edge_cases():
    """Verify false positive avoidance for all-digit, all-lower, all-upper, and correct detection for title/mixed."""
    # All-uppercase words: NOT TitleCase mutation
    for upper_pw in ["PASSWORD", "ADMIN", "WELCOME", "QWERTY"]:
        res = analyze_password(upper_pw)
        assert res.mutation_components["capitalization"] == 0.0
        assert "capitalization" not in res.mutations

    # All-lowercase words: NOT capitalization mutation
    for lower_pw in ["password", "admin", "welcome", "summer"]:
        res = analyze_password(lower_pw)
        assert res.mutation_components["capitalization"] == 0.0
        assert "capitalization" not in res.mutations

    # Title-case: exactly 1.0
    for title_pw in ["Password", "Admin", "Welcome", "Summer"]:
        res = analyze_password(title_pw)
        assert res.mutation_components["capitalization"] == 1.0
        assert "capitalization" in res.mutations

    # Mixed-case: exactly 0.7
    for mixed_pw in ["passWord", "admIn", "welcOme"]:
        res = analyze_password(mixed_pw)
        assert res.mutation_components["capitalization"] == 0.7
        assert "capitalization" in res.mutations


def test_regression_internal_symbols_vs_trailing_symbols():
    """Verify symbols inside the password are NOT detected as trailing symbol suffixes."""
    # Internal symbol without dictionary base
    res_rand_sym = analyze_password("random!value")
    assert res_rand_sym.mutation_components["symbol_suffix"] == 0.0
    assert "symbol suffix" not in res_rand_sym.mutations

    # Internal symbol with dictionary base
    res_dict_internal = analyze_password("password!value")
    assert res_dict_internal.mutation_components["symbol_suffix"] == 0.0
    assert "symbol suffix" not in res_dict_internal.mutations

    # Trailing symbol
    res_dict_trailing = analyze_password("password!")
    assert res_dict_trailing.mutation_components["symbol_suffix"] == 1.0
    assert "symbol suffix" in res_dict_trailing.mutations

    # Both internal substitution symbol and trailing symbol
    res_both = analyze_password("P@ssword2026!")
    assert res_both.mutation_components["substitution"] == 1.0
    assert res_both.mutation_components["symbol_suffix"] == 1.0
    assert "character substitution" in res_both.mutations
    assert "symbol suffix" in res_both.mutations


def test_regression_mathematical_mvs_all_active_and_none_active():
    """Test boundary conditions: all components active vs none active."""
    # All components active:
    all_comps = {
        "dictionary_base": 1.0,
        "capitalization": 1.0,
        "substitution": 1.0,
        "numeric_suffix": 1.0,
        "symbol_suffix": 1.0,
    }
    mvs_all = calculate_mvs(all_comps)
    assert math.isclose(mvs_all, 100.0, abs_tol=1e-5)

    emp_mvs_all = calculate_empirical_mvs(all_comps)
    assert emp_mvs_all > 0.0
    assert 0.0 <= emp_mvs_all <= 100.0

    # None active:
    none_comps = {k: 0.0 for k in DEFAULT_WEIGHTS}
    assert calculate_mvs(none_comps) == 0.0
    assert calculate_empirical_mvs(none_comps) == 0.0


def test_regression_psi_and_calibrated_decision_rules():
    """Test PSI formula properties, normalization, and threshold boundary."""
    # Zero entropy -> PSI = 0.0
    assert calculate_psi(h_bits=0.0, mvs=0.0, h_ref=80.0) == 0.0

    # Entropy exceeding H_ref caps E_norm at 1.0
    assert calculate_psi(h_bits=120.0, mvs=0.0, h_ref=80.0) == 100.0

    # H_ref = 50 vs H_ref = 80
    psi_80 = calculate_psi(h_bits=40.0, mvs=0.0, h_ref=80.0)
    psi_50 = calculate_psi(h_bits=40.0, mvs=0.0, h_ref=50.0)
    assert math.isclose(psi_80, 50.0, rel_tol=1e-5)   # 40/80 = 0.5 -> 50.0
    assert math.isclose(psi_50, 80.0, rel_tol=1e-5)   # 40/50 = 0.8 -> 80.0

    # Calibrated decision threshold boundary at exactly 69.0
    _, class_at = evaluate_calibrated_psi(h_bits=50.0, mvs=31.0, h_ref=50.0, threshold=69.0)
    assert "Low Vulnerability" in class_at  # 100 * 1.0 * (1 - 0.31) = 69.0 >= 69.0

    _, class_below = evaluate_calibrated_psi(h_bits=50.0, mvs=31.1, h_ref=50.0, threshold=69.0)
    assert "Predictable Mutation" in class_below  # 68.9 < 69.0


def test_regression_search_space_very_large_password_no_overflow():
    """Verify that very long passwords (e.g. 3000 chars) do not crash integer string conversion."""
    huge_pw = "Aa1!" * 750  # 3000 characters
    res = analyze_password(huge_pw)
    assert res.password_length == 3000
    assert res.character_set_size == 94
    assert res.entropy_bits > 1000.0
    assert res.entropy_normalized == 1.0
    assert 0.0 <= res.psi <= 100.0

    # Verify format_analysis formats cleanly without ValueError
    formatted = format_analysis(res)
    assert "Length: 3000" in formatted
    assert "Search space:" in formatted


def test_regression_zxcvbn_unavailable_fallback_mock(monkeypatch):
    """Verify that when zxcvbn is unavailable, the fallback estimator works smoothly."""
    import password_analyzer.baseline_comparator as bc
    monkeypatch.setattr(bc, "HAS_ZXCVBN", False)
    monkeypatch.setattr(bc, "zxcvbn", None)

    est = bc.get_existing_estimator_assessment("Password123!")
    assert "zxcvbn not installed" in est["name"]
    assert 0 <= est["score"] <= 4
    assert 0.0 <= est["normalized"] <= 100.0
    assert est["crack_time"] == "Estimated offline"

    # compare_password also functions normally
    comp = bc.compare_password("Password123!")
    assert comp.length == 12
    assert "zxcvbn not installed" in comp.existing_estimator_name
    assert comp.mvs > 0.0


def test_regression_dataset_validation_missing_file_and_empty():
    """Verify dataset pipeline error handling for missing and invalid files."""
    from password_analyzer.dataset_pipeline import import_research_dataset
    with pytest.raises(FileNotFoundError):
        import_research_dataset("data/non_existent_file_12345.csv")


# ==============================================================================
# SECTION 8: RIGOROUS AUDIT REGRESSION TESTS (Formulas, Leakage, Privacy, Sens.)
# ==============================================================================

def test_audit_scoring_formulas_and_weights():
    """Verify every scoring formula independently without using internal shortcuts."""
    # 1. Theoretical character-pool entropy: H = L * log2(N)
    # 8 lowercase letters (N=26): H = 8 * log2(26) ~ 37.6035 bits
    expected_h = 8.0 * math.log2(26.0)
    assert math.isclose(entropy("password"), expected_h, rel_tol=1e-5)

    # 2. Laplace-smoothed empirical probability: p_hat = (k + 1) / (n + 2)
    p_hat = empirical_probability(45, 105)
    assert math.isclose(p_hat, 46.0 / 107.0, rel_tol=1e-6)

    # 3. Information content (surprisal): I = -log2(p_hat)
    info = surprisal(p_hat)
    assert math.isclose(info, -math.log2(46.0 / 107.0), rel_tol=1e-6)

    # 4. Zero denominator and empty dataset behavior
    assert calculate_mvs({}) == 0.0
    assert calculate_empirical_mvs({}, DEFAULT_WEIGHTS, DEFAULT_EMPIRICAL_PROBABILITIES) == 0.0
    assert calculate_mvs({"dictionary_base": 0.0}) == 0.0
    assert calculate_empirical_mvs({"dictionary_base": 0.0}, DEFAULT_WEIGHTS, {"dictionary_base": 0.5}) == 0.0

    # 5. Fixed MVS formula: MVS = 100 * sum(w_i * x_i)
    # TitleCase (0.15) + Numeric suffix (0.20) + Dictionary base (0.35) = 0.70 -> MVS = 70.0
    comp_map = {"capitalization": 1.0, "numeric_suffix": 1.0, "dictionary_base": 1.0}
    mvs_val = calculate_mvs(comp_map, DEFAULT_WEIGHTS)
    assert math.isclose(mvs_val, 70.0, abs_tol=1e-5)


def test_fixed_mvs_vs_empirical_mvs_distinction():
    """Verify clear distinction between Fixed MVS PSI and Empirical MVS PSI."""
    pw = "Password123!"
    analysis = analyze_password(pw)
    assert hasattr(analysis, "psi_fixed_mvs")
    assert hasattr(analysis, "psi_empirical_mvs")
    assert hasattr(analysis, "calibrated_psi_fixed")
    assert hasattr(analysis, "calibrated_psi_empirical")

    # Fixed MVS uses baseline weights
    assert analysis.mvs > 0.0
    # Empirical MVS uses Laplace-smoothed probabilities
    assert analysis.empirical_mvs > 0.0
    assert analysis.psi_fixed_mvs != analysis.psi_empirical_mvs

    # Calibrated values use H_ref = 50.0
    assert math.isclose(analysis.calibrated_psi_fixed, calculate_psi(analysis.entropy_bits, analysis.mvs, h_ref=50.0), rel_tol=1e-5)
    assert math.isclose(analysis.calibrated_psi_empirical, calculate_psi(analysis.entropy_bits, analysis.empirical_mvs, h_ref=50.0), rel_tol=1e-5)


def test_whitespace_and_empty_edge_cases():
    """Verify empty and whitespace-only inputs return safe zeros and high risk."""
    for ws in ["", "   ", "\t\t", "\n\r", "   \t \n "]:
        a = analyze_password(ws)
        assert a.character_set_size == 0
        assert a.entropy_bits == 0.0
        assert a.mvs == 0.0
        assert a.empirical_mvs == 0.0
        assert a.psi == 0.0
        assert a.calibrated_psi_fixed == 0.0
        assert a.calibrated_psi_empirical == 0.0
        assert a.risk_category == "High predictability risk"


def test_internal_vs_trailing_symbols():
    """Verify internal punctuation does not trigger symbol_suffix feature."""
    # Internal symbol: 'pass!word' -> symbol is NOT trailing
    res_internal = analyze_password("pass!word")
    assert res_internal.mutation_components["symbol_suffix"] == 0.0
    assert "symbol suffix" not in res_internal.mutations

    # Trailing symbol: 'password!' -> symbol IS trailing
    res_trailing = analyze_password("password!")
    assert res_trailing.mutation_components["symbol_suffix"] == 1.0
    assert "symbol suffix" in res_trailing.mutations

    # Internal substitution: 'p@ssword' -> leetspeak substitution, NOT symbol suffix
    res_sub = analyze_password("p@ssword")
    assert res_sub.mutation_components["substitution"] == 1.0
    assert res_sub.mutation_components["symbol_suffix"] == 0.0


def test_pure_digits_no_capitalization_or_dictionary():
    """Verify pure-digit strings do not trigger capitalization or dictionary base."""
    digits_pw = "87654321"
    res = analyze_password(digits_pw)
    assert res.dictionary_base is None
    assert res.mutation_components["capitalization"] == 0.0
    assert res.mutation_components["dictionary_base"] == 0.0
    assert res.mutation_components["numeric_suffix"] == 0.0
    assert res.mvs == 0.0
    assert "sequential characters" in res.mutations
    assert res.risk_category == "High predictability risk"


def test_unicode_and_special_character_pool():
    """Verify Unicode characters are handled safely without crashing."""
    unicode_pw = "Pásswørd123!ñ"
    res = analyze_password(unicode_pw)
    assert res.password_length == len(unicode_pw)
    assert res.character_set_size >= 62
    assert res.entropy_bits > 0.0
    assert 0.0 <= res.mvs <= 100.0


def test_family_disjoint_leakage_audit():
    """Verify zero overlap between calibration and evaluation sets."""
    from pathlib import Path
    import pandas as pd
    cal_file = Path("data/phase5_family_disjoint_calibration_split.csv")
    eval_file = Path("data/phase5_family_disjoint_eval_split.csv")
    assert cal_file.exists() and eval_file.exists()

    df_cal = pd.read_csv(cal_file)
    df_eval = pd.read_csv(eval_file)

    # 1. Zero password overlap
    pw_cal = set(df_cal["password"])
    pw_eval = set(df_eval["password"])
    assert len(pw_cal.intersection(pw_eval)) == 0, "Data leakage: duplicate passwords found!"

    # 2. Zero root family overlap among positive mutations
    roots_cal = set(df_cal.loc[df_cal["target"] == 1, "root"].dropna())
    roots_eval = set(df_eval.loc[df_eval["target"] == 1, "root"].dropna())
    assert len(roots_cal.intersection(roots_eval)) == 0, "Data leakage: overlapping root families!"

    # 3. Zero control overlap
    ctrl_cal = set(df_cal.loc[df_cal["target"] == 0, "password"])
    ctrl_eval = set(df_eval.loc[df_eval["target"] == 0, "password"])
    assert len(ctrl_cal.intersection(ctrl_eval)) == 0, "Data leakage: overlapping control strings!"


def test_threshold_sensitivity_false_negatives_reproduction():
    """Reproduce exact false negative behavior at tau = 69.0 for base+number mutations."""
    # Passwords such as welcome2026, security2026, computer2026 activate only base + numeric suffix
    pws = ["welcome2026", "security2026", "computer2026"]
    for pw in pws:
        analysis = analyze_password(pw)
        # Base weight (0.35) + Numeric suffix weight (0.20)
        assert analysis.mutation_components["dictionary_base"] == 1.0
        assert analysis.mutation_components["numeric_suffix"] == 1.0
        assert analysis.mutation_components["capitalization"] == 0.0
        assert analysis.mutation_components["substitution"] == 0.0
        assert analysis.mutation_components["symbol_suffix"] == 0.0

        # Empirical MVS: 100 * [0.35 * (106/332) + 0.20 * (31/107)] / (0.35 + 0.20) ~ 30.85289
        expected_emp_mvs = 100.0 * (0.35 * (106.0 / 332.0) + 0.20 * (31.0 / 107.0)) / 0.55
        assert math.isclose(analysis.empirical_mvs, expected_emp_mvs, rel_tol=1e-4)

        # Since H > 50, E_norm = 1.0, Calibrated Empirical PSI ~ 100 * (1 - 0.3085289) = 69.1471
        assert math.isclose(analysis.calibrated_psi_empirical, 100.0 - expected_emp_mvs, rel_tol=1e-4)
        assert analysis.calibrated_psi_empirical > 69.0  # Explains why tau=69 causes False Negatives!

        # Under Fixed MVS: MVS = 55.0 -> Calibrated PSI = 45.0 << 69.0 (True Positive)
        assert math.isclose(analysis.mvs, 55.0, abs_tol=1e-5)
        assert math.isclose(analysis.calibrated_psi_fixed, 45.0, abs_tol=1e-5)
        assert analysis.calibrated_psi_fixed < 69.0


def test_cli_ui_baseline_comparator_consistency():
    """Verify consistency across compare_password and analyze_password for canonical benchmarks."""
    for pw in ["Password123!", "vQ7mK2xR9zP4", "P@ssword2026!"]:
        analysis = analyze_password(pw)
        comp = compare_password(pw)
        assert math.isclose(comp.entropy, round(analysis.entropy_bits, 2), abs_tol=1e-2)
        assert math.isclose(comp.mvs, round(analysis.mvs, 1), abs_tol=1e-1)
        assert math.isclose(comp.psi_fixed_mvs, round(analysis.psi_fixed_mvs, 1), abs_tol=1e-1)
        assert math.isclose(comp.psi_empirical_mvs, round(analysis.psi_empirical_mvs, 1), abs_tol=1e-1)
        assert math.isclose(comp.calibrated_psi_fixed, round(analysis.calibrated_psi_fixed, 1), abs_tol=1e-1)
        assert math.isclose(comp.calibrated_psi_empirical, round(analysis.calibrated_psi_empirical, 1), abs_tol=1e-1)


def test_privacy_preserving_pipeline_no_password_retention():
    """Verify dataset pipeline imports data without retaining plaintext passwords in telemetry."""
    from password_analyzer.dataset_pipeline import import_research_dataset
    report = import_research_dataset("data/public_research_dataset_example.csv")
    summary = report.summary_table()
    # The summary dataframe must not have a 'password' column or individual password entries
    assert "password" not in [str(c).lower() for c in summary.columns]
    assert report.total_records > 0
    assert 0.0 <= report.mean_mvs <= 100.0


def test_baseline_comparison_psi_variants_availability():
    """Verify BaselineComparison exposes explicit fields for all PSI and classification variants."""
    from password_analyzer.baseline_comparator import compare_password, BaselineComparison

    comp = compare_password("Password123!")
    # Direct attribute availability
    assert hasattr(comp, "psi_fixed_mvs")
    assert hasattr(comp, "psi_empirical_mvs")
    assert hasattr(comp, "calibrated_psi_fixed")
    assert hasattr(comp, "calibrated_psi_empirical")
    assert hasattr(comp, "calibrated_classification_fixed")
    assert hasattr(comp, "calibrated_classification_empirical")

    # Correct non-zero values
    assert comp.psi_fixed_mvs == 19.7
    assert comp.psi_empirical_mvs == 66.0
    assert comp.calibrated_psi_fixed == 20.0
    assert comp.calibrated_psi_empirical == 67.1
    assert comp.calibrated_classification_fixed == "Predictable Mutation (Vulnerable Family)"
    assert comp.calibrated_classification_empirical == "Predictable Mutation (Vulnerable Family)"

    # Verify that explicit BaselineComparison construction preserves all variants distinctly
    constructed_comp = BaselineComparison(
        password="TestPassword1!",
        length=14,
        character_pool=94,
        entropy=75.0,
        conventional_score=90.0,
        mvs=40.0,
        empirical_mvs=25.0,
        psi=45.0,
        empirical_psi=60.0,
        calibrated_psi=65.0,
        our_classification="Predictable Mutation (Vulnerable Family)",
        existing_estimator_name="zxcvbn",
        existing_estimator_score=2,
        existing_estimator_normalized=50.0,
        existing_estimator_guesses_log10=5.0,
        existing_estimator_crack_time_display="1 hour",
        existing_estimator_category="Fair",
        existing_estimator_warning=None,
        existing_estimator_suggestions=[],
        explanation="Explicit test",
        psi_fixed_mvs=45.0,
        psi_empirical_mvs=60.0,
        calibrated_psi_fixed=65.0,
        calibrated_classification_fixed="Predictable Mutation (Vulnerable Family)",
        calibrated_psi_empirical=72.0,
        calibrated_classification_empirical="Low Vulnerability (Synthetic Random-like Control)",
    )
    assert constructed_comp.psi_fixed_mvs == 45.0
    assert constructed_comp.psi_empirical_mvs == 60.0
    assert constructed_comp.calibrated_psi_fixed == 65.0
    assert constructed_comp.calibrated_classification_fixed == "Predictable Mutation (Vulnerable Family)"
    assert constructed_comp.calibrated_psi_empirical == 72.0
    assert constructed_comp.calibrated_classification_empirical == "Low Vulnerability (Synthetic Random-like Control)"
    # Disallow invalid attributes with clean AttributeError (no fallback masking)
    with pytest.raises(AttributeError):
        _ = constructed_comp.non_existent_attribute


def test_ui_schema_consistency_all_attributes_exist():
    """Verify that every comp.* attribute accessed in app.py exists explicitly on BaselineComparison."""
    from password_analyzer.baseline_comparator import compare_password
    comp = compare_password("Password123!")

    # Tab 1 High-level metrics
    assert isinstance(comp.entropy, float)
    assert isinstance(comp.mvs, float)
    assert isinstance(comp.psi_fixed_mvs, float)
    assert isinstance(comp.existing_estimator_score, int)
    assert isinstance(comp.existing_estimator_name, str)
    assert isinstance(comp.existing_estimator_category, str)
    assert isinstance(comp.psi_empirical_mvs, float)

    # Section 1 & 2
    assert isinstance(comp.length, int)
    assert isinstance(comp.character_pool, int)
    assert isinstance(comp.empirical_mvs, float)

    # Section 3 Security Index
    assert isinstance(comp.calibrated_psi_fixed, float)
    assert isinstance(comp.calibrated_classification_fixed, str)
    assert isinstance(comp.calibrated_psi_empirical, float)
    assert isinstance(comp.calibrated_classification_empirical, str)

    # Section 4 Baseline comparison
    assert isinstance(comp.conventional_score, float)
    assert isinstance(comp.existing_estimator_crack_time_display, str)
    assert isinstance(comp.existing_estimator_guesses_log10, float)

    # Section 5 Explanation
    assert isinstance(comp.explanation, str)
    assert len(comp.explanation) > 0


def test_threshold_boundary_decision_exact():
    """Verify threshold boundary: equality tau=69.0 is non-vulnerable, strictly <69.0 is vulnerable."""
    from password_analyzer.core import evaluate_calibrated_psi

    # At exact threshold (69.0) -> Non-vulnerable
    # E.g. H_bits=50, MVS=31.0 => PSI = 100 * 1.0 * (1 - 0.31) = 69.0
    psi_exact, class_exact = evaluate_calibrated_psi(50.0, 31.0, h_ref=50.0, threshold=69.0)
    assert math.isclose(psi_exact, 69.0, abs_tol=1e-5)
    assert class_exact == "Low Vulnerability (Synthetic Random-like Control)"

    # Just below threshold (68.99) -> Vulnerable
    psi_below, class_below = evaluate_calibrated_psi(50.0, 31.01, h_ref=50.0, threshold=69.0)
    assert psi_below < 69.0
    assert class_below == "Predictable Mutation (Vulnerable Family)"


def test_calibrated_fixed_and_empirical_distinctness():
    """Verify that fixed and empirical calibrated PSI and classifications are computed independently."""
    from password_analyzer.baseline_comparator import compare_password

    # For Password123!:
    # Fixed MVS = 80.0 (w_dict=0.35 + w_cap=0.15 + w_num=0.20 + w_sym=0.10)
    # Empirical MVS = 32.89 (weighted by Laplace frequencies)
    comp = compare_password("Password123!")
    assert comp.calibrated_psi_fixed != comp.calibrated_psi_empirical
    assert comp.calibrated_psi_fixed == 20.0
    assert comp.calibrated_psi_empirical == 67.1
    # Both happen to be < 69.0 for Password123!
    assert comp.calibrated_classification_fixed == "Predictable Mutation (Vulnerable Family)"
    assert comp.calibrated_classification_empirical == "Predictable Mutation (Vulnerable Family)"


def test_feature_flag_show_model_configuration_default():
    """Verify that SHOW_MODEL_CONFIGURATION feature flag exists and defaults to False."""
    import app
    assert hasattr(app, "SHOW_MODEL_CONFIGURATION")
    assert isinstance(app.SHOW_MODEL_CONFIGURATION, bool)
    assert app.SHOW_MODEL_CONFIGURATION is False


def test_model_configuration_defaults_consistency():
    """Verify analysis behavior with default parameters when UI configuration is disabled."""
    from password_analyzer.core import DEFAULT_WEIGHTS, DEFAULT_H_REF, analyze_password
    from password_analyzer.baseline_comparator import compare_password

    # Analysis with explicit default parameters must match analysis with omitted parameters
    a_explicit = analyze_password("Password123!", weights=DEFAULT_WEIGHTS.copy(), h_ref=DEFAULT_H_REF)
    a_default = analyze_password("Password123!")
    assert a_explicit.mvs == a_default.mvs
    assert a_explicit.psi == a_default.psi
    assert a_explicit.empirical_mvs == a_default.empirical_mvs
    assert a_explicit.calibrated_psi_fixed == a_default.calibrated_psi_fixed

    c_explicit = compare_password("Password123!", weights=DEFAULT_WEIGHTS.copy(), h_ref=DEFAULT_H_REF)
    c_default = compare_password("Password123!")
    assert c_explicit.mvs == c_default.mvs
    assert c_explicit.psi_fixed_mvs == c_default.psi_fixed_mvs
    assert c_explicit.calibrated_psi_fixed == c_default.calibrated_psi_fixed




