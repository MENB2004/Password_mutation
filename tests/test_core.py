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
    assert "No dictionary base was detected" in comp_rand.explanation

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
    assert rep_res.mvs > 50.0
    assert "repetitive characters" in rep_res.mutations
    assert rep_res.risk_category == "High predictability risk"

    # 2. Sequential digits
    seq_res = analyze_password("123456789012")
    assert seq_res.mvs > 50.0
    assert "sequential characters" in seq_res.mutations
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



