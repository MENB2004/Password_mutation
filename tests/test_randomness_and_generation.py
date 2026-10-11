"""Automated Test Suite: Password Randomness Assessment and Generation Assurance.

Tests:
1. Theoretical Character-Pool Entropy calculations and edge cases.
2. Cryptographically secure password generator (CSPRNG via secrets).
3. Configured character-pool and length enforcement.
4. Invalid, zero-length, and empty generator configuration validation.
5. Generation provenance and assurance semantics (CSPRNG vs user-entered).
6. Single-password statistical diagnostics and sample-size prerequisite handling (Not applicable for Chi-Square).
7. Controlled batch generator validation (n=100, Chi-Square uniformity, empirical Shannon entropy ratio).
8. Qualified assessment text integrity (no false claims of 'Proven Random' or 'Guaranteed Secure').
9. Preservation of existing fixed and empirical MVS, PSI, and wordlist fallback behavior.
10. Streamlit AppTest headless execution across all tabs including Tab 7.
"""

import math
import string
import pytest
from streamlit.testing.v1 import AppTest

from password_analyzer.core import (
    analyze_password,
    DEFAULT_WEIGHTS,
    DEFAULT_H_REF,
    CALIBRATED_H_REF,
    CALIBRATED_PSI_THRESHOLD,
)
from password_analyzer.baseline_comparator import (
    compare_password,
    BaselineComparison,
)
from password_analyzer.wordlist import (
    get_current_wordlist_info,
    CURATED_WORDLIST_PATH,
    OFFICIAL_OPENWALL_PATH,
)
from password_analyzer.randomness import (
    GeneratorConfig,
    GenerationResult,
    generate_secure_password,
    calculate_configured_entropy,
    assess_single_password_randomness,
    validate_generator_batch,
    build_qualified_randomness_assessment,
    DiagnosticTest,
    StatisticalDiagnosticResult,
    BatchValidationResult,
    PROVENANCE_GENERATED,
    PROVENANCE_USER_ENTERED,
    ASSURANCE_GENERATED,
    ASSURANCE_USER_ENTERED,
    METHOD_DESCRIPTION_GENERATED,
    METHOD_DESCRIPTION_USER_ENTERED,
)


# ==============================================================================
# 1. THEORETICAL CHARACTER-POOL ENTROPY & EDGE CASES
# ==============================================================================

def test_theoretical_entropy_formula():
    """Verify H = L * log2(N) under uniform independent drawing."""
    # Length 16, Alphabet 94
    h_94_16 = calculate_configured_entropy(16, 94)
    expected = 16 * math.log2(94)
    assert math.isclose(h_94_16, expected, rel_tol=1e-9)
    assert h_94_16 > 104.0

    # Length 10, Alphabet 26 (lowercase only)
    h_26_10 = calculate_configured_entropy(10, 26)
    assert math.isclose(h_26_10, 10 * math.log2(26), rel_tol=1e-9)

    # Edge cases: 0 length or 0 pool
    assert calculate_configured_entropy(0, 94) == 0.0
    assert calculate_configured_entropy(-5, 94) == 0.0
    assert calculate_configured_entropy(16, 0) == 0.0
    assert calculate_configured_entropy(16, -10) == 0.0


# ==============================================================================
# 2. CSPRNG PASSWORD GENERATOR & CONFIG VALIDATION
# ==============================================================================

def test_csprng_generator_default_config():
    """Verify default generator produces requested length and only allowed characters."""
    cfg = GeneratorConfig()
    result = generate_secure_password(cfg)

    assert isinstance(result, GenerationResult)
    assert len(result.password) == 16
    assert result.length == 16
    assert result.alphabet_size == len(cfg.get_character_pool())
    assert result.is_generated is True
    assert result.generation_method == PROVENANCE_GENERATED
    assert result.generation_assurance == ASSURANCE_GENERATED
    assert "secrets" in result.method_explanation.lower()

    # All characters must belong to the configured pool
    pool_set = set(cfg.get_character_pool())
    assert all(c in pool_set for c in result.password)


def test_csprng_generator_character_classes():
    """Verify generator honors specific character class selections."""
    # Digits only
    cfg_digits = GeneratorConfig(length=20, use_lowercase=False, use_uppercase=False, use_digits=True, use_symbols=False)
    res_digits = generate_secure_password(cfg_digits)
    assert len(res_digits.password) == 20
    assert res_digits.alphabet_size == 10
    assert all(c in string.digits for c in res_digits.password)

    # Lowercase only
    cfg_lower = GeneratorConfig(length=12, use_lowercase=True, use_uppercase=False, use_digits=False, use_symbols=False)
    res_lower = generate_secure_password(cfg_lower)
    assert len(res_lower.password) == 12
    assert res_lower.alphabet_size == 26
    assert all(c in string.ascii_lowercase for c in res_lower.password)


def test_generator_config_validation_errors():
    """Verify GeneratorConfig raises ValueError for invalid inputs."""
    # Length < 1
    with pytest.raises(ValueError, match="at least 1"):
        GeneratorConfig(length=0).validate()

    with pytest.raises(ValueError, match="at least 1"):
        GeneratorConfig(length=-5).validate()

    # Length > 512
    with pytest.raises(ValueError, match="cannot exceed 512"):
        GeneratorConfig(length=513).validate()

    # Empty character pool (all classes disabled)
    with pytest.raises(ValueError, match="At least one character class"):
        GeneratorConfig(use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False).validate()


# ==============================================================================
# 3. PROVENANCE & GENERATION ASSURANCE SEMANTICS
# ==============================================================================

def test_provenance_semantics_generated_vs_entered():
    """Verify clear distinction between generated and user-entered passwords."""
    # Generated password analysis
    gen_analysis = analyze_password(
        "K9#mX2$pL7!wQ4@v",
        generation_provenance=PROVENANCE_GENERATED,
        generation_assurance=ASSURANCE_GENERATED,
    )
    assert gen_analysis.generation_provenance == PROVENANCE_GENERATED
    assert gen_analysis.generation_assurance == ASSURANCE_GENERATED

    # User-entered password analysis (default)
    user_analysis = analyze_password("K9#mX2$pL7!wQ4@v")
    assert user_analysis.generation_provenance == PROVENANCE_USER_ENTERED
    assert user_analysis.generation_assurance == ASSURANCE_USER_ENTERED
    assert "Unknown" in user_analysis.generation_assurance

    # BaselineComparison preserves provenance
    comp = compare_password(
        "K9#mX2$pL7!wQ4@v",
        generation_provenance=PROVENANCE_GENERATED,
        generation_assurance=ASSURANCE_GENERATED,
    )
    assert comp.generation_provenance == PROVENANCE_GENERATED
    assert comp.generation_assurance == ASSURANCE_GENERATED


# ==============================================================================
# 4. SINGLE-PASSWORD STATISTICAL DIAGNOSTICS & APPLICABILITY
# ==============================================================================

def test_single_password_diagnostics_short_password():
    """Verify asymptotic tests (Chi-Square) are marked Not applicable on short passwords."""
    diag = assess_single_password_randomness("vQ7mK2xR9zP4", assumed_pool_size=94)

    assert diag.sample_type == "Single Password"
    assert diag.sample_size == 12

    # Chi-Square must be Not applicable
    chi2_test = next(t for t in diag.tests if t.test_name == "Pearson Chi-Square Uniformity Test")
    assert chi2_test.status == "Not applicable"
    assert "E_i < 5" in chi2_test.what_it_cannot_establish or "underflow" in chi2_test.what_it_cannot_establish

    # Positional independence must be Not applicable for n=1
    pos_test = next(t for t in diag.tests if t.test_name == "Position-Specific Independence Test")
    assert pos_test.status == "Not applicable"


def test_single_password_diagnostics_repetitive_run():
    """Verify repetition run test detects excessive identical runs."""
    diag_rep = assess_single_password_randomness("aaaa12345678", assumed_pool_size=94)
    run_test = next(t for t in diag_rep.tests if t.test_name == "Maximum Consecutive Identical Run")
    assert run_test.status == "Failed"
    assert "Max run = 4" in run_test.observed_value


def test_single_password_diagnostics_empty_input():
    """Verify empty input is handled safely."""
    diag_empty = assess_single_password_randomness("")
    assert diag_empty.sample_size == 0
    assert diag_empty.failed_count >= 1


# ==============================================================================
# 5. CONTROLLED BATCH GENERATOR DIAGNOSTICS
# ==============================================================================

def test_batch_generator_diagnostics():
    """Verify validate_generator_batch executes on synthetic batch of n=100 samples."""
    cfg = GeneratorConfig(length=16, use_lowercase=True, use_uppercase=True, use_digits=True, use_symbols=False)
    # alphabet size = 26 + 26 + 10 = 62. Total chars = 100 * 16 = 1600.
    # Expected per bin = 1600 / 62 = 25.8 >= 5.0, so Chi-Square is applicable.
    batch_res = validate_generator_batch(cfg, batch_size=100)

    assert isinstance(batch_res, BatchValidationResult)
    assert batch_res.batch_size == 100
    assert batch_res.configured_length == 16
    assert batch_res.configured_alphabet_size == 62
    assert batch_res.total_characters_evaluated == 1600

    # Containment must pass
    containment_test = next(t for t in batch_res.tests if t.test_name == "Alphabet & Length Enforcement")
    assert containment_test.status == "Passed"

    # Chi-Square must be applicable and pass for CSPRNG
    chi2_test = next(t for t in batch_res.tests if t.test_name == "Aggregate Chi-Square Uniformity Test")
    assert chi2_test.status == "Passed"

    # Empirical Shannon entropy ratio must exceed 95%
    entropy_test = next(t for t in batch_res.tests if t.test_name == "Empirical Shannon Entropy Ratio")
    assert entropy_test.status == "Passed"
    assert batch_res.entropy_efficiency_ratio >= 0.95


# ==============================================================================
# 6. QUALIFIED OVERALL RANDOMNESS ASSESSMENT BUILDER
# ==============================================================================

def test_qualified_assessment_no_false_claims():
    """Verify assessment wording never claims 'Proven Random' or 'Guaranteed Secure'."""
    # User entered password with no dictionary matches
    qa_user = build_qualified_randomness_assessment(
        "vQ7mK2xR9zP4",
        is_generated=False,
        dictionary_base=None,
        mutations=[],
        assumed_pool=94,
    )
    assert "Proven Random" not in qa_user.qualified_summary
    assert "Guaranteed Secure" not in qa_user.qualified_summary
    assert "generation process is unknown" in qa_user.qualified_summary
    assert "cannot be verified from the entered string alone" in qa_user.qualified_summary
    assert qa_user.generation_provenance == PROVENANCE_USER_ENTERED

    # Application generated password
    qa_gen = build_qualified_randomness_assessment(
        "vQ7mK2xR9zP4",
        is_generated=True,
        dictionary_base=None,
        mutations=[],
        assumed_pool=94,
    )
    assert "Proven Random" not in qa_gen.qualified_summary
    assert "Guaranteed Secure" not in qa_gen.qualified_summary
    assert "secrets" in qa_gen.qualified_summary
    assert "cannot prove physical randomness" in qa_gen.qualified_summary
    assert qa_gen.generation_provenance == PROVENANCE_GENERATED


# ==============================================================================
# 7. PRESERVATION OF EXISTING SCORING & WORDLIST METHODOLOGY
# ==============================================================================

def test_preservation_of_fixed_and_empirical_mvs_psi():
    """Verify that adding randomness features did not alter MVS/PSI calculations."""
    pw = "Password123!"
    analysis = analyze_password(pw)

    # Dictionary base remains 'password'
    assert analysis.dictionary_base == "password"
    assert "capitalization" in analysis.mutations
    assert "numeric suffix" in analysis.mutations
    assert "symbol suffix" in analysis.mutations

    # MVS values remain intact
    assert analysis.mvs > 0.0
    assert analysis.empirical_mvs > 0.0
    assert analysis.psi_fixed_mvs < 50.0
    assert analysis.calibrated_classification_empirical == "Predictable Mutation (Vulnerable Family)"


def test_wordlist_fallback_preservation():
    """Verify wordlist resolution tiers remain functional."""
    info_curated = get_current_wordlist_info(CURATED_WORDLIST_PATH)
    assert info_curated.count >= 2800

    info_openwall = get_current_wordlist_info(OFFICIAL_OPENWALL_PATH)
    assert info_openwall.source_type == "official_openwall"


# ==============================================================================
# 8. STREAMLIT APPTEST HEADLESS UI VALIDATION
# ==============================================================================

def test_streamlit_app_renders_all_tabs_without_exceptions():
    """Verify that Streamlit app initializes cleanly and renders Tab 7."""
    at = AppTest.from_file("../app.py")
    at.run(timeout=15)
    assert not at.exception

    # Check title
    assert len(at.title) >= 1
    assert "Password Strength & Predictable Mutation Analysis" in at.title[0].value

    # Check tabs count (7 tabs)
    assert len(at.tabs) == 7
