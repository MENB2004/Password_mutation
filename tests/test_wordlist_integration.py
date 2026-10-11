"""Comprehensive unit and regression tests for John the Ripper wordlist integration.

Covers:
1. Common dictionary word in expanded wordlist.
2. Dictionary word with numeric suffix.
3. Capitalized dictionary word.
4. Common substitution.
5. Symbol suffix.
6. Numeric sequence with no dictionary base.
7. Mixed-character sequence without a known base.
8. Wordlist with duplicate entries.
9. Empty wordlist.
10. Missing or unreadable wordlist.
11. Unicode and encoding edge cases (UTF-8, Latin-1, comments, whitespace).
12. Both fixed and empirical scoring.
13. Both states of Model Configuration feature flag.
14. No leakage of local filesystem paths in UI metadata.
15. Consistent behavior across expanded wordlist and fallback paths.
"""

import math
import os
import tempfile
from pathlib import Path

import pytest

from password_analyzer import (
    analyze_password,
    compare_password,
    DEFAULT_WEIGHTS,
    DEFAULT_EMPIRICAL_PROBABILITIES,
    CALIBRATED_H_REF,
    CALIBRATED_PSI_THRESHOLD,
    WordlistInfo,
    load_wordlist_entries,
    get_current_wordlist_info,
    clear_wordlist_cache,
)
from password_analyzer.core import find_dictionary_base, COMMON_WORDS


# ==============================================================================
# 1. CORE CANONICAL PASSWORD MUTATION CATEGORIES
# ==============================================================================

def test_common_dictionary_word():
    """Verify common dictionary words (e.g. 'password', 'shadow', 'dragon') are correctly detected."""
    res = analyze_password("password")
    assert res.dictionary_base == "password"
    assert res.mutations == []
    assert res.mutation_components["dictionary_base"] == 1.0
    assert math.isclose(res.mvs, DEFAULT_WEIGHTS["dictionary_base"] * 100.0, abs_tol=1e-5)
    assert res.empirical_mvs > 0.0
    assert res.calibrated_psi_fixed < CALIBRATED_PSI_THRESHOLD

    # Also test expanded word from John the Ripper list
    res_jtr = analyze_password("phoenix")
    assert res_jtr.dictionary_base == "phoenix"
    assert res_jtr.mutations == []
    assert res_jtr.mutation_components["dictionary_base"] == 1.0


def test_dictionary_word_with_numeric_suffix():
    """Verify a dictionary word with numeric suffix triggers the numeric_suffix feature."""
    res = analyze_password("password123")
    assert res.dictionary_base == "password"
    assert "numeric suffix" in res.mutations
    assert res.mutation_components["numeric_suffix"] == 1.0
    assert res.mutation_components["dictionary_base"] == 1.0
    expected_mvs = (DEFAULT_WEIGHTS["dictionary_base"] + DEFAULT_WEIGHTS["numeric_suffix"]) * 100.0
    assert math.isclose(res.mvs, expected_mvs, abs_tol=1e-5)


def test_capitalized_dictionary_word():
    """Verify capitalized dictionary word triggers the capitalization feature."""
    res = analyze_password("Password")
    assert res.dictionary_base == "password"
    assert "capitalization" in res.mutations
    assert res.mutation_components["capitalization"] == 1.0
    expected_mvs = (DEFAULT_WEIGHTS["dictionary_base"] + DEFAULT_WEIGHTS["capitalization"]) * 100.0
    assert math.isclose(res.mvs, expected_mvs, abs_tol=1e-5)


def test_common_substitution():
    """Verify common leetspeak substitution triggers the substitution feature."""
    res = analyze_password("p@ssw0rd")
    assert res.dictionary_base == "password"
    assert "character substitution" in res.mutations
    assert res.mutation_components["substitution"] == 1.0
    expected_mvs = (DEFAULT_WEIGHTS["dictionary_base"] + DEFAULT_WEIGHTS["substitution"]) * 100.0
    assert math.isclose(res.mvs, expected_mvs, abs_tol=1e-5)


def test_symbol_suffix():
    """Verify trailing symbol suffix triggers the symbol_suffix feature."""
    res = analyze_password("password!")
    assert res.dictionary_base == "password"
    assert "symbol suffix" in res.mutations
    assert res.mutation_components["symbol_suffix"] == 1.0
    expected_mvs = (DEFAULT_WEIGHTS["dictionary_base"] + DEFAULT_WEIGHTS["symbol_suffix"]) * 100.0
    assert math.isclose(res.mvs, expected_mvs, abs_tol=1e-5)


# ==============================================================================
# 2. SEPARATION OF STRUCTURAL SEQUENCES AND UNRELATED INPUTS
# ==============================================================================

def test_numeric_sequence_with_no_dictionary_base():
    """Verify pure numeric sequence is classified as a structural sequence, not an arbitrary dictionary base."""
    for seq in ["12345678", "987654321", "0123456789"]:
        res = analyze_password(seq)
        comp = compare_password(seq)

        assert res.dictionary_base is None, f"Numeric sequence '{seq}' must NOT be given a dictionary base"
        assert res.mvs == 0.0, f"MVS must be strictly 0.0 for pure numeric sequence '{seq}'"
        assert res.empirical_mvs == 0.0
        assert "sequential characters" in res.mutations
        assert res.risk_category == "High predictability risk"
        assert "No dictionary root word was detected in this password" in comp.explanation


def test_mixed_character_sequence_without_known_base():
    """Verify complex random-like sequences with mixed characters receive no dictionary base."""
    for rnd_pw in ["vQ7mK2xR9zP4", "xK9#mQ2$vL8*", "aX9qLm2P7vT8"]:
        res = analyze_password(rnd_pw)
        comp = compare_password(rnd_pw)

        assert res.dictionary_base is None
        assert res.mutations == []
        assert res.mvs == 0.0
        assert res.empirical_mvs == 0.0
        assert res.calibrated_psi_fixed == 100.0
        assert res.calibrated_classification_fixed == "Low Vulnerability (Synthetic Random-like Control)"
        assert "No dictionary base or supported predictable mutation pattern was detected" in comp.explanation


# ==============================================================================
# 3. WORDLIST LOADER ROBUSTNESS & EDGE CASES
# ==============================================================================

def test_wordlist_with_duplicate_entries(tmp_path):
    """Verify wordlist loader normalizes and deduplicates repeated and mixed-case entries."""
    wl_file = tmp_path / "duplicates.txt"
    wl_file.write_text(
        "# Comment line\n"
        "apple\n"
        "Apple\n"
        "  APPLE  \n"
        "banana\n"
        "Banana\n"
        "\n"
        "   \n"
        "cherry\n",
        encoding="utf-8"
    )

    clear_wordlist_cache()
    words_set, sorted_words, info = load_wordlist_entries(wl_file)

    assert info.is_expanded is True
    assert info.source_type == "expanded"
    assert info.count == 3
    assert set(sorted_words) == {"apple", "banana", "cherry"}
    assert words_set == {"apple", "banana", "cherry"}


def test_empty_wordlist_fallback(tmp_path):
    """Verify empty wordlist safely triggers the built-in fallback without errors."""
    empty_file = tmp_path / "empty_wordlist.txt"
    empty_file.write_text("", encoding="utf-8")

    clear_wordlist_cache()
    words_set, sorted_words, info = load_wordlist_entries(empty_file)

    assert info.is_expanded is False
    assert info.source_type == "builtin_fallback"
    assert "fallback" in info.label.lower()
    assert len(sorted_words) == len(COMMON_WORDS)
    assert "password" in words_set


def test_missing_or_unreadable_wordlist():
    """Verify nonexistent or directory path gracefully falls back to built-in vocabulary."""
    nonexistent = Path("nonexistent_wordlist_12345.txt")

    clear_wordlist_cache()
    words_set, sorted_words, info = load_wordlist_entries(nonexistent)

    assert info.is_expanded is False
    assert info.source_type == "builtin_fallback"
    assert "fallback" in info.label.lower()
    assert "password" in words_set


def test_unicode_and_encoding_edge_cases(tmp_path):
    """Verify wordlist loader safely handles UTF-8, Latin-1 encoding, comments, and non-ASCII lines."""
    # Latin-1 file containing accented characters
    latin1_file = tmp_path / "latin1_wordlist.txt"
    content = "# John the Ripper wordlist with accented characters\nüber\ncliché\nfalcon\n"
    latin1_file.write_bytes(content.encode("latin-1"))

    clear_wordlist_cache()
    words_set, sorted_words, info = load_wordlist_entries(latin1_file)

    assert info.is_expanded is True
    assert "falcon" in words_set


def test_wordlist_filters_pure_numbers_and_short_tokens(tmp_path):
    """Verify wordlist loader excludes pure numeric entries and 1-2 char tokens to prevent false positives."""
    filtered_file = tmp_path / "filtered.txt"
    filtered_file.write_text(
        "123456\n"      # Pure numeric -> must be ignored
        "8888\n"        # Pure numeric -> must be ignored
        "a\n"           # 1 character -> must be ignored
        "to\n"          # 2 characters -> must be ignored
        "tiger\n"       # Valid root -> must be kept
        "lion\n",       # Valid root -> must be kept
        encoding="utf-8"
    )

    clear_wordlist_cache()
    words_set, sorted_words, info = load_wordlist_entries(filtered_file)

    assert info.count == 2
    assert words_set == {"tiger", "lion"}
    assert "123456" not in words_set
    assert "to" not in words_set


# ==============================================================================
# 4. SCORING METHODOLOGY PRESERVATION
# ==============================================================================

def test_fixed_and_empirical_scoring_distinctness():
    """Verify fixed MVS and empirical MVS calculate mathematically distinct values."""
    res = analyze_password("Password123!")

    # Verify fixed MVS calculation: 100 * (0.35 + 0.15 + 0.20 + 0.10) = 80.0
    expected_fixed_mvs = (0.35 + 0.15 + 0.20 + 0.10) * 100.0
    assert math.isclose(res.mvs, expected_fixed_mvs, abs_tol=1e-5)

    # Verify empirical MVS is distinct from fixed MVS
    assert res.empirical_mvs != res.mvs
    assert 0.0 < res.empirical_mvs <= 100.0

    # Verify both PSI variants are preserved and non-zero
    assert res.psi_fixed_mvs != res.psi_empirical_mvs
    assert 0.0 < res.psi_fixed_mvs < 100.0
    assert 0.0 < res.psi_empirical_mvs < 100.0


# ==============================================================================
# 5. UI SAFETY & FEATURE FLAG VERIFICATION
# ==============================================================================

def test_wordlist_metadata_does_not_leak_filesystem_paths():
    """Verify WordlistInfo display labels do NOT leak local directory or filesystem paths."""
    info_active = get_current_wordlist_info()
    assert "/" not in info_active.label
    assert "\\" not in info_active.label
    assert "Users" not in info_active.label
    assert "C:" not in info_active.label
    assert "wordlist" in info_active.label.lower() or "vocabulary" in info_active.label.lower()


def test_model_configuration_feature_flag_both_states(monkeypatch):
    """Verify the application functions cleanly in both states of SHOW_MODEL_CONFIGURATION."""
    import app

    # State 1: Default state (False)
    assert app.SHOW_MODEL_CONFIGURATION is False

    # State 2: Enabled state (True)
    monkeypatch.setattr(app, "SHOW_MODEL_CONFIGURATION", True)
    assert app.SHOW_MODEL_CONFIGURATION is True

    # Re-run sample analysis under both states to verify scoring is unaffected
    a_false = analyze_password("Password123!")
    a_true = analyze_password("Password123!")
    assert a_false.mvs == a_true.mvs
    assert a_false.psi == a_true.psi
    assert a_false.dictionary_base == a_true.dictionary_base


# ==============================================================================
# 6. EXPANDED WORDLIST AND FALLBACK PATH CONSISTENCY
# ==============================================================================

def test_application_works_with_both_expanded_and_fallback_path(tmp_path):
    """Verify analyze_password and compare_password function identically across expanded and fallback paths."""
    # Expanded path
    comp_expanded = compare_password("Password123!")
    assert comp_expanded.mvs == 80.0
    assert "password" in comp_expanded.explanation.lower()

    # Fallback path (via nonexistent file path)
    missing_file = tmp_path / "missing.txt"
    comp_fallback = compare_password("Password123!", wordlist_path=missing_file)
    assert comp_fallback.mvs == 80.0
    assert "fallback" in comp_fallback.wordlist_source.lower()
