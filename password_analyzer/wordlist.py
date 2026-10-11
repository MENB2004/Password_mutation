"""Wordlist provider and loader module supporting John the Ripper-compatible wordlists.

Provides cached loading, normalization, deduplication, encoding fallback,
and graceful degradation to built-in vocabulary if external wordlists are missing.
No external network downloads or system tool dependencies are required.
"""

import functools
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Set, Tuple, Union

# Default bundled wordlist location relative to package directory
_DEFAULT_WORDLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "wordlists" / "jtr_common_roots.txt"
ENV_WORDLIST_PATH = "PASSWORD_MUTATION_WORDLIST_PATH"


@dataclass(frozen=True)
class WordlistInfo:
    """Public metadata describing the active dictionary provider source.

    Designed to provide concise UI indicators without leaking local filesystem paths.
    """
    source_type: str        # 'expanded' or 'builtin_fallback'
    count: int              # Number of unique root entries
    label: str              # User-facing summary badge (e.g. 'Expanded wordlist (JtR-compatible, 2,836 roots)')
    is_expanded: bool       # True if loaded from external/bundled wordlist file, False if fallback


def _get_builtin_words() -> Tuple[str, ...]:
    """Retrieve the core built-in fallback word tuple from core module."""
    from .core import COMMON_WORDS
    clean = {w.strip().lower() for w in COMMON_WORDS if len(w.strip()) >= 3 and any(c.isalpha() for c in w)}
    return tuple(sorted(clean, key=lambda w: (len(w), w), reverse=True))


@functools.lru_cache(maxsize=16)
def _load_wordlist_file_cached(resolved_path_str: Optional[str]) -> Tuple[Tuple[str, ...], WordlistInfo]:
    """Internal cached file reader for plain-text wordlists.

    Handles UTF-8 with latin-1 fallback, deduplication, comment stripping,
    blank-line removal, and graceful fallback if file is missing, empty, or unreadable.
    """
    if resolved_path_str is not None:
        target_path = Path(resolved_path_str)
        if target_path.is_file():
            try:
                # Primary attempt: UTF-8 decoding
                try:
                    with open(target_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except UnicodeDecodeError:
                    # Secondary fallback: latin-1 decoding with character replacement
                    with open(target_path, "r", encoding="latin-1", errors="replace") as f:
                        lines = f.readlines()

                unique_entries = set()
                for line in lines:
                    stripped = line.strip()
                    # Skip empty lines and comment lines (John the Ripper / rule list syntax)
                    if not stripped or stripped.startswith("#"):
                        continue
                    normalized = stripped.lower()
                    # Keep valid root words: must be at least 3 chars and contain alphabetic letters
                    # (Pure numeric sequences like '123456' must NOT be treated as dictionary roots)
                    if len(normalized) >= 3 and any(c.isalpha() for c in normalized):
                        unique_entries.add(normalized)

                if unique_entries:
                    # Sort by length descending for longest-match-first matching
                    sorted_entries = tuple(sorted(unique_entries, key=lambda w: (len(w), w), reverse=True))
                    info = WordlistInfo(
                        source_type="expanded",
                        count=len(sorted_entries),
                        label=f"Expanded wordlist (JtR-compatible, {len(sorted_entries):,} roots)",
                        is_expanded=True,
                    )
                    return sorted_entries, info
            except (OSError, PermissionError):
                pass  # Fall through to built-in fallback

    # Built-in fallback when file is missing, empty, unreadable, or not specified
    fallback_entries = _get_builtin_words()
    info = WordlistInfo(
        source_type="builtin_fallback",
        count=len(fallback_entries),
        label=f"Built-in vocabulary (fallback, {len(fallback_entries)} roots)",
        is_expanded=False,
    )
    return fallback_entries, info


def clear_wordlist_cache() -> None:
    """Clear internal LRU cache for wordlist loading (useful during tests)."""
    _load_wordlist_file_cached.cache_clear()


def resolve_wordlist_path(file_path: Optional[Union[str, Path]] = None) -> Optional[str]:
    """Resolve wordlist path from explicit argument, environment variable, or default bundled path."""
    if file_path is not None:
        return str(Path(file_path).resolve())

    env_path = os.environ.get(ENV_WORDLIST_PATH)
    if env_path:
        return str(Path(env_path).resolve())

    if _DEFAULT_WORDLIST_PATH.is_file():
        return str(_DEFAULT_WORDLIST_PATH.resolve())

    return None


def load_wordlist_entries(file_path: Optional[Union[str, Path]] = None) -> Tuple[Set[str], Tuple[str, ...], WordlistInfo]:
    """Load wordlist entries and return (words_set, sorted_words_tuple, wordlist_info).

    Parameters:
      file_path: Optional path to a plain-text wordlist file. If None, checks
                 the environment variable or default bundled location.
                 Falls back safely to built-in COMMON_WORDS if unreadable or absent.

    Returns:
      words_set: Set of lowercase root words for O(1) membership testing.
      sorted_words: Tuple of words sorted by length descending for substring detection.
      wordlist_info: WordlistInfo metadata for clean UI display.
    """
    resolved = resolve_wordlist_path(file_path)
    sorted_words, info = _load_wordlist_file_cached(resolved)
    return set(sorted_words), sorted_words, info


def get_current_wordlist_info(file_path: Optional[Union[str, Path]] = None) -> WordlistInfo:
    """Retrieve metadata about the currently active dictionary provider."""
    _, _, info = load_wordlist_entries(file_path)
    return info


def get_active_wordlist(file_path: Optional[Union[str, Path]] = None) -> Tuple[Set[str], Tuple[str, ...]]:
    """Retrieve active word set and length-sorted word tuple."""
    words_set, sorted_words, _ = load_wordlist_entries(file_path)
    return words_set, sorted_words
