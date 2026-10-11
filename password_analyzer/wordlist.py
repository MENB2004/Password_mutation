"""Wordlist provider and loader module supporting official Openwall wordlists and curated fallbacks.

Provides cached loading, normalization, deduplication, encoding fallback,
transparent gzip (.gz) decompression, and graceful degradation across a multi-tier hierarchy:
  1. Official Openwall wordlist (password.gz / openwall_passwords.txt.gz)
  2. Curated John the Ripper-compatible root wordlist (jtr_common_roots.txt, 2,833 roots)
  3. Built-in vocabulary (COMMON_WORDS, 124 roots)

No external network calls are performed on application startup.
"""

import functools
import gzip
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

# Paths relative to the project root
_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "wordlists"
OFFICIAL_OPENWALL_PATH = _DATA_DIR / "openwall_passwords.txt.gz"
CURATED_WORDLIST_PATH = _DATA_DIR / "jtr_common_roots.txt"

# Environment variables for configuration
ENV_WORDLIST_PATH = "PASSWORD_MUTATION_WORDLIST_PATH"
ENV_OPENWALL_PATH = "OPENWALL_WORDLIST_PATH"
ENV_PREFER_OPENWALL = "PASSWORD_MUTATION_PREFER_OPENWALL"

# Official Openwall distribution metadata
OPENWALL_METADATA: Dict[str, Any] = {
    "provider": "Openwall Project",
    "author": "Solar Designer (Alexander Peslyak)",
    "copyright": "Solar Designer / Openwall",
    "homepage": "https://www.openwall.com/wordlists/",
    "source_url": "https://download.openwall.net/pub/wordlists/passwords/password.gz",
    "filename": "password.gz",
    "version": "2011/11/20 (3546 entries)",
    "last_modified": "20-Nov-2011 20:12:00 GMT",
    "download_date": "2026-10-12",
    "retrieval_date": "October 12, 2026",
    "compressed_sha256": "1e7a12ddd07cfbdd7c3b774230be33968e506072ae6fec4ff195b577f51fb6c1",
    "uncompressed_sha256": "2dd79902220fa879a330d9246da147984b705087a52ad17de3803acfafe7badc",
    "license": "Solar Designer / Openwall (free for personal, educational, research, and non-commercial use)",
    "license_url": "https://www.openwall.com/wordlists/LICENSE.shtml",
}


@dataclass(frozen=True)
class WordlistInfo:
    """Public metadata describing the active dictionary provider source.

    Designed to provide concise UI indicators without leaking local filesystem paths.
    """
    source_type: str                  # 'official_openwall', 'curated', 'custom', 'builtin_fallback'
    count: int                        # Number of unique root entries
    label: str                        # User-facing summary badge (e.g. 'Official Openwall wordlist (3,254 entries)')
    is_expanded: bool                 # True if loaded from external/bundled wordlist file, False if fallback
    is_official: bool = False         # True if loaded from official Openwall distribution
    file_format: str = "plaintext"    # 'gzip', 'plaintext', or 'builtin'
    sha256_checksum: Optional[str] = None


def get_openwall_provenance() -> Dict[str, Any]:
    """Retrieve verified provenance metadata for the official Openwall wordlist."""
    return OPENWALL_METADATA.copy()


def _get_builtin_words() -> Tuple[str, ...]:
    """Retrieve the core built-in fallback word tuple from core module."""
    from .core import COMMON_WORDS
    clean = {w.strip().lower() for w in COMMON_WORDS if len(w.strip()) >= 3 and any(c.isalpha() for c in w)}
    return tuple(sorted(clean, key=lambda w: (len(w), w), reverse=True))


def _read_file_content_and_checksum(target_path: Path) -> Tuple[List[str], str, str]:
    """Read lines from a plain-text or gzip-compressed file and calculate its SHA-256.

    Returns:
      (lines, file_format, sha256_hex)
    """
    with open(target_path, "rb") as f:
        raw_bytes = f.read()

    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    is_gzip = target_path.suffix.lower() == ".gz" or str(target_path).lower().endswith(".gz")

    if is_gzip:
        decompressed = gzip.decompress(raw_bytes)
        try:
            text = decompressed.decode("utf-8")
        except UnicodeDecodeError:
            text = decompressed.decode("latin-1", errors="replace")
        file_format = "gzip"
    else:
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = raw_bytes.decode("latin-1", errors="replace")
        file_format = "plaintext"

    lines = text.splitlines()
    return lines, file_format, sha256_hash


def _get_builtin_words_with_info() -> Tuple[Tuple[str, ...], WordlistInfo]:
    """Return built-in fallback word tuple and associated WordlistInfo metadata."""
    fallback_entries = _get_builtin_words()
    info = WordlistInfo(
        source_type="builtin_fallback",
        count=len(fallback_entries),
        label=f"Built-in vocabulary (fallback, {len(fallback_entries)} roots)",
        is_expanded=False,
        is_official=False,
        file_format="builtin",
        sha256_checksum=None,
    )
    return fallback_entries, info


@functools.lru_cache(maxsize=16)
def _load_wordlist_file_cached(resolved_path_str: Optional[str]) -> Tuple[Tuple[str, ...], WordlistInfo]:
    """Internal cached file reader for plain-text and gzip-compressed wordlists.

    Handles UTF-8 with latin-1 fallback, deduplication, comment stripping,
    blank-line removal, and graceful fallback across all tiers.
    """
    if resolved_path_str is None or resolved_path_str in ("__builtin__", "builtin_fallback"):
        return _get_builtin_words_with_info()

    target_path = Path(resolved_path_str)
    is_openwall = (
        "openwall" in target_path.name.lower() or
        target_path.name.lower() in ("password.gz", "password.lst", "password.txt")
    )

    if target_path.is_file():
        try:
            lines, file_fmt, checksum = _read_file_content_and_checksum(target_path)
            if checksum == OPENWALL_METADATA["compressed_sha256"] or checksum == OPENWALL_METADATA["uncompressed_sha256"]:
                is_openwall = True

            unique_entries = set()
            for line in lines:
                stripped = line.strip()
                # Skip empty lines and comment lines (# or #!comment: syntax from Openwall)
                if not stripped or stripped.startswith("#"):
                    continue
                normalized = stripped.lower()
                # Filter valid entries: length >= 3 and must contain alphabetic characters
                # (Pure numeric sequences like '123456' must NOT be treated as dictionary roots)
                if len(normalized) >= 3 and any(c.isalpha() for c in normalized):
                    unique_entries.add(normalized)

            if unique_entries:
                sorted_entries = tuple(sorted(unique_entries, key=lambda w: (len(w), w), reverse=True))
                if is_openwall:
                    source_type = "official_openwall"
                    label = f"Official Openwall wordlist ({len(sorted_entries):,} entries)"
                    is_official = True
                elif "jtr_common_roots" in target_path.name.lower():
                    source_type = "expanded"
                    label = f"Curated wordlist ({len(sorted_entries):,} roots)"
                    is_official = False
                else:
                    source_type = "expanded"
                    label = f"Custom wordlist ({len(sorted_entries):,} roots)"
                    is_official = False

                info = WordlistInfo(
                    source_type=source_type,
                    count=len(sorted_entries),
                    label=label,
                    is_expanded=True,
                    is_official=is_official,
                    file_format=file_fmt,
                    sha256_checksum=checksum,
                )
                return sorted_entries, info
        except (OSError, PermissionError, gzip.BadGzipFile):
            pass

    # If the target requested was the official Openwall wordlist and it is missing or unreadable,
    # fall back to the curated 2,832-root list
    if is_openwall and resolved_path_str != str(CURATED_WORDLIST_PATH.resolve()):
        if CURATED_WORDLIST_PATH.is_file():
            try:
                return _load_wordlist_file_cached(str(CURATED_WORDLIST_PATH.resolve()))
            except Exception:
                pass

    # Built-in fallback when external files are missing, empty, or unreadable
    return _get_builtin_words_with_info()


def clear_wordlist_cache() -> None:
    """Clear internal LRU cache for wordlist loading (useful during tests)."""
    _load_wordlist_file_cached.cache_clear()


def resolve_wordlist_path(file_path: Optional[Union[str, Path]] = None) -> Optional[str]:
    """Resolve wordlist path according to explicit argument, environment variables, and fallback rules."""
    if file_path is not None:
        if str(file_path) in ("__builtin__", "builtin_fallback"):
            return "__builtin__"
        return str(Path(file_path).resolve())

    env_openwall = os.environ.get(ENV_OPENWALL_PATH)
    if env_openwall and Path(env_openwall).is_file():
        return str(Path(env_openwall).resolve())

    env_path = os.environ.get(ENV_WORDLIST_PATH)
    if env_path and Path(env_path).is_file():
        return str(Path(env_path).resolve())

    # Preference check: if explicitly requested via environment variable, use official Openwall
    prefer_openwall = os.environ.get(ENV_PREFER_OPENWALL, "").strip().lower() in ("1", "true", "yes")
    if prefer_openwall and OFFICIAL_OPENWALL_PATH.is_file():
        return str(OFFICIAL_OPENWALL_PATH.resolve())

    # Standard default: curated root dictionary (clean lexical roots for mutation analysis)
    if CURATED_WORDLIST_PATH.is_file():
        return str(CURATED_WORDLIST_PATH.resolve())

    # If curated list is missing, check for official Openwall list
    if OFFICIAL_OPENWALL_PATH.is_file():
        return str(OFFICIAL_OPENWALL_PATH.resolve())

    return "__builtin__"


def load_wordlist_entries(file_path: Optional[Union[str, Path]] = None) -> Tuple[Set[str], Tuple[str, ...], WordlistInfo]:
    """Load wordlist entries and return (words_set, sorted_words_tuple, wordlist_info).

    Parameters:
      file_path: Optional path to a plain-text (.txt, .lst) or gzip-compressed (.gz) wordlist.
                 If None, checks environment variables or default bundled locations.
                 Falls back safely across all tiers if unreadable or absent.

    Returns:
      words_set: Set of lowercase root words for O(1) membership testing.
      sorted_words: Tuple of words sorted by length descending for longest-match substring detection.
      wordlist_info: WordlistInfo metadata for clean UI display.
    """
    resolved = resolve_wordlist_path(file_path)
    sorted_words, info = _load_wordlist_file_cached(resolved)
    return set(sorted_words), sorted_words, info


def load_official_openwall_wordlist() -> Tuple[Set[str], Tuple[str, ...], WordlistInfo]:
    """Explicitly load the official Openwall common-password wordlist."""
    return load_wordlist_entries(OFFICIAL_OPENWALL_PATH)


def load_curated_wordlist() -> Tuple[Set[str], Tuple[str, ...], WordlistInfo]:
    """Explicitly load the curated John the Ripper root wordlist."""
    return load_wordlist_entries(CURATED_WORDLIST_PATH)


def load_builtin_wordlist() -> Tuple[Set[str], Tuple[str, ...], WordlistInfo]:
    """Explicitly retrieve the built-in fallback wordlist."""
    sorted_words, info = _load_wordlist_file_cached("__builtin__")
    return set(sorted_words), sorted_words, info


def get_current_wordlist_info(file_path: Optional[Union[str, Path]] = None) -> WordlistInfo:
    """Retrieve metadata about the currently active dictionary provider."""
    _, _, info = load_wordlist_entries(file_path)
    return info


def get_active_wordlist(file_path: Optional[Union[str, Path]] = None) -> Tuple[Set[str], Tuple[str, ...]]:
    """Retrieve active word set and length-sorted word tuple."""
    words_set, sorted_words, _ = load_wordlist_entries(file_path)
    return words_set, sorted_words
