"""Utility script to manually fetch and verify the official Openwall common-password wordlist.

Source: https://download.openwall.net/pub/wordlists/passwords/password.gz
Author: Solar Designer of Openwall Project
License: Permissive educational & non-commercial with credit (see OPENWALL_LICENSE.txt)
"""

import hashlib
import sys
import urllib.request
from pathlib import Path

OPENWALL_URL = "https://download.openwall.net/pub/wordlists/passwords/password.gz"
EXPECTED_SHA256 = "1e7a12ddd07cfbdd7c3b774230be33968e506072ae6fec4ff195b577f51fb6c1"
DESTINATION_PATH = Path(__file__).resolve().parent.parent / "data" / "wordlists" / "openwall_passwords.txt.gz"


def fetch_openwall_wordlist(force: bool = False) -> Path:
    """Download and verify the official Openwall password wordlist."""
    if DESTINATION_PATH.is_file() and not force:
        with open(DESTINATION_PATH, "rb") as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 == EXPECTED_SHA256:
            print(f"Official Openwall wordlist already present and verified at: {DESTINATION_PATH}")
            print(f"SHA-256: {sha256}")
            return DESTINATION_PATH

    DESTINATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Connecting to official Openwall repository: {OPENWALL_URL}...")
    req = urllib.request.Request(OPENWALL_URL, headers={"User-Agent": "PasswordMutationAnalysis/2.0"})
    with urllib.request.urlopen(req) as resp:
        data = resp.read()

    actual_sha256 = hashlib.sha256(data).hexdigest()
    if actual_sha256 != EXPECTED_SHA256:
        raise ValueError(
            f"Checksum validation failed!\nExpected: {EXPECTED_SHA256}\nActual:   {actual_sha256}"
        )

    with open(DESTINATION_PATH, "wb") as f:
        f.write(data)

    print(f"Successfully downloaded and verified Openwall wordlist.")
    print(f"Saved to: {DESTINATION_PATH}")
    print(f"File size: {len(data):,} bytes")
    print(f"SHA-256:   {actual_sha256}")
    return DESTINATION_PATH


if __name__ == "__main__":
    force_download = "--force" in sys.argv
    try:
        fetch_openwall_wordlist(force=force_download)
    except Exception as e:
        print(f"Error fetching wordlist: {e}", file=sys.stderr)
        sys.exit(1)
