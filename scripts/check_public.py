#!/usr/bin/env python3
"""Fail when a release tree contains private data or generated artifacts."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "__pycache__"}
FORBIDDEN_NAMES = {
    ".DS_Store",
    "wechat-debug-entitlements.plist",
    "brute_force_keys.py",
    "validate_keys_from_blobs.py",
    "hook_commoncrypto.py",
    "hook_commoncrypto_v2.py",
}
PRIVATE_SUFFIXES = {".db", ".key", ".pem", ".pyc"}
MAX_PUBLIC_FILE_BYTES = 2 * 1024 * 1024

# Build markers in pieces so this checker does not flag its own source text.
PATTERNS = {
    "personal absolute home path": re.compile("/" + r"(?:Users|home)/[^/$\s]+/"),
    "WeChat account directory": re.compile("xwechat_files/" + r"(?!all_users(?:/|$))[^/*${}\s]+/db_storage"),
    "WeChat wxid": re.compile(r"\bwxid_[A-Za-z0-9_-]{6,}\b"),
    "private key": re.compile("BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "GitHub token": re.compile("gh" + r"[opsu]_[A-Za-z0-9]{30,}"),
    "OpenAI token": re.compile("sk" + r"-[A-Za-z0-9_-]{20,}"),
    "AWS access key": re.compile("AKIA" + r"[A-Z0-9]{16}"),
}


def public_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def main() -> int:
    findings: list[str] = []
    for path in public_files():
        rel = path.relative_to(ROOT)
        if path.name in FORBIDDEN_NAMES:
            findings.append(f"forbidden file: {rel}")
        if path.suffix.lower() in PRIVATE_SUFFIXES:
            findings.append(f"private/generated file type: {rel}")
        if path.stat().st_size > MAX_PUBLIC_FILE_BYTES:
            findings.append(f"oversized file ({path.stat().st_size} bytes): {rel}")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{label}: {rel}")

    if findings:
        print("PUBLIC AUDIT FAILED")
        for finding in sorted(set(findings)):
            print(f"- {finding}")
        return 1
    print("PUBLIC AUDIT PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
