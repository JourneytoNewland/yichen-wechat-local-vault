#!/usr/bin/env python3
"""Portable launcher for the WeChat local vault skill.

It keeps third-party packages in the skill-local .venv and re-executes the
requested command with that interpreter. This makes invocations independent
of Claude's current working directory and system Python packages.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv"
COMMANDS = {
    "wechat": None,
    "vault": "vault_cli.py",
    "keys": "extract_keys.py",
    "scan": "scan_memory.py",
    "decrypt": "decrypt_all_dbs.py",
    "export": "export_chat.py",
    "contacts": "list_contacts.py",
    "moments": "search_sns.py",
    "digest": "wechat_digest.py",
}
INVASIVE_COMMANDS = {"keys", "scan"}


def venv_python() -> Path:
    return VENV / "bin" / "python3"


def modules_available(python: Path, capture: bool) -> bool:
    modules = ["Crypto", "zstandard", "click", "wechat_cli"] + (["frida"] if capture else [])
    code = "import " + ", ".join(modules)
    return subprocess.run(
        [str(python), "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def bootstrap(capture: bool = False) -> Path:
    python = venv_python()
    if not python.exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    if not modules_available(python, capture):
        requirements = ROOT / ("requirements-capture.txt" if capture else "requirements.txt")
        print(f"[setup] Installing runtime dependencies from {requirements.name}...", file=sys.stderr)
        subprocess.run(
            [str(python), "-m", "pip", "install", "-r", str(requirements)],
            check=True,
        )
    return python


def doctor() -> int:
    print(f"skill_dir: {ROOT}")
    print(f"platform: {sys.platform}")
    print(f"bootstrap_python: {sys.executable}")
    python = venv_python()
    print(f"venv: {'ok' if python.exists() else 'missing'} ({python})")
    if python.exists():
        print(f"core_dependencies: {'ok' if modules_available(python, False) else 'missing'}")
        print(f"capture_dependencies: {'ok' if modules_available(python, True) else 'missing'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run yichen-wechat-local-vault commands reliably.")
    parser.add_argument("command", choices=["doctor", "setup", "setup-capture", *COMMANDS])
    parser.add_argument(
        "--allow-invasive-capture",
        action="store_true",
        help="Explicitly allow process-memory capture and temporary app re-signing.",
    )
    parser.add_argument("args", nargs=argparse.REMAINDER)
    ns = parser.parse_args()
    if ns.command == "doctor":
        return doctor()
    if ns.command == "wechat" and ns.args[:1] == ["init"]:
        parser.error(
            "'wechat init' is disabled because the pinned upstream version may re-sign "
            "/Applications/WeChat.app in place; use the opt-in 'scan' fallback instead"
        )
    if ns.command in INVASIVE_COMMANDS and not ns.allow_invasive_capture:
        parser.error(
            f"'{ns.command}' reads WeChat process memory and may create/re-sign a temporary app copy; "
            "rerun with --allow-invasive-capture only after the user explicitly approves it"
        )
    capture = ns.command == "setup-capture"
    python = bootstrap(capture=capture)
    if ns.command in {"setup", "setup-capture"}:
        print(f"Runtime ready: {python}")
        return 0
    script_name = COMMANDS[ns.command]
    if script_name is None:
        return subprocess.run([str(python), "-m", "wechat_cli.main", *ns.args]).returncode
    script = ROOT / "scripts" / script_name
    return subprocess.run([str(python), str(script), *ns.args]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
