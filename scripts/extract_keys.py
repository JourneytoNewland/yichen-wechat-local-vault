#!/usr/bin/env python3
"""
WeChat Mac 4.x database key extractor.

Opt-in helper for a local WeChat account on macOS. It hooks
CommonCrypto's CCKeyDerivationPBKDF in an ad-hoc signed WeChat copy, records
SQLCipher PBKDF2 outputs, and matches them to local database salts.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import hashlib
import hmac as hmac_mod
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

WECHAT_APP = Path("/Applications/WeChat.app")
WECHAT_COPY = Path("/nonexistent/private-wechat-copy/WeChat.app")

PAGE_SIZE = 4096
RESERVE = 80
IV_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16
SQLITE_HDR = b"SQLite format 3\x00"

DB_RELATIVE_PATHS = {
    "message_0": "message/message_0.db",
    "message_1": "message/message_1.db",
    "message_2": "message/message_2.db",
    "message_3": "message/message_3.db",
    "message_fts": "message/message_fts.db",
    "message_resource": "message/message_resource.db",
    "contact": "contact/contact.db",
    "session": "session/session.db",
    "sns": "sns/sns.db",
    "favorite": "favorite/favorite.db",
}


def _pbkdf2_hmac_sha512(key: bytes, salt: bytes, iterations: int, dk_len: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", key, salt, iterations, dklen=dk_len)


def _mac_key(enc_key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return _pbkdf2_hmac_sha512(enc_key, mac_salt, 2, KEY_SIZE)


def try_decrypt_page(db_path: str, key_hex: str) -> bool:
    """Verify a candidate encryption key using SQLCipher 4 HMAC-SHA512 on page 1."""
    try:
        key = bytes.fromhex(key_hex)
    except (TypeError, ValueError):
        return False
    if len(key) != KEY_SIZE:
        return False
    try:
        with open(db_path, "rb") as f:
            page = f.read(PAGE_SIZE)
        if len(page) < PAGE_SIZE:
            return False

        salt = page[:SALT_SIZE]
        enc_data = page[SALT_SIZE : PAGE_SIZE - RESERVE + IV_SIZE]
        stored_hmac = page[PAGE_SIZE - RESERVE + IV_SIZE : PAGE_SIZE - RESERVE + IV_SIZE + 64]

        mac_key = _mac_key(key, salt)
        expected_hmac = hmac_mod.new(mac_key, enc_data, hashlib.sha512)
        expected_hmac.update(struct.pack("<I", 1))
        return hmac_mod.compare_digest(expected_hmac.digest(), stored_hmac)
    except Exception:
        return False


FRIDA_JS = r"""
'use strict';

const TARGET_SALTS = ___TARGET_SALTS___;
const seen = {};
let hookInstalled = false;

function sendStatus(msg) {
  send({ type: 'status', msg: msg });
}

function hexFromPointer(ptr, len, maxLen) {
  if (ptr.isNull() || len <= 0 || len > maxLen) return null;
  try {
    const bytes = new Uint8Array(ptr.readByteArray(len));
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      out += ('0' + bytes[i].toString(16)).slice(-2);
    }
    return out;
  } catch (e) {
    return null;
  }
}

function isInteresting(rounds, saltHex, dkLen) {
  if (!saltHex || dkLen < 32 || dkLen > 128) return false;
  if (TARGET_SALTS.length === 0) return true;
  if (TARGET_SALTS.indexOf(saltHex) >= 0) return true;
  // SQLCipher may perform a short second derivation for HMAC-related material.
  return rounds === 256000 || rounds === 2 || rounds === 1;
}

function installHookAt(address, owner) {
  Interceptor.attach(address, {
    onEnter: function(args) {
      this.password = args[1];
      this.passwordLen = args[2].toInt32();
      this.salt = args[3];
      this.saltLen = args[4].toInt32();
      this.prf = args[5].toInt32();
      this.rounds = args[6].toInt32();
      this.derivedKey = args[7];
      this.derivedKeyLen = args[8].toInt32();
    },
    onLeave: function(retval) {
      const saltHex = hexFromPointer(this.salt, this.saltLen, 128);
      if (!isInteresting(this.rounds, saltHex, this.derivedKeyLen)) return;

      const dkHex = hexFromPointer(this.derivedKey, this.derivedKeyLen, 128);
      if (!dkHex) return;
      const passwordHex = hexFromPointer(this.password, this.passwordLen, 512);

      const key = [this.rounds, saltHex, dkHex].join(':');
      if (seen[key]) return;
      seen[key] = true;

      const item = {
        type: 'pbkdf2',
        owner: owner,
        rounds: this.rounds,
        prf: this.prf,
        password_len: this.passwordLen,
        password: passwordHex,
        salt_len: this.saltLen,
        salt: saltHex,
        dk_len: this.derivedKeyLen,
        dk: dkHex,
        ts: Date.now()
      };
      send({ type: 'pbkdf2', data: item });
    }
  });
}

function tryInstallHook() {
  if (hookInstalled) return true;

  const modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i++) {
    let exportsList = [];
    try {
      exportsList = modules[i].enumerateExports();
    } catch (e) {
      continue;
    }
    for (let j = 0; j < exportsList.length; j++) {
      const exp = exportsList[j];
      if (exp.name === 'CCKeyDerivationPBKDF') {
        installHookAt(exp.address, modules[i].name);
        hookInstalled = true;
        sendStatus('Hook installed on ' + modules[i].name + '!' + exp.name);
        return true;
      }
    }
  }
  return false;
}

let attempts = 0;
function installLoop() {
  attempts += 1;
  if (tryInstallHook()) return;
  if (attempts === 1 || attempts % 10 === 0) {
    sendStatus('Waiting for CCKeyDerivationPBKDF (' + attempts + ')');
  }
  setTimeout(installLoop, 500);
}

sendStatus('Frida script loaded. Target database count: ' + TARGET_SALTS.length);
installLoop();
"""


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"  [ERROR] {' '.join(cmd)}")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        sys.exit(1)
    return result


def check_env() -> None:
    print("\n[1/5] Checking environment...")
    if sys.platform != "darwin":
        raise SystemExit("This helper only supports macOS.")
    if not WECHAT_APP.exists():
        raise SystemExit(f"WeChat not found: {WECHAT_APP}")
    if sys.version_info < (3, 9):
        raise SystemExit(f"Python 3.9+ is required. Current: {sys.version}")
    try:
        import frida  # noqa: F401
        print(f"  OK frida {frida.__version__}")
    except ImportError:
        print("  Installing frida...")
        run_cmd([sys.executable, "-m", "pip", "install", "frida", "frida-tools"])
    try:
        from Crypto.Cipher import AES  # noqa: F401
        print("  OK pycryptodome")
    except ImportError:
        print("  Installing pycryptodome...")
        run_cmd([sys.executable, "-m", "pip", "install", "pycryptodome"])


def prepare_wechat(copy_path: Path, skip_prepare: bool) -> None:
    print("\n[2/5] Validating signed WeChat copy...")
    resolved = copy_path.resolve()
    original = WECHAT_APP.resolve()
    if resolved == original or original in resolved.parents:
        raise SystemExit("Refusing to use the original WeChat application.")
    if not skip_prepare:
        raise SystemExit("Automatic copying and signing are disabled; prepare a private temporary copy first.")
    temp_roots = {Path(tempfile.gettempdir()).resolve(), Path('/private/tmp').resolve()}
    parent = copy_path.parent
    if (parent.resolve().parent not in temp_roots or not parent.name.startswith('wechat-')
            or parent.is_symlink() or copy_path.is_symlink() or not copy_path.is_dir()):
        raise SystemExit("The copy must be in a dedicated private temporary directory.")
    info = parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SystemExit("Temporary directory must be owned by the user and private (0700).")
    binary = copy_path / 'Contents/MacOS/WeChat'
    if binary.is_symlink() or not binary.is_file() or resolved not in binary.resolve().parents:
        raise SystemExit("Invalid application binary in the temporary copy.")
    run_cmd(["codesign", "--verify", "--deep", "--strict", str(copy_path)])
    print("  OK private temporary copy signature verified")


def collect_db_info(db_base: Path) -> dict[str, dict[str, str]]:
    info = {}
    alias_paths = set()
    for name, rel in DB_RELATIVE_PATHS.items():
        path = db_base / rel
        if not path.exists():
            continue
        with path.open("rb") as f:
            salt = f.read(16).hex()
        info[name] = {"path": str(path), "salt": salt, "size": str(path.stat().st_size)}
        alias_paths.add(path.resolve())
    for path in sorted(db_base.rglob("*.db")):
        if path.name.endswith(("-wal", "-shm")):
            continue
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in alias_paths:
            continue
        if path.stat().st_size < PAGE_SIZE:
            continue
        with path.open("rb") as f:
            salt = f.read(16).hex()
        rel = str(path.relative_to(db_base))
        info[rel] = {"path": str(path), "salt": salt, "size": str(path.stat().st_size)}
    return info


def print_db_info(info: dict[str, dict[str, str]], *, show_sensitive: bool = False) -> None:
    print("\n[3/5] Local database salts...")
    for name, item in info.items():
        size_mb = int(item["size"]) / 1024 / 1024
        if show_sensitive:
            print(f"  {name:24s} salt={item['salt']} size={size_mb:.2f} MB")
        else:
            print(f"  {name:24s} size={size_mb:.2f} MB")


def normalize_targets(targets: str, db_info: dict[str, dict[str, str]]) -> list[str]:
    if targets == "all":
        return list(db_info.keys())
    result = []
    for item in targets.split(","):
        name = item.strip()
        if not name:
            continue
        if name not in DB_RELATIVE_PATHS and name not in db_info:
            raise SystemExit(f"Unknown target database: {name}")
        result.append(name)
    return result


def run_frida_capture(
    *,
    mode: str,
    duration: int,
    copy_path: Path,
    target_salts: list[str],
    reset_log: bool,
) -> list[dict]:
    print("\n[4/5] Capturing PBKDF2 calls with frida...")
    if not reset_log:
        raise SystemExit("Reusing sensitive capture logs is disabled.")
    wechat_binary = copy_path / "Contents/MacOS/WeChat"
    if not wechat_binary.exists():
        raise SystemExit(f"WeChat executable not found: {wechat_binary}")
    if mode != "spawn":
        raise SystemExit("Attach mode is disabled.")

    js_code = (
        FRIDA_JS
        .replace("___TARGET_SALTS___", json.dumps(target_salts))
    )
    import frida
    captured = []
    def on_message(message, _data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "pbkdf2":
                captured.append(payload.get("data", {}))
        elif message.get("type") == "error":
            print("  [FRIDA ERROR] Capture script failed; details withheld.", file=sys.stderr)

    device = frida.get_local_device()
    session = None
    pid = None
    resumed = False
    try:
        pid = device.spawn([str(wechat_binary)], stdio="pipe")
        session = device.attach(pid)
        script = session.create_script(js_code)
        script.on("message", on_message)
        script.load()
        if mode == "spawn":
            device.resume(pid)
            resumed = True
        print(f"  Capture active for up to {duration} seconds; key material remains in memory.")
        time.sleep(duration)
    finally:
        if session is not None:
            session.detach()
        if mode == "spawn" and pid is not None and not resumed:
            device.kill(pid)
    return captured


def match_keys(
    db_info: dict[str, dict[str, str]],
    captured: list[dict],
    existing: dict[str, str],
    targets: list[str],
) -> dict[str, str]:
    print("\n[5/5] Matching captured keys to databases...")
    result = dict(existing)

    candidates_by_salt: dict[str, list[str]] = {}

    def add_candidate(salt: str, key_hex: str) -> None:
        if not salt or len(key_hex) != 64:
            return
        try:
            bytes.fromhex(key_hex)
        except ValueError:
            return
        candidates_by_salt.setdefault(salt, [])
        if key_hex not in candidates_by_salt[salt]:
            candidates_by_salt[salt].append(key_hex)

    def password_candidates(password_hex: str) -> list[str]:
        result = []
        if not password_hex:
            return result
        if len(password_hex) == 64:
            result.append(password_hex)
        try:
            raw = bytes.fromhex(password_hex)
        except ValueError:
            return result
        if len(raw) == 32:
            result.append(raw.hex())
        try:
            text = raw.decode("ascii", errors="ignore")
        except Exception:
            text = ""
        if text.startswith("x'") and "'" in text[2:]:
            inner = text[2:text.find("'", 2)]
            if len(inner) >= 64:
                result.append(inner[:64])
        return result

    for item in captured:
        dk = item.get("dk", "")
        salt = item.get("salt", "")
        if len(dk) >= 64:
            add_candidate(salt, dk[:64])
        for key_hex in password_candidates(item.get("password", "")):
            add_candidate(salt, key_hex)

    print(f"  Captured {len(captured)} PBKDF2 rows, {sum(len(v) for v in candidates_by_salt.values())} unique candidates")

    for name in targets:
        item = db_info.get(name)
        if not item:
            print(f"  [WARN] {name}: database not found")
            continue
        if result.get(name) and try_decrypt_page(item["path"], result[name]):
            print(f"  OK {name}: existing key still works")
            continue

        matched = None
        salt_candidates = candidates_by_salt.get(item["salt"], [])
        for key_hex in salt_candidates:
            if try_decrypt_page(item["path"], key_hex):
                matched = key_hex
                break

        if matched is None:
            # Last-chance fallback for logs from older scripts that did not preserve salt.
            for keys in candidates_by_salt.values():
                for key_hex in keys:
                    if try_decrypt_page(item["path"], key_hex):
                        matched = key_hex
                        break
                if matched:
                    break

        if matched:
            result[name] = matched
            print(f"  OK {name}: matched key")
        else:
            print(f"  [MISS] {name}: no matching key yet")

    return result


def merge_cli_keys(db_base: Path, db_info: dict, matched: dict, targets: list[str], cfg: dict) -> None:
    """Publish validated keys atomically, retaining a private pre-change backup."""
    if db_base.resolve() != Path(cfg["db_dir"]).resolve():
        raise ValueError("capture and CLI use different accounts")
    key_path = Path(cfg["keys_file"])
    if key_path.is_symlink() or not stat.S_ISREG(key_path.stat().st_mode):
        raise ValueError("CLI key configuration must be a regular file")
    with key_path.open(encoding="utf-8") as stream:
        previous = json.load(stream)
    if not isinstance(previous, dict):
        raise ValueError("invalid CLI key configuration")
    merged = dict(previous)
    for name in targets:
        item = db_info[name]
        path = Path(item["path"]).resolve()
        relative = path.relative_to(db_base.resolve()).as_posix()
        key = matched.get(name)
        if not key or not try_decrypt_page(str(path), key):
            raise ValueError("refusing unverified key")
        merged[relative] = {**merged.get(relative, {}), "enc_key": key}
    if merged == previous:
        return
    staged = []
    try:
        for label, content in (("backup", previous), ("new", merged)):
            fd, filename = tempfile.mkstemp(prefix=".wechat-keys-" + label + "-", dir=key_path.parent)
            staged.append(Path(filename))
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(content, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
        backup, new = staged
        os.replace(new, key_path)
        staged.remove(new)
        staged.remove(backup)  # retain the 0600 backup for recovery
    finally:
        for path in staged:
            path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and match WeChat Mac 4.x SQLCipher database keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Requires a pre-approved, signed copy in a private temporary directory.
            See SKILL.md for safety and compatibility limitations.
            """
        ),
    )
    parser.add_argument("--mode", choices=["spawn", "attach"], default="spawn")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--targets", default="sns,favorite")
    parser.add_argument("--db-base", default=None)
    parser.add_argument("--wechat-copy", default=str(WECHAT_COPY))
    parser.add_argument("--skip-prepare", action="store_true")
    parser.add_argument("--reuse-log", action="store_true", help="Disabled for security.")
    parser.add_argument("--list-dbs", action="store_true", help="Only print detected database salts.")
    parser.add_argument("--match-only", action="store_true", help="Disabled for security.")
    parser.add_argument("--show-sensitive", action="store_true", help="Disabled for security.")
    args = parser.parse_args()

    if args.mode != "spawn":
        raise SystemExit("Attach mode is disabled; only a private temporary copy can be spawned.")
    if args.show_sensitive:
        raise SystemExit("Sensitive diagnostic output is disabled.")
    if not 1 <= args.duration <= 600:
        raise SystemExit("Capture duration must be between 1 and 600 seconds.")

    print("=" * 64)
    print("WeChat Mac 4.x database key extractor")
    print("=" * 64)

    check_env()
    from wechat_cli.core.config import load_config as load_cli_config
    cli_cfg = load_cli_config()
    cli_db_base = Path(cli_cfg["db_dir"]).resolve()
    if args.db_base and Path(args.db_base).expanduser().resolve() != cli_db_base:
        raise SystemExit("Capture database differs from the configured wechat-cli account.")
    db_base = cli_db_base
    db_info = collect_db_info(db_base)
    print("  db_base: [redacted]")
    print_db_info(db_info, show_sensitive=False)

    if args.list_dbs:
        return

    targets = normalize_targets(args.targets, db_info)
    target_salts = [db_info[name]["salt"] for name in targets if name in db_info]

    copy_path = Path(args.wechat_copy).expanduser()
    if args.match_only or args.reuse_log:
        raise SystemExit("Reading or reusing sensitive capture logs is disabled.")
    if not args.match_only:
        prepare_wechat(copy_path, args.skip_prepare)
        captured = run_frida_capture(
            mode=args.mode,
            duration=args.duration,
            copy_path=copy_path,
            target_salts=target_salts,
            reset_log=not args.reuse_log,
        )

    # Never mix keys from the legacy vault, which may point to another account.
    matched = match_keys(db_info, captured, {}, targets)

    missing = [
        name
        for name in targets
        if name not in matched
        or name not in db_info
        or not try_decrypt_page(db_info[name]["path"], matched[name])
    ]
    print("\n" + "=" * 64)
    if missing:
        print("Not all target keys were captured yet:")
        for name in missing:
            salt = db_info.get(name, {}).get("salt", "?")
            if args.show_sensitive:
                print(f"  - {name}: salt={salt}")
            else:
                print(f"  - {name}")
        print("\nNo configuration was changed. Review the capture prerequisites before retrying.")
        raise SystemExit(2)
    else:
        merge_cli_keys(db_base, db_info, matched, targets, cli_cfg)
        print("Done. Verified keys saved to the private wechat-cli configuration.")
    print("=" * 64)


if __name__ == "__main__":
    main()
