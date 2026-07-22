#!/usr/bin/env python3
"""
Decrypt all WeChat Mac 4.x SQLCipher databases that have captured keys.

Input:
  ~/.config/wechat-local-vault.json
  ~/.config/wechat-keys.json

Output:
  ~/Library/Application Support/wechat-local-vault/decrypted/current/<relative db path>
  ~/Library/Application Support/wechat-local-vault/manifests/decrypt-*.json
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
import sqlite3
import struct
import shutil
from pathlib import Path

from Crypto.Cipher import AES
import hmac as hmac_mod

PAGE_SIZE = 4096
RESERVE = 80
IV_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16
SQLITE_HDR = b"SQLite format 3\x00"

CONFIG_FILE = Path("~/.config/wechat-local-vault.json").expanduser()
KEYS_FILE = Path("~/.config/wechat-keys.json").expanduser()
DEFAULT_VAULT_DIR = Path("~/Library/Application Support/wechat-local-vault").expanduser()
DEFAULT_OUTPUT_DIR = DEFAULT_VAULT_DIR / "decrypted/current"
DECRYPT_STATE_FILE = DEFAULT_VAULT_DIR / "state/decrypt_state.json"

ALIAS_TO_REL = {
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


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as f:
        return json.load(f)


def load_config() -> dict:
    return load_json(CONFIG_FILE)


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    if str(path).startswith(str(DEFAULT_VAULT_DIR)):
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while current != current.parent and str(current).startswith(str(DEFAULT_VAULT_DIR.parent)):
        try:
            os.chmod(current, 0o700)
        except OSError:
            pass
        if current == DEFAULT_VAULT_DIR:
            break
        current = current.parent


def resolve_db_base() -> Path:
    config = load_config()
    if config.get("db_base_path"):
        return Path(config["db_base_path"]).expanduser()
    wxid = config.get("wxid")
    if wxid:
        return Path(
            "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
        ).expanduser() / wxid / "db_storage"
    raise SystemExit(f"Missing db_base_path/wxid in {CONFIG_FILE}")


def key_name_to_rel(name: str) -> str | None:
    if name.startswith("__"):
        return None
    if name in ALIAS_TO_REL:
        return ALIAS_TO_REL[name]
    if name.endswith(".db") and "/" in name:
        return name
    return None


def _pbkdf2_hmac_sha512(key: bytes, salt: bytes, iterations: int, dk_len: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", key, salt, iterations, dklen=dk_len)


def _mac_key(enc_key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return _pbkdf2_hmac_sha512(enc_key, mac_salt, 2, KEY_SIZE)


def verify_key(db_path: Path, key_hex: str) -> bool:
    """Verify a key by checking HMAC-SHA512 on page 1 of the database."""
    key = bytes.fromhex(key_hex)
    if len(key) != KEY_SIZE:
        return False
    try:
        with db_path.open("rb") as f:
            page = f.read(PAGE_SIZE)
        if len(page) < PAGE_SIZE:
            return False
    except OSError:
        return False

    salt = page[:SALT_SIZE]
    encrypted = page[SALT_SIZE : PAGE_SIZE - RESERVE]
    stored_hmac = page[PAGE_SIZE - RESERVE + IV_SIZE : PAGE_SIZE - RESERVE + IV_SIZE + 64]

    mac_key = _mac_key(key, salt)
    expected_hmac = hmac_mod.new(mac_key, encrypted, hashlib.sha512)
    expected_hmac.update(struct.pack("<I", 1))
    return hmac_mod.compare_digest(expected_hmac.digest(), stored_hmac)


def decrypt_db(src: Path, dst: Path, key_hex: str) -> None:
    key = bytes.fromhex(key_hex)
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")

    data = src.read_bytes()
    total_pages = len(data) // PAGE_SIZE
    if total_pages == 0:
        raise ValueError("database is smaller than one page")

    salt = data[:SALT_SIZE]
    mac_key = _mac_key(key, salt)

    out = bytearray()
    for pn in range(total_pages):
        page = data[pn * PAGE_SIZE : (pn + 1) * PAGE_SIZE]
        enc_data = page[SALT_SIZE : PAGE_SIZE - RESERVE] if pn == 0 else page[: PAGE_SIZE - RESERVE]
        iv = page[PAGE_SIZE - RESERVE : PAGE_SIZE - RESERVE + IV_SIZE]
        stored_hmac = page[PAGE_SIZE - RESERVE : PAGE_SIZE - RESERVE + 64]

        h = hmac_mod.new(mac_key, enc_data, hashlib.sha512)
        h.update(struct.pack("<I", pn + 1))
        if not hmac_mod.compare_digest(h.digest(), stored_hmac):
            raise ValueError(f"HMAC verification failed on page {pn + 1}")

        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_data)

        if pn == 0:
            out_page = bytearray(PAGE_SIZE)
            out_page[:16] = SQLITE_HDR
            out_page[16 : 16 + len(dec)] = dec
            out_page[16:18] = struct.pack(">H", PAGE_SIZE)
        else:
            out_page = bytearray(PAGE_SIZE)
            out_page[: len(dec)] = dec
        out.extend(out_page)

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(out)


def sqlite_table_count(path: Path) -> int:
    con = sqlite3.connect(path)
    try:
        return con.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
    finally:
        con.close()


def write_manifest(out_base: Path, records: list[dict]) -> Path:
    manifest_dir = DEFAULT_VAULT_DIR / "manifests"
    ensure_private_dir(manifest_dir)
    manifest_path = manifest_dir / f"decrypt-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    manifest = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "decrypted_dir": str(out_base),
        "database_count": sum(1 for item in records if item.get("status") == "ok"),
        "records": records,
        "privacy": {
            "contains_plaintext_wechat_data": True,
            "do_not_sync_or_share": True,
            "keys_file": str(KEYS_FILE),
        },
    }
    save_json(manifest_path, manifest)
    return manifest_path


def update_config_paths(out_base: Path) -> None:
    config = load_config()
    config["vault_dir"] = str(DEFAULT_VAULT_DIR)
    config["decrypted_dir"] = str(out_base)
    config.setdefault("exports_dir", "~/Documents/wechat-local-vault/exports")
    save_json(CONFIG_FILE, config)


def source_fingerprint(src: Path, key_hex: str) -> dict:
    stat = src.stat()
    return {
        "source_bytes": stat.st_size,
        "source_mtime_ns": stat.st_mtime_ns,
        "key_sha256": hashlib.sha256(key_hex.encode()).hexdigest(),
    }


def unchanged(src: Path, dst: Path, key_hex: str, state: dict, rel: str) -> bool:
    if not dst.exists():
        return False
    previous = state.get(rel)
    if not previous:
        return False
    return previous == source_fingerprint(src, key_hex)


def main() -> None:
    parser = argparse.ArgumentParser(description="Decrypt all known WeChat DB keys.")
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT_DIR),
        help="output directory; default is the private local wechat-local-vault vault",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="remove the output directory before decrypting",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "incremental"],
        default="full",
        help="full decrypts every keyed DB; incremental skips unchanged sources",
    )
    parser.add_argument(
        "--no-manifest",
        action="store_true",
        help="do not write a decrypt manifest",
    )
    args = parser.parse_args()

    db_base = resolve_db_base()
    keys = load_json(KEYS_FILE)
    usable_keys = {name: value for name, value in keys.items() if key_name_to_rel(name)}
    if not usable_keys:
        raise SystemExit(
            f"No database keys found in {KEYS_FILE}. Run the key capture or match-only workflow first."
        )
    out_base = Path(args.output).expanduser()
    if args.clean and out_base.exists():
        shutil.rmtree(out_base)
    ensure_private_dir(out_base)
    state = load_json(DECRYPT_STATE_FILE)

    passed = 0
    failed = 0
    skipped = 0
    records: list[dict] = []

    print(f"DB base: {db_base}")
    print(f"Output:  {out_base}")

    for name, key_hex in sorted(keys.items()):
        rel = key_name_to_rel(name)
        if not rel:
            skipped += 1
            continue
        src = db_base / rel
        dst = out_base / rel
        if not src.exists():
            print(f"SKIP {name}: source not found ({rel})")
            skipped += 1
            records.append({"name": name, "rel": rel, "status": "skip", "reason": "source not found"})
            continue
        if args.mode == "incremental" and unchanged(src, dst, key_hex, state, rel):
            print(f"SKIP {name:24s}: unchanged")
            skipped += 1
            records.append({"name": name, "rel": rel, "status": "unchanged"})
            continue
        try:
            decrypt_db(src, dst, key_hex)
            count = sqlite_table_count(dst)
            size = dst.stat().st_size
            state[rel] = source_fingerprint(src, key_hex)
            print(f"OK   {name:24s} -> {dst} ({count} tables)")
            passed += 1
            records.append({
                "name": name,
                "rel": rel,
                "status": "ok",
                "tables": count,
                "bytes": size,
            })
        except Exception as exc:
            try:
                if dst.exists():
                    dst.unlink()
            except OSError:
                pass
            print(f"MISS {name:24s}: {exc}")
            failed += 1
            records.append({"name": name, "rel": rel, "status": "miss", "reason": str(exc)})

    update_config_paths(out_base)
    save_json(DECRYPT_STATE_FILE, state)
    if not args.no_manifest:
        manifest_path = write_manifest(out_base, records)
        print(f"Manifest: {manifest_path}")
    print(f"Done: {passed} decrypted, {failed} failed, {skipped} skipped")
    if passed == 0 and failed > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
