#!/usr/bin/env python3
"""
Scan WeChat 4.x process memory for SQLCipher 4 encryption keys.

Uses Frida to inject a JS agent with three strategies:
  1. Hook malloc/calloc to capture 32-64 byte allocations (potential keys)
  2. Scan existing heap memory ranges for key-shaped data
  3. Search for key patterns near known SQLCipher structures

Usage:
  python3 scan_memory.py --targets all --duration 120
  python3 scan_memory.py --targets sns,favorite --mode attach --duration 90
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

try:
    import frida
except ImportError:
    print("Installing frida...")
    subprocess.run([sys.executable, "-m", "pip", "install", "frida", "frida-tools"], check=True)
    import frida

try:
    from Crypto.Cipher import AES  # noqa: F401
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "pycryptodome"], check=True)

PAGE_SIZE = 4096
RESERVE = 80
IV_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16

KEYS_FILE = Path("~/.config/wechat-keys.json").expanduser()
CONFIG_FILE = Path("~/.config/wechat-local-vault.json").expanduser()
WECHAT_APP = Path("/Applications/WeChat.app")
WECHAT_COPY = Path("~/Desktop/WeChat.app").expanduser()
FRIDA_LOG = Path("/tmp/wechat_frida_scan.log")
DEFAULT_VAULT_DIR = Path("~/Library/Application Support/wechat-local-vault").expanduser()
WECHAT_BASE = Path(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
).expanduser()

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

FRIDA_JS = r"""
'use strict';

const LOG_PATH = '___LOG_PATH___';
const TARGET_SALTS = ___TARGET_SALTS___;
const SCAN_HEAP = ___SCAN_HEAP___;

const seenKeys = {};

function sendStatus(msg) {
  send({ type: 'status', msg: msg });
}

function sendKey(keyHex, source) {
  if (!keyHex || keyHex.length !== 64) return;
  if (seenKeys[keyHex]) return;
  seenKeys[keyHex] = true;
  send({ type: 'key', source: source, key: keyHex });
}

// ── Strategy 1: Syscall hooking — catch DB file I/O ────────────────────────
// Hook open() to detect when WeChat opens .db files, then hook read()/pread()
// to capture the salt from page 1 and look for the key in adjacent memory.
// This bypasses the need for malloc/calloc exports entirely.

let openCalls = {};
let dbFileFds = {};

function setupSyscallHooks() {
  // Hook open() to detect .db file opens
  try {
    const openPtr = Module.findExportByName(null, 'open');
    if (openPtr) {
      Interceptor.attach(openPtr, {
        onEnter: function(args) {
          const pathPtr = args[0];
          if (pathPtr.isNull()) return;
          try {
            const path = Memory.readUtf8String(pathPtr);
            if (path && path.endsWith('.db')) {
              const fd = -1;  // will be set on leave
              openCalls[path] = { opened: false, fd: fd };
              sendStatus('DB file open: ' + path);
            }
          } catch (e) { /* skip */ }
        },
        onLeave: function(retval) {
          // Can't easily get path here, but we log the fd
        }
      });
      sendStatus('Hooked open syscall');
    }
  } catch (e) {
    sendStatus('open hook error: ' + e);
  }

  // Hook read() to capture DB file contents (including salt from page 1)
  try {
    const readPtr = Module.findExportByName(null, 'read');
    if (readPtr) {
      Interceptor.attach(readPtr, {
        onEnter: function(args) {
          const fd = args[0].toInt32();
          const bufPtr = args[1];
          const count = args[2].toInt32();
          this.fd = fd;
          this.bufPtr = bufPtr;
          this.count = count;
        },
        onLeave: function(retval) {
          const nread = retval.toInt32();
          if (nread <= 0) return;
          // Check if this is a .db file read (fd tracking is approximate)
          try {
            const raw = Memory.readByteArray(this.bufPtr, Math.min(nread, 4096));
            if (!raw) return;
            // Check for SQLite header
            const header = String.fromCharCode.apply(null, raw.slice(0, 16));
            if (header.startsWith('SQLite format 3')) {
              sendStatus('SQLite header detected! fd=' + this.fd + ' size=' + nread);
              const salt = raw.slice(16, 32);
              const saltHex = Array.from(salt).map(b => ('0' + b.toString(16)).slice(-2)).join('');
              sendStatus('Salt from read buffer: ' + saltHex);
              // The encryption key might be in memory nearby this buffer
              // We can't easily find it from here, but we confirmed the DB is being read
            }
          } catch (e) { /* skip */ }
        }
      });
      sendStatus('Hooked read syscall');
    }
  } catch (e) {
    sendStatus('read hook error: ' + e);
  }

  // Hook mmap to find memory-mapped file regions
  try {
    const mmapPtr = Module.findExportByName(null, 'mmap');
    if (mmapPtr) {
      Interceptor.attach(mmapPtr, {
        onLeave: function(retval) {
          if (retval.isNull()) return;
          // mmap returns the mapped address — could be a DB file
          this.mmapAddr = retval;
          this.mmapLen = this.args[1].toInt32();
          this.mmapFd = this.args[4].toInt32();
        }
      });
      sendStatus('Hooked mmap syscall');
    }
  } catch (e) {
    sendStatus('mmap hook error: ' + e);
  }
}

function scanForSalts() {
  if (TARGET_SALTS.length === 0) return;

  sendStatus('Scanning memory for ' + TARGET_SALTS.length + ' known salt(s)...');

  const results = {};
  for (let s = 0; s < TARGET_SALTS.length; s++) {
    results[s] = { found: 0, addresses: [] };
  }

  // Get all RW memory ranges
  const ranges = Process.enumerateRanges({
    protection: 'rw-',
    coalesce: true
  });

  sendStatus('Scanning ' + ranges.length + ' RW ranges for salt patterns...');

  for (const range of ranges) {
    // Focus on heap-sized ranges (keys live in heap memory)
    if (range.size < 65536 || range.size > 500 * 1024 * 1024) continue;

    try {
      // Read the range in 1MB chunks
      const chunkSize = 1024 * 1024;
      const maxChunks = Math.min(Math.ceil(range.size / chunkSize), 10);

      for (let c = 0; c < maxChunks; c++) {
        const offset = c * chunkSize;
        try {
          const data = Memory.readByteArray(range.base.add(offset), Math.min(chunkSize, range.size - offset));
          if (!data) continue;

          for (let s = 0; s < TARGET_SALTS.length; s++) {
            const saltBytes = hexToBytes(TARGET_SALTS[s]);
            const positions = findPattern(data, saltBytes);
            if (positions.length > 0) {
              results[s].found += positions.length;
              for (const pos of positions) {
                const addr = range.base.add(offset + pos);
                results[s].addresses.push(addr);
                sendStatus('Found salt ' + s + ' at ' + addr);
                examineNearby(addr, s);
              }
            }
          }
        } catch (e) { break; }
      }
    } catch (e) { /* skip range */ }
  }

  for (let s = 0; s < TARGET_SALTS.length; s++) {
    sendStatus('Salt ' + s + ': ' + results[s].found + ' occurrences in memory');
  }
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

function findPattern(data, pattern) {
  const positions = [];
  if (pattern.length === 0 || data.length < pattern.length) return positions;
  for (let i = 0; i <= data.length - pattern.length; i++) {
    let match = true;
    for (let j = 0; j < pattern.length; j++) {
      if (data[i + j] !== pattern[j]) { match = false; break; }
    }
    if (match) positions.push(i);
  }
  return positions;
}

function examineNearby(saltAddr, saltIndex) {
  // Check memory around the salt for potential keys.
  // Keys may be stored nearby in a struct (before or after the salt).
  const checkOffsets = [-128, -96, -64, -48, -32, -16, 16, 32, 48, 64, 96, 128];

  for (const offset of checkOffsets) {
    try {
      const addr = saltAddr.add(offset);
      const raw = Memory.readByteArray(addr, 64);
      if (!raw || raw.length < 64) continue;

      // A 32-byte encryption key has very high entropy
      let distinct = 0;
      for (let i = 0; i < 64; i++) {
        if (raw[i] !== raw[0]) distinct++;
      }
      if (distinct > 30) {
        const hex = Array.from(raw)
          .map(b => ('0' + b.toString(16)).slice(-2))
          .join('');
        sendKey(hex, 'salt_nearby_s' + saltIndex + '_' + offset);
        sendStatus('HIGH ENTROPY near salt ' + saltIndex + ' at offset ' + offset + ': ' + hex.substring(0, 32) + '...');
      }
    } catch (e) { /* skip invalid reads */ }
  }
}

// ── Strategy 2: Direct heap scan (fallback) ─────────────────────────────────

function scanHeap() {
  try {
    sendStatus('Scanning heap for key-shaped data...');
    const ranges = Process.enumerateRanges({
      protection: 'rw-',
      coalesce: true
    });

    let scanned = 0;
    let found = 0;

    for (const range of ranges) {
      if (range.size < 65536 || range.size > 500 * 1024 * 1024) continue;
      if (scanned++ > 50) break;

      const pageSize = 4096;
      const maxPages = Math.min(Math.floor(range.size / pageSize), 64);
      for (let i = 0; i < maxPages; i++) {
        try {
          const raw = Memory.readByteArray(range.base.add(i * pageSize), 64);
          if (!raw) continue;
          let distinct = 0;
          for (let j = 0; j < 64; j++) {
            if (raw[j] !== raw[0]) distinct++;
          }
          if (distinct > 30) {
            const hex = Array.from(raw)
              .map(b => ('0' + b.toString(16)).slice(-2))
              .join('');
            sendKey(hex, 'heap_r' + scanned + '_p' + i);
            found++;
          }
        } catch (e) { break; }
      }
    }
    sendStatus('Heap scan complete, found ' + found + ' candidates');
  } catch (e) {
    sendStatus('Heap scan error: ' + e);
  }
}

// ── Main ───────────────────────────────────────────────────────────────────

function main() {
  sendStatus('Scanner loaded, target salts: ' + TARGET_SALTS.length);

  // Strategy 1: Scan memory for known salt values and examine nearby for keys
  try {
    scanForSalts();
  } catch (e) {
    sendStatus('Salt scan error: ' + e);
  }

  // Strategy 2: Direct heap scan for high-entropy 64-byte blocks
  try {
    scanHeap();
  } catch (e) {
    sendStatus('Heap scan error: ' + e);
  }

  sendStatus('Scanner ready. Waiting for more interaction...');
}

setTimeout(main, 500);
"""

FRIDA_HOST = r"""
import frida
import json
import os
import sys
import time

MODE = "___MODE___"
WECHAT_PATH = "___WECHAT_PATH___"
ATTACH_PID = ___ATTACH_PID___
DURATION = ___DURATION___
LOG_FILE = "___LOG_FILE___"
JS_CODE = ___JS_CODE_JSON___

keys = []

def on_message(message, data):
    if message.get("type") == "send":
        payload = message.get("payload", {})
        ptype = payload.get("type", "")

        if ptype == "key":
            item = {
                "key": payload["key"],
                "source": payload.get("source", "unknown"),
                "ts": time.time(),
            }
            keys.append(item)
            print(f"  [KEY] source={item['source']} key={payload['key'][:16]}...")
        elif ptype == "status":
            print(f"  {payload.get('msg')}")
        elif ptype == "error":
            print(f"  [SCAN ERROR] {payload.get('msg')}")
        else:
            print(f"  [SCAN] {payload}")
    elif message.get("type") == "error":
        print(f"  [FRIDA ERROR] {message.get('description', message)}")

device = frida.get_local_device()

if MODE == "spawn":
    print("  Spawning WeChat for memory scanning...")
    pid = device.spawn([WECHAT_PATH])
    session = device.attach(pid)
else:
    print("  Attaching to running WeChat (PID " + str(ATTACH_PID) + ")...")
    if ATTACH_PID <= 0:
        raise SystemExit("No running WeChat found. Start WeChat first.")
    pid = ATTACH_PID
    session = device.attach(pid)

script = session.create_script(JS_CODE)
script.on("message", on_message)
script.load()

if MODE == "spawn":
    device.resume(pid)

print("")
print(f"  Scanning for keys. Duration: {DURATION}s")
print(f"  Interact with WeChat: open chats, favorites, moments, etc.")
print("")

try:
    for remaining in range(DURATION, 0, -1):
        time.sleep(1)
        if remaining % 15 == 0:
            print(f"  Remaining {remaining}s, captured {len(keys)} keys...")
except KeyboardInterrupt:
    print("\n  Interrupted; keeping captured keys.")
finally:
    session.detach()
    print(f"\n  Captured {len(keys)} keys total.")
"""


# ── Helpers ─────────────────────────────────────────────────────────────────

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
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def check_env() -> None:
    print("\n[1/4] Checking environment...")
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


def prepare_wechat(copy_path: Path, skip_prepare: bool) -> None:
    print("\n[2/4] Preparing signed WeChat copy...")
    if skip_prepare:
        print(f"  Skipped. Using {copy_path}")
        return
    if not copy_path.exists():
        print(f"  Copying {WECHAT_APP} -> {copy_path}")
        if copy_path.parent:
            copy_path.parent.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copytree(WECHAT_APP, copy_path, symlinks=True)
    else:
        print(f"  Existing copy: {copy_path}")
    print("  Ad-hoc signing the copy...")
    run_cmd(["codesign", "--force", "--deep", "--sign", "-", str(copy_path)])
    print("  OK signed copy ready")


def find_db_base(preferred: str | None = None) -> tuple[str, Path]:
    if preferred:
        db_base = Path(preferred).expanduser()
        wxid = db_base.parts[-2] if db_base.name == "db_storage" else db_base.name
        return wxid, db_base

    config = load_config()
    if config.get("db_base_path"):
        db_base = Path(config["db_base_path"]).expanduser()
        wxid = config.get("wxid") or db_base.parts[-2]
        return wxid, db_base

    import glob
    dirs = sorted(glob.glob(str(WECHAT_BASE / "*/db_storage")))
    if not dirs:
        raise SystemExit(f"No WeChat db_storage found under {WECHAT_BASE}")
    db_base = Path(dirs[0])
    return db_base.parts[-2], db_base


def collect_db_info(db_base: Path) -> dict[str, dict[str, str]]:
    import glob
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


def normalize_targets(targets: str, db_info: dict) -> list[str]:
    if targets == "all":
        return list(db_info.keys())
    result = []
    for item in targets.split(","):
        item = item.strip()
        if item in db_info:
            result.append(item)
    return result


def find_running_process(executable_path: str) -> int:
    result = run_cmd(["pgrep", "-f", executable_path], check=False)
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    return 0


def run_scan(
    *,
    mode: str,
    duration: int,
    copy_path: Path,
    target_salts: list[str],
    reset_log: bool,
    scan_heap: bool = True,
) -> None:
    print("\n[3/4] Scanning WeChat memory for encryption keys...")
    if reset_log and FRIDA_LOG.exists():
        FRIDA_LOG.unlink()

    wechat_binary = copy_path / "Contents/MacOS/WeChat"
    if not wechat_binary.exists():
        raise SystemExit(f"WeChat executable not found: {wechat_binary}")
    attach_pid = find_running_process(str(wechat_binary)) if mode == "attach" else 0

    js_code = (
        FRIDA_JS
        .replace("___LOG_PATH___", str(FRIDA_LOG))
        .replace("___TARGET_SALTS___", json.dumps(target_salts))
        .replace("___SCAN_HEAP___", json.dumps(scan_heap))
    )
    host = (
        FRIDA_HOST
        .replace("___MODE___", mode)
        .replace("___WECHAT_PATH___", str(wechat_binary))
        .replace("___ATTACH_PID___", str(attach_pid))
        .replace("___DURATION___", str(duration))
        .replace("___LOG_FILE___", str(FRIDA_LOG))
        .replace("___JS_CODE_JSON___", json.dumps(js_code))
    )

    with tempfile.NamedTemporaryFile("w", suffix="_wechat_scan_host.py", delete=False) as f:
        f.write(host)
        host_path = f.name

    try:
        subprocess.run([sys.executable, host_path], check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"frida host failed with exit code {exc.returncode}") from exc
    finally:
        try:
            os.unlink(host_path)
        except OSError:
            pass


def read_captured_keys() -> list[dict]:
    if not FRIDA_LOG.exists():
        return []
    rows = []
    with FRIDA_LOG.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "key" and obj.get("key"):
                    rows.append(obj)
            except json.JSONDecodeError:
                continue
    return rows


# ── Key verification (SQLCipher 4 HMAC-SHA512) ──────────────────────────────

import hashlib
import hmac as hmac_mod
import struct


def _pbkdf2_hmac_sha512(key: bytes, salt: bytes, iterations: int, dk_len: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", key, salt, iterations, dklen=dk_len)


def _mac_key(enc_key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return _pbkdf2_hmac_sha512(enc_key, mac_salt, 2, KEY_SIZE)


def verify_key(db_path: Path, key_hex: str) -> bool:
    """Verify a candidate key using SQLCipher 4 HMAC-SHA512 on page 1."""
    key = bytes.fromhex(key_hex)
    if len(key) != KEY_SIZE:
        return False
    try:
        with db_path.open("rb") as f:
            page = f.read(PAGE_SIZE)
        if len(page) < PAGE_SIZE:
            return False

        salt = page[:SALT_SIZE]
        enc_data = page[SALT_SIZE : PAGE_SIZE - RESERVE]
        stored_hmac = page[PAGE_SIZE - RESERVE : PAGE_SIZE - RESERVE + 64]

        mac_key = _mac_key(key, salt)
        expected_hmac = hmac_mod.new(mac_key, enc_data, hashlib.sha512)
        expected_hmac.update(struct.pack("<I", 1))
        return hmac_mod.compare_digest(expected_hmac.digest(), stored_hmac)
    except Exception:
        return False


def match_and_validate(db_info: dict, captured: list[dict], existing: dict[str, str],
                       targets: list[str]) -> dict[str, str]:
    print("\n[4/4] Matching and validating keys...")
    result = dict(existing)

    seen = set()
    candidates = []
    for item in captured:
        key_hex = item.get("key", "")
        if key_hex and key_hex not in seen and len(key_hex) == 64:
            seen.add(key_hex)
            candidates.append(key_hex)

    print(f"  Captured {len(captured)} raw keys, {len(candidates)} unique candidates")

    for name in targets:
        item = db_info.get(name)
        if not item:
            continue
        if result.get(name) and verify_key(Path(item["path"]), result[name]):
            print(f"  OK {name}: existing key still works")
            continue

        matched = None
        for key_hex in candidates:
            if verify_key(Path(item["path"]), key_hex):
                matched = key_hex
                print(f"  OK {name}: matched key")
                break

        if matched is None:
            for key_hex in candidates:
                if verify_key(Path(item["path"]), key_hex):
                    matched = key_hex
                    print(f"  OK {name}: matched key (cross-salt)")
                    break

        if matched:
            result[name] = matched
        else:
            print(f"  [MISS] {name}: no matching key")

    return result


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan WeChat Mac 4.x process memory for SQLCipher 4 encryption keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Typical runs:
              python3 scan_memory.py --targets all --duration 240
              python3 scan_memory.py --targets sns,favorite --mode attach --duration 120 --skip-prepare
            """
        ),
    )
    parser.add_argument("--mode", choices=["spawn", "attach"], default="spawn")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--targets", default="all")
    parser.add_argument("--db-base", default=None)
    parser.add_argument("--wechat-copy", default=str(WECHAT_COPY))
    parser.add_argument("--skip-prepare", action="store_true")
    parser.add_argument("--no-heap-scan", action="store_true",
                        help="Disable heap scanning (only use hook-based capture)")
    parser.add_argument("--reuse-log", action="store_true")
    parser.add_argument("--list-dbs", action="store_true")
    parser.add_argument("--show-sensitive", action="store_true",
                        help="Show account identifiers, database paths, and salt prefixes.")
    args = parser.parse_args()

    print("=" * 64)
    print("WeChat Mac 4.x Memory Key Scanner")
    print("=" * 64)

    check_env()
    wxid, db_base = find_db_base(args.db_base)
    db_info = collect_db_info(db_base)
    print(f"  wxid: {wxid if args.show_sensitive else '[redacted]'}")
    print(f"  db_base: {db_base if args.show_sensitive else '[redacted]'}")
    print(f"  Databases found: {len(db_info)}")

    if args.list_dbs:
        for name, item in sorted(db_info.items()):
            salt = item['salt'][:16] + '...' if args.show_sensitive else '[redacted]'
            print(f"    {name}: salt={salt} size={int(item['size'])/1024/1024:.2f} MB")
        return

    targets = normalize_targets(args.targets, db_info)
    target_salts = [db_info[name]["salt"] for name in targets if name in db_info]

    copy_path = Path(args.wechat_copy).expanduser()
    prepare_wechat(copy_path, args.skip_prepare)
    run_scan(
        mode=args.mode,
        duration=args.duration,
        copy_path=copy_path,
        target_salts=target_salts,
        reset_log=not args.reuse_log,
        scan_heap=not args.no_heap_scan,
    )

    captured = read_captured_keys()
    existing = load_json(KEYS_FILE)

    if not captured:
        print("\n  [WARN] No keys captured. Tips:")
        print("    1. Make sure WeChat is logged in")
        print("    2. Interact with WeChat: open chats, favorites, moments")
        print("    3. Try longer duration: --duration 240")
        print("    4. Try attach mode: --mode attach --skip-prepare")
        print("    5. If task_for_pid fails, re-sign WeChat with get-task-allow")
        sys.exit(1)

    matched = match_and_validate(db_info, captured, existing, targets)

    save_json(KEYS_FILE, matched)

    missing = [name for name in targets if name not in matched]
    print("\n" + "=" * 64)
    if missing:
        print(f"Not all keys captured ({len(missing)}/{len(targets)} missing):")
        for name in missing:
            print(f"  - {name}")
        print("\nTry again with more interaction or longer duration.")
        raise SystemExit(2)
    else:
        print(f"Done. All {len(targets)} keys captured and validated.")
        print(f"Keys saved to {KEYS_FILE}")
    print("=" * 64)


if __name__ == "__main__":
    main()
