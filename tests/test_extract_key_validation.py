import importlib.util
import hashlib
import hmac
import struct
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from Crypto.Cipher import AES


spec = importlib.util.spec_from_file_location(
    "extract_keys", Path(__file__).resolve().parents[1] / "scripts" / "extract_keys.py"
)
extract_keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract_keys)


class KeyValidationTests(unittest.TestCase):
    def test_publish_is_atomic_private_and_only_after_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "message/message_1.db"
            db.parent.mkdir()
            db.touch()
            config = root / "all_keys.json"
            previous = {"message/message_0.db": {"enc_key": "old"}}
            config.write_text(json.dumps(previous))
            info = {"message_1": {"path": str(db)}}
            cfg = {"db_dir": str(root), "keys_file": str(config)}
            with patch.object(extract_keys, "try_decrypt_page", return_value=False):
                with self.assertRaises(ValueError):
                    extract_keys.merge_cli_keys(root, info, {"message_1": "candidate"}, ["message_1"], cfg)
            self.assertEqual(json.loads(config.read_text()), previous)
            self.assertEqual(list(root.glob(".wechat-keys-*")), [])
            with patch.object(extract_keys, "try_decrypt_page", return_value=True):
                extract_keys.merge_cli_keys(root, info, {"message_1": "candidate"}, ["message_1"], cfg)
            actual = json.loads(config.read_text())
            self.assertEqual(actual["message/message_0.db"], previous["message/message_0.db"])
            self.assertEqual(actual["message/message_1.db"]["enc_key"], "candidate")
            backups = list(root.glob(".wechat-keys-backup-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(json.loads(backups[0].read_text()), previous)
            self.assertEqual(os.stat(config).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(backups[0]).st_mode & 0o777, 0o600)

    def test_capture_keeps_candidates_in_memory_and_does_not_print_them(self):
        secret = "a" * 64

        class Script:
            def on(self, _name, callback):
                self.callback = callback

            def load(self):
                self.callback({"type": "send", "payload": {"type": "pbkdf2",
                              "data": {"dk": secret}}}, None)

        script = Script()
        session = SimpleNamespace(create_script=lambda js: script, detach=lambda: None)
        device = SimpleNamespace(spawn=lambda args, **kwargs: 10, attach=lambda pid: session,
                                 resume=lambda pid: None, kill=lambda pid: None)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "Contents/MacOS/WeChat"
            binary.parent.mkdir(parents=True)
            binary.touch()
            output = io.StringIO()
            with patch.dict(sys.modules, {"frida": SimpleNamespace(get_local_device=lambda: device)}), \
                 patch.object(extract_keys.time, "sleep"), contextlib.redirect_stdout(output):
                rows = extract_keys.run_frida_capture(mode="spawn", duration=1,
                    copy_path=Path(directory), target_salts=[], reset_log=True)
            self.assertEqual(rows[0]["dk"], secret)
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn("appendJsonLine(item)", extract_keys.FRIDA_JS)

    def test_copy_validation_refuses_original_and_insecure_paths(self):
        with self.assertRaises(SystemExit):
            extract_keys.prepare_wechat(extract_keys.WECHAT_APP, True)
        with tempfile.TemporaryDirectory(prefix="wechat-") as directory:
            root = Path(directory)
            copy = root / "WeChat.app"
            binary = copy / "Contents/MacOS/WeChat"
            binary.parent.mkdir(parents=True)
            binary.touch()
            with patch.object(extract_keys, "run_cmd"):
                extract_keys.prepare_wechat(copy, True)
                with self.assertRaises(SystemExit):
                    extract_keys.prepare_wechat(copy, False)
                root.chmod(0o755)
                with self.assertRaises(SystemExit):
                    extract_keys.prepare_wechat(copy, True)

    def test_valid_hmac_is_accepted_and_tampering_is_rejected(self):
        key = bytes(range(32))
        salt = bytes(range(16))
        body = bytes(4000) + bytes(range(16))
        mac_salt = bytes(value ^ 0x3A for value in salt)
        mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, 32)
        digest = hmac.new(mac_key, body + struct.pack("<I", 1), hashlib.sha512).digest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.db"
            path.write_bytes(salt + body + digest)
            self.assertTrue(extract_keys.try_decrypt_page(str(path), key.hex()))
            self.assertFalse(extract_keys.try_decrypt_page(str(path), "ff" * 32))
            self.assertFalse(extract_keys.try_decrypt_page(str(path), "invalid"))
            changed = bytearray(path.read_bytes())
            changed[100] ^= 1
            path.write_bytes(changed)
            self.assertFalse(extract_keys.try_decrypt_page(str(path), key.hex()))

    def test_invalid_mac_is_rejected_even_if_plaintext_header_looks_valid(self):
        key = bytes(range(32))
        iv = bytes(range(16))
        plaintext = bytearray(4000)
        plaintext[:8] = bytes([0x10, 0x00, 1, 1, 80, 64, 32, 32])
        encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes(plaintext))
        page = bytes(16) + encrypted + iv + bytes(64)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.db"
            path.write_bytes(page)
            self.assertFalse(extract_keys.try_decrypt_page(str(path), key.hex()))


if __name__ == "__main__":
    unittest.main()
