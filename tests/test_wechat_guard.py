import contextlib
import html
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("wechat_guard", ROOT / "scripts" / "wechat_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "db_storage"
        (self.db / "message").mkdir(parents=True)
        for name in ("message_0.db", "message_1.db", "message_fts.db"):
            (self.db / "message" / name).touch()
        self.keys = self.root / "keys.json"
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"db_dir": str(self.db), "keys_file": str(self.keys)}))

    def set_keys(self, names):
        self.keys.write_text(json.dumps({name: {"enc_key": "fixture-not-a-real-key"} for name in names}))

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "wechat_guard.py"), *args], capture_output=True, text=True)

    def test_missing_shard_fails_closed_before_upstream_query(self):
        self.set_keys(["message/message_0.db"])
        result = self.invoke("--config", str(self.config), "history", "测试群", "--format", "json")
        self.assertEqual(result.returncode, 3)
        self.assertIn("message_1.db", result.stderr)
        self.assertIn("查询中止", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("fixture-not-a-real-key", result.stderr)

    def test_complete_coverage_is_only_name_coverage(self):
        self.set_keys(["message/message_0.db", "message\\message_1.db"])
        info = guard.coverage(str(self.config))
        self.assertTrue(info["complete"])
        self.assertEqual(info["shard_count"], 2)
        self.assertFalse(info["key_validity_checked"])

    def test_new_messages_is_blocked_before_cursor_can_advance(self):
        self.set_keys(["message/message_0.db"])
        result = self.invoke("--config", str(self.config), "new-messages")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")
        self.assertIn("查询中止", result.stderr)

    def test_missing_key_metadata_is_not_reported_complete(self):
        with self.assertRaises(OSError):
            guard.coverage(str(self.config))
        result = self.invoke("--config", str(self.config), "stats", "测试群")
        self.assertEqual(result.returncode, 3)
        self.assertIn("无法检查", result.stderr)

    def test_init_is_blocked_after_global_config(self):
        result = self.invoke("--config", str(self.config), "init")
        self.assertEqual(result.returncode, 2)
        self.assertIn("被禁用", result.stderr)

    def test_partial_does_not_allow_stats_or_missing_coverage(self):
        self.set_keys(["message/message_0.db"])
        result = self.invoke("--config", str(self.config), "stats", "测试群", "--allow-partial")
        self.assertEqual(result.returncode, 2)
        self.assertIn("仅支持 history", result.stderr)
        self.keys.unlink()
        result = self.invoke("--config", str(self.config), "history", "测试群", "--allow-partial")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")

    def test_runtime_parser_is_wired_into_cli(self):
        self.set_keys(["message/message_0.db", "message/message_1.db"])
        from wechat_cli.core import messages
        from wechat_cli.main import cli
        original = messages._format_app_message_text
        observed = []

        def fake_cli(**kwargs):
            observed.append(messages._format_app_message_text(forward_xml(record_xml()), 49, False, "", "", {}, None))
        try:
            with patch.object(sys, "argv", ["guard", "--config", str(self.config), "history", "测试群"]), patch.object(cli, "main", side_effect=fake_cli):
                self.assertEqual(guard.main(), 0)
            self.assertIn("测试员", observed[0])
            self.assertIn("模拟正文", observed[0])
        finally:
            messages._format_app_message_text = original

    def test_partial_text_is_marked_and_returns_nonzero(self):
        self.set_keys(["message/message_0.db"])
        from wechat_cli.core import messages
        from wechat_cli.main import cli
        original = messages._format_app_message_text
        out, err = io.StringIO(), io.StringIO()
        try:
            with patch.object(sys, "argv", ["guard", "--config", str(self.config), "history", "测试群", "--format", "text", "--allow-partial"]), patch.object(cli, "main", side_effect=lambda **kwargs: print("样本消息")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(guard.main(), 3)
            self.assertTrue(out.getvalue().startswith("【不完整结果】"))
            self.assertIn("样本消息", out.getvalue())
            self.assertIn("局部结果", err.getvalue())
        finally:
            messages._format_app_message_text = original


def record_xml():
    return '<recordinfo><datalist><dataitem datatype="1"><sourcename>测试员</sourcename><sourcetime>10:00</sourcetime><datadesc>模拟正文</datadesc></dataitem></datalist></recordinfo>'


def forward_xml(record):
    return f'<msg><appmsg><title>模拟记录</title><type>19</type><recorditem><![CDATA[{record}]]></recorditem></appmsg></msg>'


class ForwardTests(unittest.TestCase):
    def test_plain_forward_and_unrelated_message(self):
        result = guard.format_forward(forward_xml(record_xml()))
        self.assertIn("测试员 10:00: 模拟正文", result)
        self.assertIsNone(guard.format_forward('<msg><appmsg><type>5</type><title>链接</title></appmsg></msg>'))

    def test_nested_escaped_record(self):
        nested = html.escape(record_xml())
        outer = f'<recordinfo><datalist><dataitem datatype="17"><sourcename>转发者</sourcename><datatitle>嵌套</datatitle><recorditem>{nested}</recorditem></dataitem></datalist></recordinfo>'
        result = guard.format_forward(forward_xml(outer))
        self.assertIn("转发者", result)
        self.assertIn("测试员 10:00: 模拟正文", result)

    def test_malformed_and_unsafe_nested_xml_fail_closed(self):
        payload = '<!DOCTYPE recordinfo [<!ENTITY x "PRIVATE">]><recordinfo><datalist/></recordinfo>'
        result = guard.format_forward(forward_xml(payload))
        self.assertIn("不可解析", result)
        self.assertNotIn("PRIVATE", result)
        result = guard.format_forward(forward_xml('<recordinfo><broken>PRIVATE'))
        self.assertIn("不可解析", result)
        self.assertNotIn("PRIVATE", result)

    def test_bounds_and_nontext_do_not_print_transport_fields(self):
        item = '<dataitem datatype="2"><sourcename>测试员</sourcename><cdn_dataurl>PRIVATE_TOKEN</cdn_dataurl></dataitem>'
        record = '<recordinfo><datalist>' + item * 102 + '</datalist></recordinfo>'
        result = guard.format_forward(forward_xml(record))
        self.assertIn("非文本", result)
        self.assertIn("条数上限", result)
        self.assertNotIn("PRIVATE_TOKEN", result)

    def test_full_history_path_reads_synthetic_forward_from_sqlite(self):
        from wechat_cli.core import messages
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "synthetic.db"
            table = "Msg_" + "a" * 32
            with sqlite3.connect(db) as conn:
                conn.execute(f'CREATE TABLE [{table}] (local_id INTEGER, local_type INTEGER, create_time INTEGER, real_sender_id INTEGER, message_content TEXT, WCDB_CT_message_content INTEGER)')
                conn.execute(f'INSERT INTO [{table}] VALUES (1, 49, 1793836800, 0, ?, 0)', (forward_xml(record_xml()),))
            ctx = {"query": "样本", "username": "sample", "display_name": "样本", "db_path": str(db), "table_name": table, "message_tables": [], "is_group": False}
            original = messages._format_app_message_text
            def patched(content, *rest, **kwargs):
                return guard.format_forward(content) or original(content, *rest, **kwargs)
            with patch.object(messages, "_format_app_message_text", side_effect=patched):
                lines, failures = messages.collect_chat_history(ctx, {}, lambda user, names: user, limit=10)
            self.assertFalse(failures)
            self.assertEqual(len(lines), 1)
            self.assertIn("测试员 10:00: 模拟正文", lines[0])

    def test_guard_to_real_history_command_with_synthetic_database(self):
        from types import SimpleNamespace
        import wechat_cli.main as entry
        import wechat_cli.commands.history as history_module
        from wechat_cli.core import messages
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db_dir = root / "source"
            (db_dir / "message").mkdir(parents=True)
            (db_dir / "message" / "message_0.db").touch()
            keys = root / "keys.json"
            keys.write_text(json.dumps({"message/message_0.db": {"enc_key": "fixture"}}))
            config = root / "config.json"
            config.write_text(json.dumps({"db_dir": str(db_dir), "keys_file": str(keys)}))
            database = root / "fixture.db"
            table = "Msg_" + "b" * 32
            with sqlite3.connect(database) as conn:
                conn.execute(f'CREATE TABLE [{table}] (local_id INTEGER, local_type INTEGER, create_time INTEGER, real_sender_id INTEGER, message_content TEXT, WCDB_CT_message_content INTEGER)')
                conn.execute(f'INSERT INTO [{table}] VALUES (1, 49, 1793836800, 0, ?, 0)', (forward_xml(record_xml()),))
            ctx = {"query": "样本", "username": "sample", "display_name": "样本", "db_path": str(database), "table_name": table, "message_tables": [], "is_group": False}
            app = SimpleNamespace(msg_db_keys=[], cache=None, decrypted_dir="", db_dir=str(db_dir), display_name_fn=lambda user, names: user)
            output = io.StringIO()
            original = messages._format_app_message_text
            try:
                with patch.object(sys, "argv", ["guard", "--config", str(config), "history", "样本", "--format", "json"]), patch.object(entry, "AppContext", return_value=app), patch.object(history_module, "resolve_chat_context", return_value=ctx), patch.object(history_module, "get_contact_names", return_value={}), contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as exit_result:
                        guard.main()
                self.assertEqual(exit_result.exception.code, 0)
                response = json.loads(output.getvalue())
                self.assertEqual(response["count"], 1)
                self.assertIn("测试员 10:00: 模拟正文", response["messages"][0])
                messages._format_app_message_text = original
                (db_dir / "message" / "message_1.db").touch()
                output, error = io.StringIO(), io.StringIO()
                with patch.object(sys, "argv", ["guard", "--config", str(config), "history", "样本", "--format", "json", "--allow-partial"]), patch.object(entry, "AppContext", return_value=app), patch.object(history_module, "resolve_chat_context", return_value=ctx), patch.object(history_module, "get_contact_names", return_value={}), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                    self.assertEqual(guard.main(), 3)
                partial = json.loads(output.getvalue())
                self.assertIn("模拟正文", partial["messages"][0])
                self.assertFalse(partial["coverage"]["complete"])
                self.assertEqual(partial["coverage"]["missing_shards"], ["message_1.db"])
                self.assertIn("局部结果", error.getvalue())
            finally:
                messages._format_app_message_text = original

    def test_nested_transport_fields_are_not_read_as_human_text(self):
        record = '<recordinfo><datalist><dataitem datatype="1"><datadesc>可见正文<aeskey>PRIVATE_TOKEN</aeskey></datadesc></dataitem></datalist></recordinfo>'
        result = guard.format_forward(forward_xml(record))
        self.assertIn("可见正文", result)
        self.assertNotIn("PRIVATE_TOKEN", result)


if __name__ == "__main__":
    unittest.main()
