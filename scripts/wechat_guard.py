"""Guard the pinned CLI and expand bounded forwarded records locally.

The guard checks configured shard names, not key validity or message freshness.
It neither captures keys nor changes a WeChat database or app.
"""
from __future__ import annotations

import html
import contextlib
import io
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_XML = 512_000
MAX_ITEMS = 100
MAX_DEPTH = 3
MAX_FIELD = 4_000
SHARD = re.compile(r"^message_\d+\.db$")
UNSAFE_XML = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.I)
SENSITIVE_COMMANDS = {"history", "search", "stats", "export", "new-messages"}


def command_and_config(argv):
    """Read Click's global options without mistaking their values for commands."""
    config = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--config":
            if i + 1 >= len(argv):
                return None, None
            config = argv[i + 1]
            i += 2
        elif arg.startswith("--config="):
            config = arg.split("=", 1)[1]
            i += 1
        elif arg in ("--help", "--version"):
            return None, config
        elif arg.startswith("-"):
            return None, config
        else:
            return arg, config
    return None, config


def coverage(config_path=None):
    from wechat_cli.core.config import load_config

    cfg = load_config(config_path)
    message_dir = Path(cfg["db_dir"]) / "message"
    if not message_dir.is_dir():
        raise ValueError("message directory unavailable")
    with open(cfg["keys_file"], encoding="utf-8") as stream:
        keys = json.load(stream)
    if not isinstance(keys, dict):
        raise ValueError("key metadata unavailable")
    shards = sorted(p.name for p in message_dir.iterdir() if p.is_file() and SHARD.fullmatch(p.name))
    if not shards:
        raise ValueError("no message shards found")
    configured = {k.replace("\\", "/") for k in keys if isinstance(k, str) and not k.startswith("_")}
    missing = [name for name in shards if f"message/{name}" not in configured]
    return {"complete": not missing, "shard_count": len(shards),
            "configured_count": len(shards) - len(missing), "missing_shards": missing,
            "key_validity_checked": False}


def _tag(node):
    return node.tag.rsplit("}", 1)[-1] if isinstance(node.tag, str) else ""


def _child(node, name):
    return next((item for item in node if _tag(item) == name), None)


def _field(node, name):
    item = _child(node, name)
    if item is None:
        return ""
    # Only direct text is a display field. Nested XML may contain transport keys.
    value = " ".join((item.text or "").split())
    return value[:MAX_FIELD] + ("…[字段已截断]" if len(value) > MAX_FIELD else "")


def _parse_xml(value):
    if not value or len(value) > MAX_XML or UNSAFE_XML.search(value):
        return None
    try:
        return ET.fromstring(value)
    except ET.ParseError:
        return None


def _record_root(node):
    if _tag(node) == "recordinfo":
        return node
    direct = _child(node, "recordinfo")
    if direct is not None:
        return direct
    text = (node.text or "").strip()
    for _ in range(2):
        parsed = _parse_xml(text)
        if parsed is not None:
            return parsed if _tag(parsed) == "recordinfo" else _child(parsed, "recordinfo")
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    return None


def _extract_record(node, depth, budget):
    if depth > MAX_DEPTH:
        return ["[更深层记录未展开]"]
    record = _record_root(node)
    items = _child(record, "datalist") if record is not None else None
    if items is None:
        return ["[合并记录正文不可解析或未包含在消息中]"]
    lines = []
    for item in items:
        if _tag(item) != "dataitem":
            continue
        if budget[0] <= 0:
            lines.append("[其余记录已省略：达到安全条数上限]")
            break
        budget[0] -= 1
        sender = _field(item, "sourcename") or "未知发言人"
        when = _field(item, "sourcetime") or _field(item, "datatime")
        kind = item.get("datatype", "")
        description = _field(item, "datadesc")
        title = _field(item, "datatitle")
        content = description if kind in ("", "1") and description else title or "[非文本或无法读取的内容]"
        prefix = f"{sender} {when}".strip()
        lines.append(f"{prefix}: {content}")
        nested = _child(item, "recorditem")
        if nested is None:
            nested = _child(item, "recordinfo")
        if nested is not None:
            lines.extend("  " + part for part in _extract_record(nested, depth + 1, budget))
    return lines or ["[合并记录没有可展示的条目]"]


def format_forward(content):
    """Return None for other message types; never expose raw XML as fallback."""
    if not isinstance(content, str):
        return None
    start = content.find("<msg")
    if start < 0:
        return None
    root = _parse_xml(content[start:])
    if root is None:
        if "<appmsg" in content[:MAX_XML] and re.search(r"<type>\s*(?:17|19)\s*</type>", content[:MAX_XML]):
            return "[聊天记录] [合并记录正文不可解析或超过安全限制]"
        return None
    app = next((e for e in root.iter() if _tag(e) == "appmsg"), None)
    if app is None or _field(app, "type") not in {"17", "19"}:
        return None
    title = _field(app, "title") or "合并聊天记录"
    record = _child(app, "recorditem")
    details = _extract_record(record, 0, [MAX_ITEMS]) if record is not None else ["[合并记录正文未包含在消息中]"]
    return "[聊天记录] " + title + "\n" + "\n".join(details)


def main():
    args = sys.argv[1:]
    if args == ["--coverage"]:
        try:
            result = coverage()
        except Exception:
            print(json.dumps({"complete": None, "error": "coverage_unavailable"}, ensure_ascii=False))
            return 3
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["complete"] else 3

    partial = "--allow-partial" in args
    if partial:
        args = [arg for arg in args if arg != "--allow-partial"]
    command, config = command_and_config(args)
    if partial and command != "history":
        print("错误：--allow-partial 仅支持 history，不支持搜索、统计或导出。", file=sys.stderr)
        return 2
    if partial and "--help" in args:
        partial = False
    if command == "init":
        print("错误: 上游 init 被禁用，避免修改微信应用。", file=sys.stderr)
        return 2
    if command in SENSITIVE_COMMANDS and not any(x in args for x in ("--help",)):
        try:
            result = coverage(config)
        except Exception:
            print("错误：无法检查消息分片覆盖；查询中止，不能将结果视为完整。", file=sys.stderr)
            return 3
        if not result["complete"] and not partial:
            print("错误：消息分片密钥配置不完整（缺少 " + ", ".join(result["missing_shards"]) + "）；查询中止，不能判断是否无消息。", file=sys.stderr)
            return 3

    from wechat_cli.core import messages
    from wechat_cli.main import cli
    original = messages._format_app_message_text

    def with_forward(content, *rest, **kwargs):
        return format_forward(content) or original(content, *rest, **kwargs)

    messages._format_app_message_text = with_forward
    if partial:
        import click
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                cli.main(args=args, prog_name="wechat-cli", standalone_mode=False)
        except click.ClickException as exc:
            exc.show(file=sys.stderr)
            return exc.exit_code
        content = output.getvalue()
        output_format = "json"
        for i, arg in enumerate(args):
            if arg == "--format" and i + 1 < len(args):
                output_format = args[i + 1]
            elif arg.startswith("--format="):
                output_format = arg.split("=", 1)[1]
        notice = "历史消息仅为已配置分片的局部结果，不能判断完整或无消息；密钥有效性未验证。"
        if output_format == "json":
            try:
                parsed = json.loads(content)
                if not isinstance(parsed, dict):
                    raise ValueError("history output is not an object")
            except (ValueError, json.JSONDecodeError):
                print("错误：无法验证历史输出结构；局部结果已丢弃。", file=sys.stderr)
                return 3
            parsed["coverage"] = {"complete": False, "reason": "partial_query",
                                  "missing_shards": result["missing_shards"],
                                  "key_validity_checked": False, "notice": notice}
            print(json.dumps(parsed, ensure_ascii=False))
        else:
            print("【不完整结果】" + notice)
            print(content, end="")
        print("警告：" + notice, file=sys.stderr)
        return 3
    cli.main(args=args, prog_name="wechat-cli", standalone_mode=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
