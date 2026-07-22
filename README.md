# yichen-wechat-local-vault

老王注：原 Skill 来源：https://github.com/mcncarl/yichen-skills ，直接运行不行，取不到数据！用 Codex 半小时硬解（用 Clauded Code 改了三个小时硬是没有改出来，哈哈）至少本机 Mac/Apple M5/Tahoe 26.0/微信版本 4.1.2.241 经测试可正常运行。

面向 Claude Code 与 Codex 的 macOS 微信本地数据查询、导出和分析 Skill。默认只读，日常查询基于固定提交版本的 [`wechat-cli`](https://github.com/huohuoer/wechat-cli)。

## 安装与检查

```bash
python3 scripts/run.py doctor
python3 scripts/run.py setup
python3 scripts/check_public.py
```

主要入口：

```bash
python3 scripts/run.py wechat sessions --limit 20 --format text
python3 scripts/run.py wechat history "联系人或群名" --limit 50 --format text
python3 scripts/run.py wechat search "关键词" --limit 50 --format text
```

完整的 Agent 使用规则和安全边界见 [SKILL.md](SKILL.md)。

## 隐私与安全

本项目处理的数据可能包含完整聊天记录和数据库密钥。密钥、配置、数据库、日志、导出、虚拟环境和临时签名应用均已加入 `.gitignore`，不得提交或上传。

旧版密钥捕获能力会读取微信进程内存，并可能创建临时重新签名的微信副本。启动器默认拒绝执行；只有了解影响并明确同意后，才使用 `--allow-invasive-capture`。固定的上游版本可能原地重新签名微信原件，因此启动器明确禁用 `wechat init`。

发布前必须执行：

```bash
python3 scripts/check_public.py
```

## 范围说明

- 仅适用于用户本人有权访问的本机数据。
- 不提供远程采集、账号绕过、消息发送或云端上传能力。
- 微信版本变化可能导致本地数据库格式或捕获流程失效。

## License

[MIT License](LICENSE)
