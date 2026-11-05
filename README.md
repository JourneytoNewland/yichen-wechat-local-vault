# yichen-wechat-local-vault

老王注：原 Skill 来源：https://github.com/mcncarl/yichen-skills ，直接运行不行，取不到数据！用 Codex 半小时硬解（用 Claude Code 改了三个小时硬是没有改出来，哈哈）至少本机 Mac/Apple M5/Tahoe 26.0/微信版本 4.1.2.241 经测试可正常运行。

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

`doctor` 会检查已发现消息分片的密钥配置覆盖。`history`、`search`、`stats`、`export`、`new-messages` 在分片未覆盖或无法检查时以状态码 3 中止，而不是返回容易误解的“无消息”。`new-messages` 可能更新本地游标，并非只读。该检查只核对配置名称，不验证密钥、同步或数据完整性；`sessions` 和 `unread` 仍可读取会话摘要，但摘要不是完整历史。

确需查看已配置分片的旧记录时，可在 `wechat history` 后追加 `--allow-partial`。结果会标注不完整且退出码为 3；零条不代表没有消息。覆盖状态无法检查时仍无法查询，搜索、统计及导出不支持局部模式。

对能读取的合并聊天记录，历史结果会有限展开文本：最多 100 项、3 层；损坏、过大、超限或非文本内容会标出限制。搜索合并记录内部文本暂不保证完整。`--end-time` 使用日期时包含该日全天。

完整的 Agent 使用规则和安全边界见 [SKILL.md](SKILL.md)。

## 隐私与安全

本项目处理的数据可能包含完整聊天记录和数据库密钥。密钥、配置、数据库、日志、导出、虚拟环境和临时签名应用均已加入 `.gitignore`，不得提交或上传。

密钥捕获会读取微信副本的进程内存，启动器默认拒绝执行；只有了解影响并明确同意后才可授权。禁止修改原版微信，`wechat init` 已禁用。临时副本也可能访问账户数据，运行前须退出原版微信并做好备份。

`scan` 已禁用。`keys` 仅接受专用私有临时目录中的已签名副本，不再自动复制、签名或附加到正在运行的进程；候选密钥仅在内存中匹配，验证通过后原子更新 CLI 配置，并保留私有备份。此前版本曾在一台本机实际修复新分片并成功查询；此后新增的副本校验和输出重定向只通过模拟测试，尚未重新进行真实捕获，其他机器或微信版本的兼容性未知。此前捕获曾改写旧版 Vault 配置，需从可信备份恢复，不能仅凭 CLI 查询成功认定旧版 Vault 已恢复。

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
