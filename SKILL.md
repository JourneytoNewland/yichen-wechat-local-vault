---
name: yichen-wechat-local-vault
description: |
  微信 Mac 4.x 本地数据查询与分析。用于本机微信聊天记录、联系人、群聊、朋友圈、收藏夹、客户跟进、关系复盘和内容沉淀。触发词：微信解析、微信增量、聊天记录、导出聊天、朋友圈解析、收藏夹解析、客户跟进、yichen-wechat-local-vault。
---

# 微信本地数据 Vault

仅处理用户本人有权访问的本机微信数据。默认只读，不发送消息、不操作微信界面、不读取第二微信容器。

## 运行入口

始终通过启动器运行，不直接调用其他脚本：

```bash
SKILL_DIR="${CLAUDE_SKILL_DIR:-$HOME/.codex/skills/yichen-wechat-local-vault}"
[ -e "$SKILL_DIR/SKILL.md" ] || SKILL_DIR="$HOME/.claude/skills/yichen-wechat-local-vault"
python3 "$SKILL_DIR/scripts/run.py" doctor
python3 "$SKILL_DIR/scripts/run.py" setup
```

启动器把依赖安装到被 `.gitignore` 排除的 skill 本地 `.venv`，不污染系统 Python。

`doctor` 同时报告消息分片的密钥**配置覆盖**；`key_validity_checked: false` 表示并未验证密钥有效性。覆盖不完整或无法检查时退出码为 3，不代表聊天记录为空。`sessions` 和 `unread` 显示会话摘要，不证明历史正文完整。

## 安全边界

- 不在回复、日志或项目目录中输出或保存密钥、完整 salt、wxid、原始数据库、明文数据库或完整私聊内容。
- 配置和密钥仅保存到工具自己的用户私有目录；导出文件必须使用用户明确指定的位置。
- 日常查询只使用已配置的 `wechat-cli` 或已有私有 vault。
- `keys` 和 `scan` 会读取微信进程内存，并可能复制、临时重新签名微信应用。只有用户在当前任务中明确同意后，才可加 `--allow-invasive-capture` 执行。
- 不修改 `/Applications/WeChat.app` 原件。出现权限、签名、SIP 或安全软件拦截时停止，不绕过系统保护。
- 不上传微信数据，不调用云端分析服务，不把输出提交到 Git。
- 发布或提交前运行 `python3 scripts/check_public.py`；检查失败不得发布。

## 日常查询（首选）

优先使用固定提交版本的 `wechat-cli` SQLCipher 4 查询链路：

```bash
python3 "$SKILL_DIR/scripts/run.py" wechat sessions --limit 20 --format text
python3 "$SKILL_DIR/scripts/run.py" wechat unread --limit 50 --format text
python3 "$SKILL_DIR/scripts/run.py" wechat history "联系人或群名" --limit 50 --format text
python3 "$SKILL_DIR/scripts/run.py" wechat search "关键词" --limit 50 --format text
python3 "$SKILL_DIR/scripts/run.py" wechat stats "群名" --start-time "YYYY-MM-DD" --format text
python3 "$SKILL_DIR/scripts/run.py" wechat favorites --limit 20 --format text
```

查询遵循最小必要原则：明确会话时只查该会话，明确时间时只查该时间段；大批量结果先导出到用户指定的私有目录，再做分析。

- 启动器对 `history`、`search`、`stats`、`export`、`new-messages` 检查消息分片配置；未覆盖或检查失败时停止查询并返回非零状态，不能将此结果当作“无消息”。`new-messages` 可能更新本地游标，不属于只读操作。不得绕过启动器调用上游 CLI 来规避检查。
- 用户确实需要查看仍可读取的历史时，可对 `wechat history` 显式追加 `--allow-partial`；其文本和 JSON 均含不完整提示，退出码为 3。它只查询已配置分片，不证明任意时间段或群聊完整，零条不能作为“没有消息”的依据。覆盖信息无法检查时仍停止；搜索、统计和导出不提供该选项。
- 配置覆盖只检查分片名称是否存在于密钥配置中，不能证明密钥有效、WAL 完整、微信已同步、查询成功或数据完整。发现缺分片时不得自行捕获密钥，继续遵守上面的安全边界。
- `history` 对可读消息中的合并转发进行本地有限展开：最多 100 项、3 层；非文本、损坏、过大和超限内容以占位提示，不能声称包含完整附件或全部消息。合并转发内的文本搜索尚不保证覆盖压缩消息，重要核对应读对应历史记录。
- `--end-time YYYY-MM-DD` 包含该日到 23:59:59；查询单日时起止日期应相同。摘要与结果要注明时间、覆盖和限制。

## 已有私有 Vault

只有用户已有旧版私有 vault，或需要朋友圈、摘要素材包时才使用：

```bash
python3 "$SKILL_DIR/scripts/run.py" vault status --format text
python3 "$SKILL_DIR/scripts/run.py" vault history "联系人或群名" --start-time "YYYY-MM-DD" --end-time "YYYY-MM-DD" --format text
python3 "$SKILL_DIR/scripts/run.py" vault search "关键词" --chat "群名" --format text
python3 "$SKILL_DIR/scripts/run.py" vault moments --name "联系人" --start "YYYY-MM-DD" --format text
python3 "$SKILL_DIR/scripts/run.py" vault digest-source "群名" --start "YYYY-MM-DD" --end "YYYY-MM-DD" --format text
```

不要用旧解密器处理 `wechat-cli` 提取的 SQLCipher 4 raw key。

## 首次配置或密钥失效

不要运行 `wechat init`：固定的上游版本可能原地重新签名微信原件，启动器已禁用。`scan` 存在泄漏候选密钥风险，也已禁用。`keys` 只允许用户明确授权后从专用私有临时目录内的已签名副本启动，不再自动复制或签名，也不支持附加原进程；密钥材料在内存中匹配，验证通过才写入 CLI 私有配置并保留私有备份。

此前的捕获实现曾在一台本机上恢复新分片并实际查询群消息；随后新增的私有副本校验和输出重定向尚未重新做真实捕获验证，不代表其他系统或版本可用。继续捕获前须完成备份，核验临时应用副本与授权范围，确认原版微信已退出。出现新的系统保护拦截时停止。捕获完成后退出并清理临时副本；密钥仅保留在用户私有配置目录。此前旧版 Vault 配置受过改写，须使用可信备份恢复，不能从新分片成功推断旧版 Vault 已恢复。

## 分析与输出

- 先给有依据的主题、行动、风险、参与者和时间线，不做极简空泛小结。
- 私聊只引用支撑结论所需的最少原文；群聊区分事实、推断和待确认项。
- 图片不可见时明确标注，不根据上下文编造画面。
- 不推断健康、家庭、身份、所在地等敏感属性，不用时间戳武断推断作息。
- 输出结束时说明数据时间范围、是否完整、使用了哪个本地数据源，以及是否生成了明文文件。

## 发布前检查

```bash
python3 "$SKILL_DIR/scripts/check_public.py"
python3 -m compileall -q "$SKILL_DIR/scripts"
```

仓库只应包含源码、依赖声明、Agent 元数据和文档；`.venv`、缓存、日志、数据库、密钥、配置、状态、导出、临时应用副本都不得提交。
