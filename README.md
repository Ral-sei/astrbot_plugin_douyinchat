# astrbot_plugin_douyinchat

将**抖音网页版私信**作为消息平台接入 [AstrBot](https://github.com/AstrBotDevs/AstrBot)。核心能力移植自 [douyin-chat-export](https://github.com/TeamBreakerr/douyin-chat-export) 项目：通过 Playwright 自动化登录后的抖音网页 IM，直接调用 imapi protobuf 接口拉取新消息，DOM 自动化发送消息。

## 功能

- 接收：轮询监听指定会话的新消息，支持文本、图片、表情包、语音、引用回复（转为 AstrBot 消息组件，媒体下载失败自动降级为占位文本）
- 发送：文本（剪贴板粘贴 + Enter）、图片（剪贴板粘贴 + 弹窗发送按钮）
- 主动推送：支持 AstrBot 的主动消息（`send_by_session`）
- 登录态复用：可直接指向 douyin-chat-export 的浏览器 profile，或通过 Cookie 字符串导入

## 安装

1. 插件目录内自带 `requirements.txt`，AstrBot 会自动安装 `playwright`
2. 手动安装 Chromium 内核：

```bash
playwright install chromium
```

## 配置

在 WebUI「平台适配器」中添加「抖音」实例：

| 配置项 | 说明 |
|--------|------|
| `browser_profile_dir` | Chromium 用户数据目录。留空使用 `<AstrBot数据目录>/douyin_profile`；可指向 douyin-chat-export 的 `data/browser_profile` 直接复用登录态 |
| `cookies` | 可选。无头模式无法扫码时粘贴抖音 Cookie（支持 DevTools JSON 数组或 `key=value; key=value` 格式） |
| `headless` | 无头模式。服务器部署开启；桌面环境建议关闭以便扫码登录 |
| `watched_conversations` | 监听的会话列表：会话昵称或数字会话 ID。数字 ID 需先执行 `/douyin_scan` 绑定昵称后才能回复 |
| `group_conversations` | 群聊会话列表：填写 watched_conversations 中属于群聊的条目。群聊事件按 GROUP_MESSAGE 处理，`message_str` 保持用户原文（唤醒词按 startswith 匹配）；消息中的 `@机器人昵称` 会被翻译为 At 组件以触发标准 @ 唤醒 |
| `poll_interval` | 轮询间隔秒数，默认 3 |
| `login_timeout` | 等待登录超时秒数，默认 300 |
| `self_uid` | 可选。自己的抖音 UID，用于过滤自己发的消息；默认自动从页面读取 |
| `conversation_aliases` | 会话显示名修正：格式 `会话键=显示名`。扫描绑定的群名不准确时手动指定；配合「识别用户」「显示群名称」开关供模型读取 |

## 使用

1. 启动适配器实例。有头模式下首次启动会在弹出的浏览器窗口等待扫码；无头模式请提前导入 Cookie 或复用已有 profile
2. 指令：
   - `/douyin_list` — 刷新并列出所有会话昵称（用于填写监听配置）
   - `/douyin_scan` — 逐个点击会话并绑定「昵称 ↔ 会话ID」（**数字 ID 监听回复必需**），结果同时用于状态展示
   - `/douyin_status` — 查看登录状态、自身 UID、会话解析与绑定情况
3. 在监听列表中的会话发消息即可触发 LLM 回复；私聊自动唤醒，群聊需唤醒词或 @

## 实现说明

- **接收**：向聊天页注入 imapi protobuf 工具，按会话调用 `get_by_conversation` 拉取消息；单聊会话的 `short_id` 通过拦截 SDK 首次请求解析（内存缓存，重启后重新解析）
- **首轮基线**：适配器启动后第一次拉取只标记存量消息、不触发回复，重启不会重放历史
- **零持久化**：本插件不保存任何消息数据，历史记录由 AstrBot 统一管理
- 所有页面 UI 操作串行化执行，避免 DOM 竞争

## 已知限制

- **同一账号禁止多开**：多个浏览器实例（或多个适配器实例）同时登录同一抖音账号会导致消息只在本地可见、他人无法收到——这是网页端 IM 的通道限制，请确保同一时刻只有一个实例使用该账号
- 抖音网页版 DOM class 与接口可能随时变动导致失效
- 媒体 CDN 链接有签名有效期，接收时即时下载落地以规避过期
- 图片发送依赖剪贴板注入与确认弹窗按钮选择器，客户端改版可能需要更新选择器
- 群聊/私聊类型由 `group_conversations` 配置显式声明；群聊遵循 AstrBot 标准唤醒规则（需唤醒词/@），会话隔离等行为由平台设置统一管理
- 群消息的 `message_str` 为用户原文，不含发言人前缀；如需让模型区分不同发言人，请在「配置 → 识别用户(identifier)」开启用户识别，或启用群聊上下文（group_icl）

## 致谢与许可

本项目实现参考了以下开源项目（均为 MIT 协议）：

- [douyin-chat-export](https://github.com/TeamBreakerr/douyin-chat-export) — imapi protobuf 收消息机制、文本发送 DOM 自动化、消息类型解析
- [TikTokcn-AutoSpark](https://github.com/Kounva/TikTokcn-AutoSpark) (Copyright (c) 2026 Kounva) — 备用输入框选择器、会话匹配与随机化操作间隔等风控策略

本插件以 [MIT License](./LICENSE) 发布。
