"""Douyin platform adapter for AstrBot.

Polls watched conversations through DouyinWebClient and commits incoming
messages as AstrBotMessageEvents. Outgoing MessageChains (including
proactive pushes) are delivered back through the client.
"""

import asyncio
import time

from astrbot import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import At, Image, Plain, Record, Reply
from astrbot.api.platform import (
    AstrBotMessage,
    Group,
    MessageMember,
    MessageType,
    Platform,
    PlatformMetadata,
    register_platform_adapter,
)
from astrbot.core.platform.astr_message_event import MessageSesion

from .client import DouyinWebClient
from .event import DouyinMessageEvent, send_chain_via_client

DOUYIN_CONFIG_METADATA = {
    "browser_profile_dir": {
        "description": "浏览器用户数据目录",
        "type": "string",
        "hint": (
            "Chromium 持久化用户目录，用于保存抖音登录态。留空则使用 "
            "AstrBot 数据目录下的 douyin_profile。可指向 douyin-chat-export "
            "的 data/browser_profile 以直接复用已有登录态。"
        ),
    },
    "cookies": {
        "description": "Cookie 字符串",
        "type": "string",
        "hint": (
            "可选。无头模式无法扫码时，粘贴从浏览器复制的抖音 Cookie"
            "（支持 DevTools JSON 数组或 key=value; key=value 格式）。"
        ),
    },
    "headless": {
        "description": "无头模式",
        "type": "bool",
        "hint": "服务器部署时开启；桌面环境建议关闭以便扫码登录和观察运行状态。",
    },
    "watched_conversations": {
        "description": "监听的会话列表",
        "type": "list",
        "items": {"type": "string"},
        "hint": (
            "填写会话昵称或数字会话 ID。仅拉取列表内会话的新消息。"
            "数字 ID 需先执行 /douyin_scan 绑定昵称后才能回复。"
        ),
    },
    "group_conversations": {
        "description": "群聊会话列表",
        "type": "list",
        "items": {"type": "string"},
        "hint": (
            "watched_conversations 中属于群聊的条目（填相同内容）。"
            "群聊事件按 GROUP_MESSAGE 处理，消息带 发言人: 前缀，"
            "遵循 AstrBot 标准唤醒规则（需唤醒词/@）。"
        ),
    },
    "poll_interval": {
        "description": "轮询间隔（秒）",
        "type": "int",
        "hint": "每轮遍历所有监听会话的间隔。",
    },
    "login_timeout": {
        "description": "登录等待超时（秒）",
        "type": "int",
        "hint": "启动后等待扫码/登录态出现的最长时间。",
    },
    "self_uid": {
        "description": "自己的抖音 UID（可选）",
        "type": "string",
        "hint": "用于过滤自己发送的消息。默认自动从页面读取，读取失败时填写。",
    },
    "conversation_aliases": {
        "description": "会话显示名修正",
        "type": "list",
        "items": {"type": "string"},
        "hint": (
            "格式：会话键=显示名（如 7571332346864042523=我的群聊）。"
            "扫描绑定的群名不准确时，在此手动指定；开启「识别用户/显示群名称」"
            "后模型将读到该名称。"
        ),
    },
}


@register_platform_adapter(
    "douyin",
    "抖音私信适配器（Playwright 网页自动化）",
    default_config_tmpl={
        "browser_profile_dir": "",
        "cookies": "",
        "headless": False,
        "watched_conversations": [],
        "group_conversations": [],
        "poll_interval": 3,
        "login_timeout": 300,
        "self_uid": "",
        "conversation_aliases": [],
    },
    adapter_display_name="抖音",
    support_streaming_message=False,
    config_metadata=DOUYIN_CONFIG_METADATA,
    logo_path="logo.png",
)
class DouyinPlatformAdapter(Platform):
    """Adapter bridging Douyin web DMs into the AstrBot event pipeline."""

    instances: list["DouyinPlatformAdapter"] = []
    """Live adapter instances, used by the /douyin_status command."""

    def __init__(
        self,
        platform_config: dict,
        platform_settings: dict,
        event_queue: asyncio.Queue,
    ) -> None:
        super().__init__(platform_config, event_queue)
        self.settings = platform_settings
        self.client = DouyinWebClient(platform_config)
        self.poll_interval = max(int(platform_config.get("poll_interval") or 3), 1)
        self._shutdown = asyncio.Event()

        self.metadata = PlatformMetadata(
            name="douyin",
            description="抖音私信适配器",
            id=str(self.config.get("id", "douyin")),
            support_streaming_message=False,
        )
        DouyinPlatformAdapter.instances.append(self)

    async def send_by_session(
        self,
        session: MessageSesion,
        message_chain: MessageChain,
    ) -> None:
        """Proactively push a message chain to a persisted session."""
        try:
            await send_chain_via_client(
                self.client, session.session_id, message_chain.chain
            )
        finally:
            await super().send_by_session(session, message_chain)

    def meta(self) -> PlatformMetadata:
        return self.metadata

    async def run(self) -> None:
        """Main loop: poll every watched conversation and commit new events."""
        watched = [
            str(w).strip()
            for w in (self.config.get("watched_conversations") or [])
            if str(w).strip()
        ]
        if not watched:
            raise ValueError("douyin adapter requires non-empty watched_conversations")

        await self.client.start()
        logger.info(f"[douyin] adapter started, watching: {watched}")

        while not self._shutdown.is_set():
            for conv_key in watched:
                if self._shutdown.is_set():
                    break
                try:
                    messages = await self.client.poll_conversation(conv_key)
                except Exception as e:
                    logger.warning(f"[douyin] poll {conv_key!r} failed: {e}")
                    continue
                for msg in messages:
                    abm = await self.convert_message(msg, conv_key)
                    if abm is not None:
                        await self.handle_msg(abm)

            try:
                await asyncio.wait_for(
                    self._shutdown.wait(), timeout=self.poll_interval
                )
            except asyncio.TimeoutError:
                pass

    async def convert_message(self, msg: dict, conv_key: str) -> AstrBotMessage | None:
        """Map one polled message into an AstrBotMessage.

        Media is downloaded through the page context and wrapped into local
        file components; failures degrade to placeholder text components.
        Conversations listed in group_conversations are committed as
        GROUP_MESSAGE events with sender-prefixed text so the model can
        tell speakers apart; everything else is a FRIEND_MESSAGE.

        Returns None for own messages or messages with no usable content.
        """
        info = msg["_parsed"]
        sender_uid = msg.get("sender_uid", "")
        self_uid = await self.client.get_self_uid()
        if sender_uid and self_uid and sender_uid == self_uid:
            return None

        components: list = []
        text_parts: list[str] = []
        local_files: list[str] = []

        # Quoted/reply payload (Douyin field 18) -> standard Reply component;
        # core injects it into the LLM request as <Quoted Message>. When the
        # quoted original carries media (sticker/image), resolve it through
        # the recent-message cache and attach the real image so the model
        # sees the actual quoted content instead of a "[表情]" placeholder.
        ref = msg.get("ref_msg") or {}
        if isinstance(ref, dict) and (
            ref.get("content") or ref.get("refmsg_content") or ref.get("nickname")
        ):
            ref_text = str(
                ref.get("content") or ref.get("refmsg_content") or ""
            ).strip()
            ref_nick = str(ref.get("nickname") or "").strip()
            ref_sid = str(ref.get("server_id") or "")
            reply_chain: list = []
            if ref_text:
                reply_chain.append(Plain(text=ref_text))
            cached = self.client.get_cached_message(ref_sid)
            if cached and cached.get("urls"):
                for idx, candidate in enumerate(cached["urls"]):
                    suffix = ".img" if idx == 0 else f".img{idx}"
                    local_path = await self.client.download_media(
                        candidate,
                        f"ref_{ref_sid}{suffix}",
                        skey_hex=cached.get("skey"),
                    )
                    if local_path:
                        reply_chain.append(Image.fromFileSystem(str(local_path)))
                        local_files.append(str(local_path))
                        break
            if not reply_chain and cached and cached.get("text"):
                reply_chain.append(Plain(text=str(cached["text"])))
            components.append(
                Reply(
                    id=ref_sid,
                    sender_nickname=ref_nick,
                    message_str=ref_text,
                    chain=reply_chain,
                )
            )
            # No inline copy in text_parts: core already injects the Reply
            # component as a <Quoted Message> block into the LLM request.

        text = info.get("text", "")
        kind = info.get("media_kind")
        # CDN nodes rotate (p3/p9/p26...); every candidate URL is tried.
        media_candidates = [
            u for u in (info.get("media_urls") or []) if isinstance(u, str)
        ]
        media_skey = info.get("media_skey") or None
        duration_ms = int(info.get("duration_ms") or 0)

        if text:
            components.append(Plain(text=text))
            text_parts.append(text)

        server_id = msg.get("server_id", "")
        if kind in ("image", "video_cover"):
            placeholder = "[视频]" if kind == "video_cover" else "[图片]"
            local_path = None
            if media_candidates:
                for idx, candidate in enumerate(media_candidates):
                    suffix = ".img" if idx == 0 else f".img{idx}"
                    local_path = await self.client.download_media(
                        candidate, f"{server_id}{suffix}", skey_hex=media_skey
                    )
                    if local_path:
                        break
            if local_path:
                components.append(Image.fromFileSystem(str(local_path)))
                local_files.append(str(local_path))
            elif not text:
                components.append(Plain(text=placeholder))
                text_parts.append(placeholder)
        elif kind == "voice":
            local_path = None
            if media_candidates:
                for idx, candidate in enumerate(media_candidates):
                    suffix = ".mp3" if idx == 0 else f".mp3{idx}"
                    local_path = await self.client.download_media(
                        candidate, f"{server_id}{suffix}", skey_hex=media_skey
                    )
                    if local_path:
                        break
            if local_path:
                components.append(Record.fromFileSystem(str(local_path)))
                local_files.append(str(local_path))
                if not text:
                    text_parts.append("[语音]")
            elif not text:
                placeholder = (
                    f"[语音 {round(duration_ms / 1000)}秒]" if duration_ms else "[语音]"
                )
                components.append(Plain(text=placeholder))
                text_parts.append(placeholder)

        if not components:
            return None

        nickname = await self.client.get_nickname(sender_uid)
        group_keys = [
            str(g).strip() for g in (self.config.get("group_conversations") or [])
        ]

        message_str = "".join(text_parts)
        abm = AstrBotMessage()
        abm.self_id = self_uid or "douyin"
        abm.session_id = conv_key
        abm.message_id = server_id
        abm.sender = MessageMember(user_id=sender_uid, nickname=nickname)
        abm.message = components
        abm.raw_message = {**msg, "_local_files": local_files}
        created_at_us = int(msg.get("created_at_us", 0))
        abm.timestamp = (
            created_at_us // 1_000_000 if created_at_us > 0 else int(time.time())
        )

        if conv_key in group_keys:
            # Group semantics per AstrBot conventions: GROUP_MESSAGE type and
            # Group metadata. message_str stays the RAW user text — core's
            # wake check matches wake_prefix via startswith() on it, so no
            # sender prefix may be prepended here (speaker identity is
            # provided by provider settings like identifier / group context).
            # A leading "@<self nickname>" text mention is translated into a
            # real At component so core's At-wake check can see it; the text
            # itself is kept untouched because users may configure the same
            # mention as a wake_prefix.
            abm.type = MessageType.GROUP_MESSAGE
            abm.group = Group(
                group_id=self.client.conversation_real_id(conv_key) or conv_key,
                group_name=self.client.conversation_display_name(conv_key),
            )
            self_nick = await self.client.get_self_nickname()
            if self_nick and message_str.lstrip().startswith(f"@{self_nick}"):
                components.insert(0, At(qq=self_uid or "douyin"))
            abm.message_str = message_str
        else:
            abm.type = MessageType.FRIEND_MESSAGE
            abm.message_str = message_str
        return abm

    async def handle_msg(self, message: AstrBotMessage) -> None:
        event = DouyinMessageEvent(
            message_str=message.message_str,
            message_obj=message,
            platform_meta=self.meta(),
            session_id=message.session_id,
            client=self.client,
        )
        raw = message.raw_message
        if isinstance(raw, dict):
            for path in raw.get("_local_files", []):
                event.track_temporary_local_file(path)
        self.commit_event(event)

    async def terminate(self) -> None:
        logger.info("[douyin] adapter terminating")
        self._shutdown.set()
        if self in DouyinPlatformAdapter.instances:
            DouyinPlatformAdapter.instances.remove(self)
        await self.client.close()
