"""Message event for the Douyin platform adapter."""

from astrbot import logger
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.message_components import (
    At,
    AtAll,
    BaseMessageComponent,
    Image,
    Plain,
    Reply,
)
from astrbot.api.platform import AstrBotMessage, PlatformMetadata

from .client import DouyinWebClient


class DouyinMessageEvent(AstrMessageEvent):
    """Carries the client so replies can be delivered back to the conversation."""

    def __init__(
        self,
        message_str: str,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        session_id: str,
        client: DouyinWebClient,
    ) -> None:
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.client = client

    async def send(self, message: MessageChain) -> None:
        await send_chain_via_client(self.client, self.session_id, message.chain)
        await super().send(message)


async def send_chain_via_client(
    client: DouyinWebClient,
    conv_key: str,
    chain: list[BaseMessageComponent],
) -> None:
    """Deliver a component chain to one Douyin conversation.

    Adjacent Plain components are merged into a single text send. Only text
    and image components are supported; anything else degrades to a
    placeholder so the reply is never silently dropped.
    """
    pending_text = ""
    for comp in chain:
        if isinstance(comp, Plain):
            pending_text += comp.text or ""
            continue
        if pending_text.strip():
            if not await client.send_text(conv_key, pending_text):
                logger.error(f"[douyin] failed to send text to {conv_key!r}")
            pending_text = ""
        if isinstance(comp, Image):
            try:
                image_path = await comp.convert_to_file_path()
                if not await client.send_image(conv_key, image_path):
                    logger.error(f"[douyin] failed to send image to {conv_key!r}")
            except Exception as e:
                logger.error(f"[douyin] image convert/send failed: {e}")
                await client.send_text(conv_key, "[图片发送失败]")
        elif isinstance(comp, At | AtAll | Reply):
            # Core adds these for group replies; Douyin IM has no equivalent,
            # drop them silently instead of sending placeholder noise.
            logger.debug(f"[douyin] dropped {comp.type} component for douyin")
        else:
            logger.warning(
                f"[douyin] unsupported component {comp.type}, replaced with placeholder"
            )
            comp_name = getattr(comp.type, "name", None) or str(comp.type)
            await client.send_text(conv_key, f"[{comp_name}]")
    if pending_text.strip():
        if not await client.send_text(conv_key, pending_text):
            logger.error(f"[douyin] failed to send text to {conv_key!r}")
