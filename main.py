from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register


@register(
    "astrbot_plugin_douyinchat",
    "Ral_sei",
    "抖音私信平台适配器：基于 Playwright 自动化抖音网页版收发私信",
    "v0.1.0",
)
class DouyinChatPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        # Importing the adapter module triggers platform registration.
        from .core import adapter as _adapter  # noqa: F401

    @filter.command("douyin_status")
    async def douyin_status(self, event: AstrMessageEvent):
        """查看抖音适配器运行状态"""
        from .core.adapter import DouyinPlatformAdapter

        instances = DouyinPlatformAdapter.instances
        if not instances:
            yield event.plain_result("当前没有运行中的抖音适配器实例。")
            return
        lines = []
        for inst in instances:
            s = inst.client.status()
            resolved = (
                "\n".join(
                    f"  - {k} → {v}" for k, v in s["resolved_conversations"].items()
                )
                or "  (尚未解析)"
            )
            bound = (
                "\n".join(f"  - {k} → {v}" for k, v in s["bound_names"].items())
                or "  (未绑定，请执行 /douyin_scan)"
            )
            lines.append(
                f"实例 {inst.metadata.id}\n"
                f"  运行中: {s['running']}（headless={s['headless']}）\n"
                f"  自己 UID: {s['self_uid']}\n"
                f"  Profile: {s['profile_dir']}\n"
                f"  已解析会话:\n{resolved}\n"
                f"  会话 ID 绑定:\n{bound}"
            )
        yield event.plain_result("\n".join(lines))

    @filter.command("douyin_list")
    async def douyin_list(self, event: AstrMessageEvent):
        """刷新并列出抖音会话列表（用于填写监听配置）"""
        inst = self._running_instance()
        if inst is None:
            yield event.plain_result("没有运行中的抖音适配器，请先在平台适配器页启用。")
            return
        yield event.plain_result("正在滚动加载会话列表，请稍候...")
        convs = await inst.client.list_conversations()
        if not convs:
            yield event.plain_result("未发现任何会话，请确认已登录且聊天页正常。")
            return
        names = [c.get("nickname") or c.get("name") or "?" for c in convs]
        shown = "\n".join(f"{i + 1}. {n}" for i, n in enumerate(names[:50]))
        extra = f"\n...共 {len(names)} 个" if len(names) > 50 else ""
        yield event.plain_result(f"共发现 {len(convs)} 个会话：\n{shown}{extra}")

    @filter.command("douyin_scan")
    async def douyin_scan(self, event: AstrMessageEvent):
        """扫描会话并绑定会话 ID（数字 ID 监听回复必需）"""
        inst = self._running_instance()
        if inst is None:
            yield event.plain_result("没有运行中的抖音适配器，请先在平台适配器页启用。")
            return
        yield event.plain_result(
            "开始扫描（会清空 SDK 缓存并逐个点击会话），期间请勿操作浏览器窗口..."
        )
        results = await inst.client.scan_conversation_ids()
        if not results:
            yield event.plain_result("扫描完成，但未捕获到任何会话。")
            return
        lines = []
        for r in results:
            ids = r.get("real_conv_id") or "-"
            mark = "" if r.get("short_id") else "（未捕获）"
            lines.append(f"- {r['name']} → {ids}{mark}")
        text = "\n".join(lines[:50])
        extra = f"\n...共 {len(results)} 个" if len(results) > 50 else ""
        bound = sum(1 for r in results if r.get("short_id"))
        yield event.plain_result(
            f"扫描完成：成功绑定 {bound}/{len(results)} 个。\n{text}{extra}"
        )

    @staticmethod
    def _running_instance():
        from .core.adapter import DouyinPlatformAdapter

        for inst in DouyinPlatformAdapter.instances:
            if inst.client.context is not None:
                return inst
        return None

    async def terminate(self):
        """Plugin unload; adapters are cleaned up by their own terminate()."""
