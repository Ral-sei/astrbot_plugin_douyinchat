"""Douyin web IM client based on Playwright browser automation.

Receiving: polls the imapi protobuf endpoint from the logged-in chat page
context (cookies apply automatically). Sending: DOM automation on
https://www.douyin.com/chat (text via insertText + Enter, images via
clipboard paste + confirm modal).

All state is in-memory only. This plugin only transports messages;
history/dedup across restarts is left to AstrBot.
"""

import asyncio
import base64
import json
import mimetypes
import random
import time
from collections import OrderedDict
from pathlib import Path

from playwright.async_api import Locator, Page, async_playwright

from astrbot import logger
from astrbot.core.utils.astrbot_path import (
    get_astrbot_data_path,
    get_astrbot_temp_path,
)

CHAT_URL = "https://www.douyin.com/chat"
DOUYIN_HOME_URL = "https://www.douyin.com/"

# DOM selectors (class-substring matching to survive CSS hash suffixes).
SEL_CONV_LIST = 'div[class*="conversationConversationListwrapper"]'
SEL_CONV_ITEM = 'div[class*="conversationConversationItemwrapper"]'
SEL_INPUT_AREA = 'div[class*="messageEditorinputArea"][contenteditable="true"]'
# Alternative editor container seen in other Douyin web builds.
SEL_INPUT_AREA_ALT = (
    'div[class*="messageEditorimChatEditorContainer"] [contenteditable="true"]'
)
SEL_INPUT_AREA_FALLBACK = 'div[class*="messageMsgInput"] [contenteditable="true"]'
# Image paste pops up a confirm modal; click its send button (user-verified).
SEL_SEND_FILE_CONFIRM = "button.MsgInputSendFileModalbtnSure"
# "Save login info?" prompt shown after fresh login / first chat-page open;
# it blocks the UI until dismissed. Cancel is the safe choice.
SEL_TRUST_LOGIN_CANCEL = "button.trust-login-dialog-button-cancel"

MAX_SEEN_IDS = 20000
"""Upper bound of the in-memory message-id dedup set."""

MAX_SCAN_ITEMS = 30
"""Upper bound of conversations clicked during one id-scan round."""

MAX_RECENT_MSGS = 400
"""Upper bound of the in-memory recent-message cache for quote resolution."""


def decrypt_gcm(data: bytes, skey_hex: str) -> bytes | None:
    """Decrypt a Douyin IM media payload (AES-256-GCM).

    Layout per douyin-chat-export: key = skey hex (32 bytes),
    IV = first 12 bytes of the ciphertext, remainder = body + tag.

    Args:
        data: Raw downloaded ciphertext.
        skey_hex: Hex-encoded key from resource_url.skey / poster.skey.

    Returns:
        Plaintext media bytes, or None on any failure (missing/short key,
        auth failure from a wrong or expired pairing).
    """
    if not skey_hex or not data or len(data) <= 12:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = bytes.fromhex(skey_hex)
        if len(key) != 32:
            return None
        return AESGCM(key).decrypt(data[:12], data[12:], None)
    except Exception:
        return None


def sniff_media_ext(data: bytes) -> str | None:
    """Identify a downloaded payload by magic bytes.

    Returns:
        File extension ('.jpg'/'.png'/'.gif'/'.webp'/'.heic'/'.mp4'/'.mp3')
        or None when the bytes are not recognizable media (e.g. an error
        page returned with HTTP 200).
    """
    if not data or len(data) < 3:
        return None
    if data[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if data[:4] == b"GIF8":
        return ".gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"hevc"):
            return ".heic"
        return ".mp4"
    if data[:3] == b"ID3" or (data[0] == 0xFF and data[1] & 0xE0 == 0xE0):
        return ".mp3"
    return None


# Conversation match confidence levels (higher wins).
MATCH_EXACT = 3
MATCH_PREFIX = 2
MATCH_SUBSTRING = 1


def score_conversation_match(conv_key: str, nickname: str, fallback_text: str) -> int:
    """Score how well one conversation list item matches the target key.

    Matching runs against the pure nickname first and the whole rendered
    text only as a fallback. Levels: exact equality beats bidirectional
    prefix beats substring containment. The prefix check works in both
    directions so a key copied from a visually truncated (CSS ellipsis)
    display can still hit the full name; trailing ellipsis characters on
    the key are stripped before comparing.

    Args:
        conv_key: Configured conversation nickname (or mapped display name).
        nickname: Pure nickname extracted from the item title element.
        fallback_text: Whole item text used when the nickname is missing.

    Returns:
        One of MATCH_EXACT / MATCH_PREFIX / MATCH_SUBSTRING, or 0.
    """
    key = (conv_key or "").strip().rstrip("….")
    if not key or not key.strip("."):
        # Empty key, or nothing but ellipsis dots.
        return 0
    best = 0
    for candidate in ((nickname or "").strip(), (fallback_text or "").strip()):
        if not candidate:
            continue
        if candidate == key:
            return MATCH_EXACT
        # Bidirectional prefix; guard against degenerate tiny candidates.
        if min(len(key), len(candidate)) >= 2 and (
            candidate.startswith(key) or key.startswith(candidate)
        ):
            best = max(best, MATCH_PREFIX)
        elif key in candidate:
            best = max(best, MATCH_SUBSTRING)
    return best


# ── Minimal protobuf helpers (only what interception needs) ────────────


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return result, pos


def _iter_fields(buf: bytes) -> list[tuple[int, int, object]]:
    """Iterate top-level protobuf fields as (field_number, wire_type, value)."""
    fields = []
    pos = 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            val, pos = _read_varint(buf, pos)
            fields.append((fn, wt, val))
        elif wt == 2:
            length, pos = _read_varint(buf, pos)
            fields.append((fn, wt, bytes(buf[pos : pos + length])))
            pos += length
        elif wt == 1:
            pos += 8
        elif wt == 5:
            pos += 4
        else:
            break
    return fields


def _extract_bytes_field(buf: bytes, target: int) -> bytes | None:
    for fn, wt, val in _iter_fields(buf):
        if fn == target and wt == 2:
            return val
    return None


def _parse_short_id_request(body: bytes) -> tuple[str, str] | None:
    """Parse an intercepted get_by_conversation request body.

    Layout: outer field 8 wraps the query message; its field 301 contains
    field 1 (string, real conversation id) and field 3 (varint, short id).

    Returns:
        (short_id, real_conv_id), or None when not parseable.
    """
    outer = _extract_bytes_field(body, 8)
    if not outer:
        return None
    query = _extract_bytes_field(outer, 301)
    if not query:
        return None
    short_id = ""
    real_conv_id = ""
    for fn, wt, val in _iter_fields(query):
        if fn == 3 and wt == 0:
            short_id = str(val)
        elif fn == 1 and wt == 2:
            real_conv_id = val.decode("utf-8", errors="ignore")
    return (short_id, real_conv_id) if short_id else None


# ── Injected page-side JS ──────────────────────────────────────────────

# Protobuf encoder/decoder + imapi XHR bridge. Idempotent on re-injection.
_IMAPI_TOOLS_JS = r"""() => {
    if (window.__imApi) return;
    function encodeVarint(value) {
        const bytes = [];
        let v = typeof value === 'bigint' ? value : BigInt(value);
        do { let b = Number(v & 0x7Fn); v >>= 7n; if (v > 0n) b |= 0x80; bytes.push(b); } while (v > 0n);
        if (bytes.length === 0) bytes.push(0);
        return new Uint8Array(bytes);
    }
    function encodeTag(fn, wt) { return encodeVarint((fn << 3) | wt); }
    function encodeString(fn, s) { const e = new TextEncoder().encode(s); return concatArrays([encodeTag(fn, 2), encodeVarint(e.length), e]); }
    function encodeVarintField(fn, v) { return concatArrays([encodeTag(fn, 0), encodeVarint(v)]); }
    function encodeBytes(fn, d) { return concatArrays([encodeTag(fn, 2), encodeVarint(d.length), d]); }
    function concatArrays(arrs) { const t = arrs.reduce((s, a) => s + a.length, 0); const r = new Uint8Array(t); let o = 0; for (const a of arrs) { r.set(a, o); o += a.length; } return r; }
    function decodeVarint(buf, pos) { let result = 0, shift = 0; while (pos < buf.length) { const b = buf[pos++]; result |= (b & 0x7F) << shift; if ((b & 0x80) === 0) break; shift += 7; if (shift > 35) break; } return [result, pos]; }
    function decodeVarintBig(buf, pos) { let result = 0n, shift = 0n; while (pos < buf.length) { const b = buf[pos++]; result |= BigInt(b & 0x7F) << shift; if ((b & 0x80) === 0) break; shift += 7n; } return [result, pos]; }
    function extractField(buf, targetField) { let pos = 0; while (pos < buf.length) { let tag; [tag, pos] = decodeVarint(buf, pos); const fn = tag >> 3, wt = tag & 7; if (wt === 0) { let v; [v, pos] = decodeVarintBig(buf, pos); } else if (wt === 2) { let len; [len, pos] = decodeVarint(buf, pos); if (fn === targetField) return buf.slice(pos, pos + len); pos += len; } else if (wt === 1) pos += 8; else if (wt === 5) pos += 4; else break; } return null; }
    function buildRequest(convId, cursor, timestamp) {
        const inner = concatArrays([encodeString(1, convId), encodeVarintField(2, 1), encodeVarintField(3, cursor), encodeVarintField(4, 1), encodeVarintField(5, timestamp), encodeVarintField(6, 50)]);
        const queryMsg = encodeBytes(301, inner);
        return concatArrays([encodeVarintField(1, 301), encodeVarintField(2, 10027), encodeString(3, '0.1.6'), encodeString(4, ''), encodeVarintField(5, 3), encodeVarintField(6, 0), encodeString(7, 'fef1a80:p/lzg/store'), encodeBytes(8, queryMsg), encodeString(9, '0'), encodeString(11, 'douyin_pc'), encodeString(14, '360000'), encodeVarintField(18, 1), encodeString(21, 'douyin_pc')]);
    }
    function parseMessage(buf) {
        const r = {}; let pos = 0;
        while (pos < buf.length) { let tag; [tag, pos] = decodeVarint(buf, pos); const fn = tag >> 3, wt = tag & 7; if (fn === 0 || fn > 500) break;
            if (wt === 0) { let v; [v, pos] = decodeVarintBig(buf, pos); if (fn===3) r.server_id=v.toString(); else if (fn===4) r.created_at_us=v.toString(); else if (fn===7) r.sender_uid=v.toString(); else if (fn===6) r.type_code=Number(v); else if (fn===11) r.is_recalled=Number(v); }
            else if (wt === 2) { let len; [len, pos] = decodeVarint(buf, pos); const slice = buf.slice(pos, pos+len);
                if (fn===1) r.conv_id=new TextDecoder().decode(slice);
                else if (fn===8) { try { r.content_json=new TextDecoder().decode(slice); } catch {} }
                else if (fn===14) { try { r.sender_sec_uid=new TextDecoder().decode(slice); } catch {} }
                else if (fn===18) {
                    // Field 18: reference/reply message.
                    // Layout: f1=quoted message server_id,
                    //         f2=JSON {content, nickname, refmsg_sec_uid, refmsg_content}
                    try {
                        let rp = 0; const ref = {};
                        while (rp < slice.length) {
                            let t2; [t2, rp] = decodeVarint(slice, rp);
                            const f2n = t2 >> 3, f2wt = t2 & 7;
                            if (f2wt === 0) { let v; [v, rp] = decodeVarintBig(slice, rp); if (f2n===1) ref.server_id=v.toString(); }
                            else if (f2wt === 2) { let l2; [l2, rp] = decodeVarint(slice, rp); const s2 = new TextDecoder().decode(slice.slice(rp, rp+Number(l2))); rp += Number(l2);
                                if (f2n===1) ref.server_id=s2;
                                else if (f2n===2) { try { Object.assign(ref, JSON.parse(s2)); } catch {} } }
                            else if (f2wt === 1) rp += 8; else if (f2wt === 5) rp += 4; else break;
                        }
                        if (ref.server_id || ref.content || ref.nickname) r._ref_msg = ref;
                    } catch {}
                }
                pos += len; }
            else if (wt === 1) pos += 8; else if (wt === 5) pos += 4; else break; }
        return r;
    }
    function parseResponse(data) {
        const f6 = extractField(data, 6); if (!f6) return { msgs: [], hasMore: 0, nextTs: null };
        const f301 = extractField(f6, 301); if (!f301) return { msgs: [], hasMore: 0, nextTs: null };
        let pos = 0; const msgs = []; let nextTs = null, hasMore = 0;
        while (pos < f301.length) { let tag; [tag, pos] = decodeVarint(f301, pos); const fn = tag >> 3, wt = tag & 7;
            if (wt === 0) { let v; [v, pos] = decodeVarintBig(f301, pos); if (fn===2) nextTs=v.toString(); if (fn===3) hasMore=Number(v); }
            else if (wt === 2) { let len; [len, pos] = decodeVarint(f301, pos); if (fn===1) msgs.push(parseMessage(f301.slice(pos, pos+len))); pos += len; }
            else if (wt === 1) pos += 8; else if (wt === 5) pos += 4; else break; }
        return { msgs, nextTs, hasMore };
    }
    window.__imApi = {
        call: async function(convId, cursor, timestamp, retries = 3) {
            for (let attempt = 0; attempt < retries; attempt++) {
                try {
                    return await new Promise((resolve, reject) => {
                        const reqBody = buildRequest(convId, BigInt(cursor), BigInt(timestamp));
                        const xhr = new XMLHttpRequest(); xhr.open('POST', 'https://imapi.douyin.com/v1/message/get_by_conversation');
                        xhr.setRequestHeader('Content-Type', 'application/x-protobuf'); xhr.setRequestHeader('Accept', 'application/x-protobuf');
                        xhr.responseType = 'arraybuffer'; xhr.withCredentials = true; xhr.timeout = 30000;
                        xhr.onload = () => resolve({ status: xhr.status, data: new Uint8Array(xhr.response) });
                        xhr.onerror = () => reject(new Error('XHR failed')); xhr.ontimeout = () => reject(new Error('XHR timeout'));
                        xhr.send(reqBody.buffer);
                    });
                } catch (e) { if (attempt < retries - 1) await new Promise(r => setTimeout(r, (attempt+1)*3000)); else throw e; }
            }
        },
        parseResponse: parseResponse,
    };
}"""

_PASTE_TEXT_JS = """(text) => {
    let el = document.activeElement;
    const isEditable =
        el && el.getAttribute && el.getAttribute('contenteditable') === 'true';
    if (!isEditable) {
        // Focus was lost or landed elsewhere; target the editor explicitly.
        el =
            document.querySelector(
                'div[class*="messageEditorinputArea"][contenteditable="true"]',
            ) || document.querySelector('[contenteditable="true"]');
        if (el) el.focus();
    }
    if (!el || el.getAttribute('contenteditable') !== 'true') {
        return { ok: false, reason: 'editor not focused' };
    }
    const dt = new DataTransfer();
    dt.setData('text/plain', text);
    el.dispatchEvent(new ClipboardEvent('paste', {
        clipboardData: dt,
        bubbles: true,
        cancelable: true,
    }));
    return { ok: true };
}"""

_PASTE_IMAGE_JS = """(args) => {
    const bytes = Uint8Array.from(atob(args.base64), c => c.charCodeAt(0));
    const file = new File([bytes], 'image.png', { type: args.mime });
    const dt = new DataTransfer();
    dt.items.add(file);
    const el = document.activeElement ||
        document.querySelector('div[class*="messageEditorinputArea"]');
    if (!el) return;
    el.focus();
    el.dispatchEvent(new ClipboardEvent('paste', {
        clipboardData: dt,
        bubbles: true,
        cancelable: true,
    }));
}"""

_DOWNLOAD_MEDIA_JS = """async (url) => {
    try {
        const resp = await fetch(url, { credentials: 'include' });
        if (!resp.ok) return { status: resp.status, body: '' };
        const bytes = new Uint8Array(await resp.arrayBuffer());
        let binary = '';
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
        }
        return { status: resp.status, body: btoa(binary) };
    } catch (e) {
        return { status: -1, body: '', error: String(e) };
    }
}"""

_GET_SELF_UID_JS = """() => {
    const store = window.userInfoStore;
    const me = store && store.curLoginUserInfo;
    return me ? String(me.uid || '') : '';
}"""
_LAST_OWN_BUBBLE_JS = """() => {
    const boxes = document.querySelectorAll('div[class*="messageMessageBoxmessageBox"]');
    let last = null;
    boxes.forEach(box => {
        if (box.innerHTML.includes('messageMessageBoxhideAvatar')) {
            let el = box.querySelector(
                'div[class*="MessageBoxContentactiveClickArea"] > div:not([class])');
            if (!el) el = box.querySelector(
                'div[class*="MessageBoxContentactiveClickArea"]');
            if (!el) el = box.querySelector('div[class*="messageMessageBoxcontentBox"]');
            if (el) last = el.textContent.trim();
        }
    });
    return last;
}"""


_GET_SELF_NICKNAME_JS = """() => {
    const store = window.userInfoStore;
    const me = store && store.curLoginUserInfo;
    return me && me.nickname ? String(me.nickname) : '';
}"""

_GET_NICKNAME_JS = """(uid) => {
    const store = window.userInfoStore;
    if (!store || !store.usersInfoMap || !store.usersInfoMap.data_) return '';
    try {
        for (const wrap of store.usersInfoMap.data_.values()) {
            const u = wrap && (wrap.value_ !== undefined ? wrap.value_ : wrap);
            if (u && String(u.uid) === String(uid)) return u.nickname || '';
        }
    } catch {}
    return '';
}"""

# Extract display name from one conversation item element.
_CONV_META_JS = """(el) => {
    const titleEl = el.querySelector('div[class*="conversationConversationItemtitle"]');
    let nickname = '';
    if (titleEl) {
        const innerTitle =
            titleEl.querySelector('div[class*="conversationConversationItemtitle"]');
        nickname =
            innerTitle && innerTitle !== titleEl
                ? innerTitle.textContent.trim()
                : ((titleEl.firstChild && titleEl.firstChild.textContent) || '').trim();
    }
    return {
        name: titleEl ? titleEl.textContent.trim() : el.textContent.trim(),
        nickname: nickname,
    };
}"""


def _parse_cookies(raw: str) -> list[dict]:
    """Parse user-provided cookies into Playwright cookie dicts.

    Args:
        raw: Either a DevTools JSON array or a `key=value; key=value` string.

    Returns:
        List of cookie dicts scoped to .douyin.com.
    """
    raw = raw.strip()
    cookies: list[dict] = []
    if raw.startswith("["):
        try:
            for c in json.loads(raw):
                if isinstance(c, dict) and c.get("name") and c.get("value"):
                    cookies.append(
                        {
                            "name": c["name"],
                            "value": c["value"],
                            "domain": c.get("domain") or ".douyin.com",
                            "path": c.get("path") or "/",
                        }
                    )
        except json.JSONDecodeError:
            logger.warning("[douyin] cookies config is not valid JSON, ignored")
    elif raw:
        for pair in raw.split(";"):
            pair = pair.strip()
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            name = name.strip()
            if name:
                cookies.append(
                    {
                        "name": name,
                        "value": value.strip(),
                        "domain": ".douyin.com",
                        "path": "/",
                    }
                )
    return cookies


def parse_message_content(content_json: str) -> dict:
    """Parse Douyin message content JSON into normalized parts.

    Mirrors the aweType mapping maintained by douyin-chat-export.

    Args:
        content_json: Raw content JSON string of a message.

    Returns:
        Dict with keys:
            text: display/fallback text (may be empty).
            media_url: direct CDN URL when the message carries media.
            media_kind: one of 'image' | 'voice' | 'video_cover' | None.
            duration_ms: media duration in milliseconds when known.
    """
    result = {
        "text": "",
        "media_url": None,
        "media_urls": [],
        "media_kind": None,
        "duration_ms": 0,
    }
    try:
        cj = json.loads(content_json) if content_json else {}
    except json.JSONDecodeError:
        result["text"] = content_json[:500]
        return result
    if not isinstance(cj, dict):
        cj = {}

    awe_type = cj.get("aweType", -1)

    def all_strs(url_obj: object) -> list[str]:
        if isinstance(url_obj, dict):
            return [u for u in url_obj.get("url_list", []) if isinstance(u, str)]
        return []

    text = cj.get("text", "") or cj.get("description", "")

    if awe_type in (500, 501, 507, 508, 510, 514, 516):
        # Sticker / animated emoji.
        result["media_kind"] = "image"
        result["media_urls"] = all_strs(cj.get("url"))
        text = text or cj.get("display_name") or ""
    elif awe_type in (2702, 2703, 2704):
        # Image message. Payloads are AES-256-GCM encrypted; `resource_url.skey`
        # holds the hex key and ORIGIN urls carry the ciphertext (validated by
        # douyin-chat-export). Origin candidates go first.
        result["media_kind"] = "image"
        ru = cj.get("resource_url") or {}
        if isinstance(ru.get("skey"), str):
            result["media_skey"] = ru["skey"]
        for key in ("origin_url_list", "large_url_list", "medium_url_list"):
            # NOTE: resource_url values are direct URL lists (no url_list key).
            ul = ru.get(key, [])
            if isinstance(ul, list):
                result["media_urls"].extend(u for u in ul if isinstance(u, str))
    elif cj.get("resource_url") and cj.get("duration"):
        # Voice message.
        result["media_kind"] = "voice"
        result["media_urls"] = all_strs(cj.get("resource_url"))
        try:
            result["duration_ms"] = int(cj.get("duration") or 0)
        except (TypeError, ValueError):
            result["duration_ms"] = 0
    elif cj.get("video", {}).get("vid") and cj.get("poster", {}).get("origin_url_list"):
        # Video message: only the poster cover is directly accessible.
        result["media_kind"] = "video_cover"
        poster = cj.get("poster") or {}
        if isinstance(poster.get("skey"), str):
            result["media_skey"] = poster["skey"]
        result["media_urls"] = all_strs(poster.get("origin_url_list"))
        try:
            result["duration_ms"] = int(float(cj.get("duration") or 0))
        except (TypeError, ValueError):
            result["duration_ms"] = 0

    if not text:
        if awe_type >= 100000:
            text = cj.get("push_detail") or ""
        elif awe_type in (
            11054,
            11055,
            11063,
            11066,
            11067,
            11069,
            11070,
            11029,
            10500,
            10401,
        ):
            # Shared video/livestream/product/comment cards.
            comment = cj.get("comment", "")
            text = comment or cj.get("push_detail") or cj.get("aweme_title", "")
        elif awe_type in (800, 801, 803):
            text = cj.get("push_detail") or ""

    result["media_url"] = result["media_urls"][0] if result["media_urls"] else None
    result["text"] = text
    return result


class DouyinWebClient:
    """Playwright-powered Douyin web IM client.

    Responsibilities: browser lifecycle, login detection, imapi polling,
    short_id resolution, DOM message sending and authenticated media download.
    """

    def __init__(self, config: dict) -> None:
        profile_dir = str(config.get("browser_profile_dir") or "").strip()
        self.profile_dir = (
            Path(profile_dir)
            if profile_dir
            else Path(get_astrbot_data_path()) / "douyin_profile"
        )
        self.headless = bool(config.get("headless", False))
        self.cookies_raw = str(config.get("cookies") or "")
        self.self_uid_override = str(config.get("self_uid") or "").strip()
        # Explicit key=display-name overrides for conversation names; the
        # scan-derived binding can occasionally be wrong (SDK request
        # timing), so users may pin the correct display name in config.
        self._aliases: dict[str, str] = {}
        for item in config.get("conversation_aliases") or []:
            raw = str(item)
            if "=" in raw:
                k, _, v = raw.partition("=")
                if k.strip() and v.strip():
                    self._aliases[k.strip()] = v.strip()
        self.login_timeout = int(config.get("login_timeout") or 300)

        self.pw = None
        self.context = None
        self.page: Page | None = None
        self.self_uid = ""

        # In-memory state only (no persistence by design).
        self._short_ids: dict[str, dict[str, str]] = {}
        self._seen_ids: OrderedDict[str, None] = OrderedDict()
        self._baselined: set[str] = set()
        self._nicknames: dict[str, str] = {}
        self._self_nickname: str = ""
        # Recent parsed messages by server_id, used to resolve quoted
        # messages back to their original media/text content.
        self._recent_msgs: OrderedDict[str, dict] = OrderedDict()
        # Conversation id (numeric/short) -> DOM display name, filled by
        # scan_conversation_ids(). Numeric watched keys need this to be
        # clickable in the conversation list for sending.
        self._conv_names: dict[str, str] = {}
        # Display name -> {'short_id', 'real_conv_id'}, filled by scan.
        self._scan_results: dict[str, dict[str, str]] = {}
        # Serializes every UI-mutating page operation (clicking conversations,
        # typing, pasting). API polls are lock-free evaluate calls.
        self._page_lock = asyncio.Lock()

    async def start(self) -> None:
        """Launch the browser, restore/import login state and enter the chat page.

        Raises:
            RuntimeError: When no valid login state exists within login_timeout.
        """
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self.pw = await async_playwright().start()
        self.context = await self.pw.chromium.launch_persistent_context(
            str(self.profile_dir),
            headless=self.headless,
            viewport={"width": 1400, "height": 900},
            locale="zh-CN",
            args=["--disable-blink-features=AutomationControlled"],
        )
        await self.context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )
        page = (
            self.context.pages[0]
            if self.context.pages
            else await self.context.new_page()
        )

        cookies = _parse_cookies(self.cookies_raw)
        if cookies:
            await self.context.add_cookies(cookies)
            logger.info(f"[douyin] imported {len(cookies)} cookies")

        # Use wait_until="commit": heavy bot-detection JS can stall full loads,
        # the QR UI renders client-side and cookie polling handles the rest.
        try:
            await page.goto(DOUYIN_HOME_URL, wait_until="commit", timeout=60000)
        except Exception as e:
            logger.warning(f"[douyin] home page load slow, continuing: {e}")

        if not await self.wait_for_login():
            raise RuntimeError(
                "Douyin login required: scan the QR code in the browser window "
                "or fill the `cookies` config item."
            )

        await self.navigate_to_chat(page)
        self.page = page
        await self.get_self_uid()

    async def wait_for_login(self) -> bool:
        """Poll cookies until a non-empty sessionid appears or timeout hits."""
        deadline = time.monotonic() + self.login_timeout
        prompted = False
        while time.monotonic() < deadline:
            try:
                cookies = await self.context.cookies(DOUYIN_HOME_URL)
            except Exception:
                cookies = []
            # An empty-value sessionid may remain in the profile; value check
            # avoids a false positive that would break all API calls.
            if any(c.get("name") == "sessionid" and c.get("value") for c in cookies):
                logger.info("[douyin] login state detected")
                return True
            if not prompted and not self.headless:
                logger.info(
                    "[douyin] waiting for QR code login in the browser window..."
                )
                prompted = True
            await asyncio.sleep(2)
        return False

    async def navigate_to_chat(self, page: Page) -> None:
        """Navigate to the IM page and wait for the conversation list."""
        for attempt in range(3):
            await page.goto(CHAT_URL, wait_until="domcontentloaded")
            try:
                await page.wait_for_selector(SEL_CONV_ITEM, timeout=20000)
                await self._dismiss_popups(page)
                return
            except Exception as e:
                logger.warning(
                    f"[douyin] conversation list not ready (attempt {attempt + 1}/3): "
                    f"{str(e)[:80]}"
                )
                await asyncio.sleep(3)
        logger.warning("[douyin] conversation list still missing, continuing anyway")

    async def close(self) -> None:
        """Shut down the browser. Safe to call multiple times."""
        try:
            if self.context:
                await self.context.close()
        except Exception:
            pass
        try:
            if self.pw:
                await self.pw.stop()
        except Exception:
            pass
        self.context = None
        self.pw = None
        self.page = None

    def status(self) -> dict:
        """Return a snapshot for the status command."""
        return {
            "running": self.context is not None,
            "headless": self.headless,
            "profile_dir": str(self.profile_dir),
            "self_uid": self.self_uid or self.self_uid_override or "unknown",
            "resolved_conversations": {
                k: v["short_id"] for k, v in self._short_ids.items()
            },
            "bound_names": dict(self._conv_names),
        }

    # ── Conversation discovery ─────────────────────────────────────

    async def list_conversations(self) -> list[dict]:
        """Scroll the conversation list and collect all visible entries.

        The list uses virtual scrolling, so we scroll top→bottom reading
        items each round and dedup by display name (ported from
        douyin-chat-export's _load_all_conversations).

        Returns:
            List of {'name', 'nickname'} dicts, top-to-bottom order.
        """
        async with self._page_lock:
            page = await self.ensure_page()

            async def scroll_top() -> None:
                await page.evaluate(
                    """(sel) => {
                        const list = document.querySelector(sel);
                        if (!list) return;
                        const scrollable =
                            list.querySelector('[style*="overflow"]') || list;
                        scrollable.scrollTop = 0;
                    }""",
                    SEL_CONV_LIST,
                )

            await self._dismiss_popups(page)
            await scroll_top()
            await asyncio.sleep(0.6)

            seen: OrderedDict[str, dict] = OrderedDict()
            stable_rounds = 0
            for _ in range(120):
                convs = await page.evaluate(
                    """(sel) => Array.from(document.querySelectorAll(sel))
                        .map((el) => {
                            const titleEl = el.querySelector(
                                'div[class*="conversationConversationItemtitle"]');
                            let nickname = '';
                            if (titleEl) {
                                const innerTitle = titleEl.querySelector(
                                    'div[class*="conversationConversationItemtitle"]');
                                nickname =
                                    innerTitle && innerTitle !== titleEl
                                        ? innerTitle.textContent.trim()
                                        : ((titleEl.firstChild &&
                                            titleEl.firstChild.textContent) || '')
                                              .trim();
                            }
                            return {
                                name: titleEl
                                    ? titleEl.textContent.trim()
                                    : el.textContent.trim(),
                                nickname: nickname,
                            };
                        })""",
                    SEL_CONV_ITEM,
                )
                added = 0
                for c in convs:
                    key = c.get("nickname") or c.get("name")
                    c["name"] = (c.get("name") or "").replace("\xa0", " ").strip()
                    c["nickname"] = (
                        (c.get("nickname") or "").replace("\xa0", " ").strip()
                    )
                    if key and key not in seen:
                        seen[key] = c
                        added += 1

                reached_bottom = await page.evaluate(
                    """(sel) => {
                        const list = document.querySelector(sel);
                        if (!list) return true;
                        const scrollable =
                            list.querySelector('[style*="overflow"]') || list;
                        const before = scrollable.scrollTop;
                        scrollable.scrollTop += 400;
                        return scrollable.scrollTop === before;
                    }""",
                    SEL_CONV_LIST,
                )
                stable_rounds = stable_rounds + 1 if added == 0 else 0
                if reached_bottom and stable_rounds >= 2:
                    break
                await asyncio.sleep(0.5)

            await scroll_top()
            logger.info(f"[douyin] discovered {len(seen)} conversation(s)")
            return list(seen.values())

    async def scan_conversation_ids(
        self, max_items: int = MAX_SCAN_ITEMS
    ) -> list[dict]:
        """Click through conversations capturing SDK ids per display name.

        Builds the name↔id bindings that let numeric watched keys be
        selected in the DOM for sending. SDK caches are cleared first so
        every click fires a fresh get_by_conversation request.

        Args:
            max_items: Maximum number of list items to click through.

        Returns:
            List of {'name', 'short_id'?, 'real_conv_id'?} dicts; entries
            without ids could not be captured (kept for reporting).
        """
        results: list[dict] = []
        async with self._page_lock:
            page = await self.ensure_page()
            await self._clear_sdk_cache_and_reload()
            await self._dismiss_popups(page)
            items = page.locator(SEL_CONV_ITEM)
            count = min(await items.count(), max_items)
            logger.info(f"[douyin] scanning {count} conversation(s) for id binding")

            for i in range(count):
                item = items.nth(i)
                try:
                    meta = await item.evaluate(_CONV_META_JS)
                except Exception:
                    continue
                name = (meta.get("nickname") or meta.get("name") or "").strip()
                if not name:
                    continue

                captured: dict[str, str] = {}

                async def on_request(request, captured=captured) -> None:
                    if (
                        "get_by_conversation" not in request.url
                        or request.method != "POST"
                    ):
                        return
                    body = request.post_data_buffer
                    parsed = _parse_short_id_request(body) if body else None
                    if parsed:
                        captured["short_id"] = parsed[0]
                        captured["real_conv_id"] = parsed[1]

                page.on("request", on_request)
                try:
                    await item.scroll_into_view_if_needed(timeout=5000)
                    await item.click(timeout=5000)
                    for _ in range(50):
                        if captured:
                            break
                        await asyncio.sleep(0.1)
                except Exception as e:
                    logger.debug(f"[douyin] scan click failed on item {i}: {e}")
                finally:
                    page.remove_listener("request", on_request)

                entry = {"name": name, **captured}
                results.append(entry)
                if captured:
                    self._scan_results[name] = {
                        "short_id": captured["short_id"],
                        "real_conv_id": captured["real_conv_id"],
                    }
                    self._conv_names[captured["real_conv_id"]] = name
                    self._conv_names[captured["short_id"]] = name

        bound = sum(1 for r in results if "short_id" in r)
        logger.info(f"[douyin] scan finished: {bound}/{len(results)} bound")
        return results

    def _dom_name_for(self, conv_key: str) -> str:
        """Translate a watched key into its DOM-visible display name."""
        ids = self._short_ids.get(conv_key) or {}
        for probe in (ids.get("real_conv_id"), ids.get("short_id"), conv_key):
            if probe and probe in self._conv_names:
                return self._conv_names[probe]
        return conv_key

    def conversation_real_id(self, conv_key: str) -> str:
        """Best-known numeric conversation id for a watched key."""
        ids = self._short_ids.get(conv_key) or {}
        return str(ids.get("real_conv_id") or "")

    def conversation_display_name(self, conv_key: str) -> str:
        """Best-known display name for a watched key (falls back to the key).

        Explicit `conversation_aliases` entries take priority over the
        scan-derived binding.
        """
        if conv_key in self._aliases:
            return self._aliases[conv_key]
        return self._dom_name_for(conv_key)

    # ── Receiving ──────────────────────────────────────────────────

    async def poll_conversation(self, conv_key: str) -> list[dict]:
        """Fetch new messages of one conversation via the imapi endpoint.

        The first successful poll establishes a baseline: all existing
        messages are marked seen without being returned, so restarts never
        replay history into AstrBot.

        Args:
            conv_key: Conversation nickname or numeric conversation id
                as configured in watched_conversations.

        Returns:
            List of parsed message dicts (oldest first), each containing
            server_id, sender_uid, sender_sec_uid, created_at_us,
            content_json and _parsed. Empty when nothing new or unresolved.
        """
        ids = self._short_ids.get(conv_key)
        if not ids:
            async with self._page_lock:
                ids = self._short_ids.get(conv_key)
                if not ids:
                    ids = await self.resolve_short_id(conv_key)
            if not ids:
                return []

        raw = await self._api_fetch(ids["real_conv_id"], ids["short_id"], conv_key)
        if raw is None:
            # Response conv mismatch means the cached mapping is wrong;
            # drop it so the next round re-resolves.
            self._short_ids.pop(conv_key, None)
            self._baselined.discard(conv_key)
            return []

        fresh = []
        for m in raw:
            mid = m["server_id"]
            if not mid or mid in self._seen_ids:
                continue
            self._remember(mid)
            fresh.append(m)

        if conv_key not in self._baselined:
            self._baselined.add(conv_key)
            if fresh:
                logger.info(
                    f"[douyin] baseline established for {conv_key!r}: "
                    f"{len(fresh)} existing message(s) skipped"
                )
            return []
        return fresh

    async def resolve_short_id(self, conv_key: str) -> dict | None:
        """Resolve the imapi short_id / real conv id for a conversation.

        Numeric keys are used directly (group chats). Nicknames require one
        SDK request interception after clicking the conversation in the DOM.

        Must be called with self._page_lock held.

        Returns:
            {'short_id': ..., 'real_conv_id': ...}, or None on failure.
        """
        if conv_key.isdigit():
            ids = {"short_id": conv_key, "real_conv_id": conv_key}
            self._short_ids[conv_key] = ids
            return ids

        # Prefer a binding captured by scan_conversation_ids(): no clicking
        # needed and more reliable than substring matching.
        hit = self._scan_results.get(conv_key)
        if hit:
            self._short_ids[conv_key] = dict(hit)
            return dict(hit)

        for attempt in range(2):
            result = await self._intercept_short_id(conv_key)
            if result:
                self._short_ids[conv_key] = result
                logger.info(
                    f"[douyin] resolved {conv_key!r}: short_id={result['short_id']} "
                    f"real_conv_id={result['real_conv_id']}"
                )
                return result
            if attempt == 0:
                logger.info(
                    "[douyin] SDK request not captured (likely cached), "
                    "clearing cache and reloading..."
                )
                await self._clear_sdk_cache_and_reload()

        logger.error(
            f"[douyin] failed to resolve conversation id for {conv_key!r}; "
            "will retry next poll round"
        )
        return None

    async def _intercept_short_id(self, conv_key: str) -> dict | None:
        """Click the conversation once and parse the SDK get_by_conversation request."""
        page = await self.ensure_page()
        captured: dict[str, str] = {}

        async def on_request(request) -> None:
            if "get_by_conversation" not in request.url or request.method != "POST":
                return
            body = request.post_data_buffer
            if not body:
                return
            parsed = _parse_short_id_request(body)
            if parsed:
                captured["short_id"] = parsed[0]
                captured["real_conv_id"] = parsed[1]

        page.on("request", on_request)
        try:
            await self._select_conversation(page, conv_key)
            for _ in range(80):
                if captured:
                    break
                await asyncio.sleep(0.1)
        finally:
            page.remove_listener("request", on_request)
        return captured or None

    async def _api_fetch(
        self, real_conv_id: str, short_id: str, conv_key: str
    ) -> list[dict] | None:
        """Call the imapi endpoint through the page context.

        Returns:
            Sorted (old→new) message dicts; None signals an identity
            mismatch requiring re-resolution of the conversation mapping.
        """
        try:
            page = await self.ensure_page()
            await page.evaluate(_IMAPI_TOOLS_JS)
            result = await page.evaluate(
                """async (args) => {
                    if (!window.__imApi) return { error: 'api tools missing' };
                    const r = await window.__imApi.call(args[0], args[1], args[2]);
                    if (!r || r.status !== 200) {
                        return { error: 'HTTP ' + (r ? r.status : 'no response') };
                    }
                    return window.__imApi.parseResponse(r.data);
                }""",
                [real_conv_id, short_id, "9999999999999999"],
            )
        except Exception as e:
            logger.warning(f"[douyin] api fetch failed for {conv_key!r}: {e}")
            return []

        if result.get("error"):
            logger.warning(f"[douyin] api error for {conv_key!r}: {result['error']}")
            return []

        msgs = sorted(
            result.get("msgs") or [], key=lambda m: int(m.get("created_at_us", "0"))
        )

        resp_ids = {str(m.get("conv_id", "")) for m in msgs}
        if msgs and real_conv_id not in resp_ids:
            logger.warning(
                f"[douyin] conv id mismatch for {conv_key!r}: expected "
                f"{real_conv_id}, got {resp_ids}; dropping cached mapping"
            )
            return None

        parsed = []
        for m in msgs:
            if m.get("is_recalled"):
                continue
            content_json = m.get("content_json", "") or ""
            parsed.append(
                {
                    "server_id": str(m.get("server_id", "")),
                    "sender_uid": str(m.get("sender_uid", "")),
                    "sender_sec_uid": str(m.get("sender_sec_uid", "")),
                    "created_at_us": int(m.get("created_at_us", "0")),
                    "type_code": int(m.get("type_code", 0)),
                    "content_json": content_json,
                    # Reference/reply payload (field 18) when present:
                    # {server_id, content, nickname, refmsg_content, ...}
                    "ref_msg": m.get("_ref_msg") or None,
                    "_parsed": parse_message_content(content_json),
                }
            )
            self._remember_parsed(parsed[-1])
        return parsed

    def _remember_parsed(self, parsed: dict) -> None:
        """Keep a rolling index of recent parsed messages for quote lookup."""
        sid = parsed.get("server_id")
        if not sid:
            return
        info = parsed.get("_parsed") or {}
        self._recent_msgs[sid] = {
            "kind": info.get("media_kind"),
            "urls": list(info.get("media_urls") or []),
            "text": info.get("text", ""),
            "skey": info.get("media_skey"),
        }
        while len(self._recent_msgs) > MAX_RECENT_MSGS:
            self._recent_msgs.popitem(last=False)

    def get_cached_message(self, server_id: str | None) -> dict | None:
        """Return the cached parse info of a recent message by server_id."""
        if not server_id:
            return None
        hit = self._recent_msgs.get(str(server_id))
        if hit is not None:
            self._recent_msgs.move_to_end(str(server_id))
        return hit

    def _remember(self, msg_id: str) -> None:
        self._seen_ids[msg_id] = None
        while len(self._seen_ids) > MAX_SEEN_IDS:
            self._seen_ids.popitem(last=False)

    # ── Sending ────────────────────────────────────────────────────

    async def send_text(self, conv_key: str, text: str) -> bool:
        """Send a plain text message via DOM automation."""
        if not text.strip():
            return False
        async with self._page_lock:
            page = await self.ensure_page()
            if not await self._select_conversation(page, self._dom_name_for(conv_key)):
                return False
            input_loc = await self._locate_input(page)
            if input_loc is None:
                logger.error(
                    f"[douyin] input box not found, cannot send to {conv_key!r}"
                )
                return False
            for attempt in range(3):
                try:
                    await input_loc.click()
                    await asyncio.sleep(random.uniform(0.2, 0.5))
                    await page.keyboard.press("ControlOrMeta+a")
                    await page.keyboard.press("Backspace")
                    await asyncio.sleep(0.2)

                    # Synthetic clipboard paste: the editor accepts the
                    # payload and Enter transmits it. (Real-delivery issues
                    # were traced to running multiple browser instances for
                    # the same account, not to the input method.)
                    result = await page.evaluate(_PASTE_TEXT_JS, text)
                    if not (isinstance(result, dict) and result.get("ok")):
                        reason = (
                            result.get("reason") if isinstance(result, dict) else result
                        )
                        logger.warning(
                            f"[douyin] paste text failed on attempt "
                            f"{attempt + 1}/3: {reason}"
                        )
                        continue

                    prev_bubble = await self._get_last_own_bubble(page)
                    await page.keyboard.press("Enter")
                    await asyncio.sleep(random.uniform(1.2, 1.8))

                    # Gold standard: ask the server via imapi whether our own
                    # message really exists now (local bubble rendering alone
                    # is optimistic and may not mean delivery).
                    delivered = await self._verify_delivery_via_api(conv_key, text)

                    observed, matched = await self._wait_own_bubble(
                        page, prev_bubble, text
                    )
                    if delivered:
                        logger.info(
                            f"[douyin] text delivered (server-confirmed) "
                            f"to {conv_key!r}"
                        )
                    elif delivered is None and (matched or observed != prev_bubble):
                        logger.info(
                            f"[douyin] text sent (bubble updated) to {conv_key!r}"
                        )
                    else:
                        logger.warning(
                            f"[douyin] text NOT delivered to {conv_key!r} "
                            f"(server={'no' if delivered is False else 'unknown'}; "
                            f"bubble {'changed' if observed != prev_bubble else 'unchanged'}; "
                            f"last: {(observed or '<none>')[:50]!r})"
                        )
                    return True
                except Exception as e:
                    logger.warning(
                        f"[douyin] send text attempt {attempt + 1}/3 failed: {e}"
                    )
                    await asyncio.sleep(2)
            return False

    async def _verify_delivery_via_api(self, conv_key: str, text: str) -> bool | None:
        """Confirm a just-sent message exists server-side via the imapi API.

        Returns:
            True/False when the conversation mapping is known, None when we
            cannot check (unresolved short_id or API failure).
        """
        ids = self._short_ids.get(conv_key)
        if not ids:
            return None
        try:
            raw = await self._api_fetch(ids["real_conv_id"], ids["short_id"], conv_key)
        except Exception as e:
            logger.debug(f"[douyin] delivery check failed: {e}")
            return None
        if not raw:
            return None
        self_uid = await self.get_self_uid()
        needle = text[:20]
        for m in reversed(raw):
            if (
                self_uid
                and m.get("sender_uid") == self_uid
                and needle in (m.get("_parsed") or {}).get("text", "")
            ):
                return True
        return False

    async def send_image(self, conv_key: str, image_path: str) -> bool:
        """Send a local image file via clipboard paste + confirm modal.

        Pasting pops up a confirmation dialog whose send button must be
        clicked (button.MsgInputSendFileModalbtnSure).
        """
        path = Path(image_path)
        if not path.is_file():
            logger.error(f"[douyin] image file not found: {image_path}")
            return False
        mime = mimetypes.guess_type(str(path))[0] or "image/png"
        payload = {
            "base64": base64.b64encode(path.read_bytes()).decode(),
            "mime": mime,
        }
        async with self._page_lock:
            page = await self.ensure_page()
            if not await self._select_conversation(page, self._dom_name_for(conv_key)):
                return False
            input_loc = await self._locate_input(page)
            if input_loc is None:
                logger.error(
                    f"[douyin] input box not found, cannot send to {conv_key!r}"
                )
                return False
            try:
                await input_loc.click()
                await asyncio.sleep(random.uniform(0.2, 0.5))
                await page.evaluate(_PASTE_IMAGE_JS, payload)
                if not await self._confirm_send_file_modal(page):
                    return False
                await asyncio.sleep(random.uniform(1.2, 1.8))
                logger.info(f"[douyin] image sent to {conv_key!r}")
                return True
            except Exception as e:
                logger.error(f"[douyin] send image to {conv_key!r} failed: {e}")
                return False

    async def _confirm_send_file_modal(self, page: Page) -> bool:
        """Wait for the image confirm modal and click its send button."""
        btn = page.locator(SEL_SEND_FILE_CONFIRM).first
        try:
            await btn.wait_for(state="visible", timeout=10000)
        except Exception:
            # Fallback: role-based lookup inside the popped-up modal.
            btn = page.get_by_role("button", name="发送").first
            try:
                await btn.wait_for(state="visible", timeout=3000)
            except Exception:
                logger.error(
                    "[douyin] image confirm modal did not appear; aborting send"
                )
                return False
        try:
            await btn.click(timeout=5000)
            return True
        except Exception as e:
            logger.error(f"[douyin] failed to click modal send button: {e}")
            return False

    # ── Media download ─────────────────────────────────────────────

    async def download_media(
        self, url: str, filename: str, skey_hex: str | None = None
    ) -> Path | None:
        """Download a media URL: direct HTTP first, in-page fetch as fallback.

        Image-message payloads are AES-256-GCM encrypted; pass `skey_hex`
        (resource_url.skey) to decrypt them before the magic-byte check.

        Signed CDN URLs need no cookies (validated by douyin-chat-export),
        while Douyin's CSP may block cross-origin fetches from the chat
        page entirely — so the direct channel runs first and the page
        fetch only serves as a fallback.

        Args:
            url: Direct CDN URL of the media resource.
            filename: Target file name under AstrBot temp dir.
            skey_hex: Optional AES-256-GCM hex key for encrypted payloads.

        Returns:
            Local file path, or None when the download fails (callers fall
            back to placeholder text).
        """
        # 1) Direct HTTP with browser-like headers (Referer included).
        data = await self._direct_download(url, minimal=False)

        # 2) Retry with a minimal UA-only header set: some CDN nodes reject
        #    requests carrying a Referer they do not expect.
        if data is None:
            data = await self._direct_download(url, minimal=True)

        # 3) In-page fetch fallback (cookies included). Note: Douyin's CSP
        #    may block cross-origin fetches entirely (TypeError: Failed to
        #    fetch), which is why direct attempts come first.
        if data is None:
            try:
                async with self._page_lock:
                    page = await self.ensure_page()
                    result = await page.evaluate(_DOWNLOAD_MEDIA_JS, url)
                    data_b64 = (
                        result.get("body", "") if isinstance(result, dict) else ""
                    )
                    if data_b64:
                        data = base64.b64decode(data_b64)
                    else:
                        status = (
                            result.get("status") if isinstance(result, dict) else None
                        )
                        js_error = (
                            result.get("error") if isinstance(result, dict) else None
                        )
                        detail = f", error: {js_error}" if js_error else ""
                        logger.warning(
                            f"[douyin] page fetch failed for {filename} "
                            f"(http status: {status}{detail})"
                        )
            except Exception as e:
                logger.warning(f"[douyin] page fetch errored for {filename}: {e}")

        if data is None:
            logger.warning(f"[douyin] media download failed entirely: {filename}")
            return None

        if skey_hex:
            plain = decrypt_gcm(data, skey_hex)
            if plain is None:
                logger.warning(
                    f"[douyin] AES-GCM decryption failed for {filename} "
                    "(wrong/expired skey); trying next candidate"
                )
                return None
            data = plain

        ext = sniff_media_ext(data)
        if ext is None:
            # HTTP 200 with non-media body: blocked/expired/expired-signature
            # responses look like this. Log enough to diagnose remotely.
            logger.warning(
                f"[douyin] downloaded payload of {len(data)}B is not media "
                f"for {filename}: head={data[:60]!r}"
            )
            return None
        return self._save_media(data, filename, ext)

    @staticmethod
    def _save_media(data: bytes, filename: str, ext: str | None = None) -> Path:
        """Persist media under the AstrBot temp dir.

        The sniffed extension overrides the caller-provided one so the file
        is named after its actual format.
        """
        dest_dir = Path(get_astrbot_temp_path()) / "douyin_chat_media"
        dest_dir.mkdir(parents=True, exist_ok=True)
        name = Path(filename).stem + (ext or Path(filename).suffix or ".bin")
        dest = dest_dir / name
        dest.write_bytes(data)
        return dest

    @staticmethod
    async def _direct_download(url: str, minimal: bool = False) -> bytes | None:
        """Fetch a CDN URL directly without cookies.

        Args:
            url: Media URL.
            minimal: When True send only a plain Mozilla User-Agent
                (matching douyin-chat-export's proven voice downloader);
                otherwise full browser-like headers including Referer.
        """
        import aiohttp

        headers = {"User-Agent": "Mozilla/5.0"}
        if not minimal:
            headers.update(
                {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/125.0.0.0 Safari/537.36"
                    ),
                    "Referer": "https://www.douyin.com/",
                }
            )
        label = "minimal" if minimal else "full"
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status != 200:
                        logger.warning(
                            f"[douyin] direct({label}) http {resp.status} "
                            f"for {url[:80]}"
                        )
                        return None
                    return await resp.read()
        except Exception as e:
            logger.warning(f"[douyin] direct({label}) download failed: {e}")
            return None

    # ── Page helpers ───────────────────────────────────────────────

    async def ensure_page(self) -> Page:
        """Return a live page positioned on the chat URL.

        Callers performing UI mutations should hold self._page_lock.

        Raises:
            RuntimeError: When the browser has already been closed (e.g.
                during adapter termination while an event is still in
                flight); surfaced as a clear error instead of a cryptic
                NoneType attribute failure.
        """
        if self.context is None:
            raise RuntimeError("douyin client is closed")
        if self.page is None or self.page.is_closed():
            pages = self.context.pages
            self.page = pages[0] if pages else await self.context.new_page()
        url = self.page.url or ""
        if "douyin.com/chat" not in url:
            await self.page.goto(CHAT_URL, wait_until="domcontentloaded", timeout=30000)
            try:
                await self.page.wait_for_selector(SEL_CONV_ITEM, timeout=10000)
            except Exception:
                logger.warning(
                    "[douyin] conversation list not visible after navigation"
                )
        return self.page

    async def _dismiss_popups(self, page: Page) -> None:
        """Close blocking prompts like the 'save login info' dialog.

        Must be called with self._page_lock held (all callers are).
        """
        try:
            btn = page.locator(SEL_TRUST_LOGIN_CANCEL).first
            if await btn.count() and await btn.is_visible():
                await btn.click(timeout=3000)
                logger.info("[douyin] dismissed trust-login dialog")
                await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"[douyin] dismiss popups: {e}")

    async def _select_conversation(self, page: Page, conv_key: str) -> bool:
        """Click the conversation item that best matches conv_key.

        All visible items are extracted with one evaluate() call as pure
        nickname pairs; scoring prefers exact equality, then bidirectional
        prefix (tolerates keys copied from truncated displays), then
        substring. No match aborts the send to avoid misdelivery.
        """
        metas = await page.evaluate(
            """(sel) => Array.from(document.querySelectorAll(sel)).map((el) => {
                const titleEl = el.querySelector(
                    'div[class*="conversationConversationItemtitle"]');
                let nickname = '';
                if (titleEl) {
                    const innerTitle = titleEl.querySelector(
                        'div[class*="conversationConversationItemtitle"]');
                    nickname =
                        innerTitle && innerTitle !== titleEl
                            ? innerTitle.textContent.trim()
                            : ((titleEl.firstChild && titleEl.firstChild.textContent) ||
                                  '').trim();
                }
                return { nickname, text: el.textContent.trim() };
            })""",
            SEL_CONV_ITEM,
        )
        await self._dismiss_popups(page)
        best_index = -1
        best_score = 0
        for i, meta in enumerate(metas or []):
            score = score_conversation_match(
                conv_key, meta.get("nickname", ""), meta.get("text", "")
            )
            if score > best_score:
                best_index = i
                best_score = score
            if score == MATCH_EXACT:
                break
        if best_index < 0:
            logger.warning(
                f"[douyin] conversation {conv_key!r} not found in list "
                f"({len(metas or [])} items); aborting to avoid misdelivery"
            )
            return False
        item = page.locator(SEL_CONV_ITEM).nth(best_index)
        await item.scroll_into_view_if_needed(timeout=5000)
        await item.click(timeout=5000)
        await asyncio.sleep(random.uniform(1.0, 1.8))
        return True

    @staticmethod
    async def _locate_input(page: Page) -> Locator | None:
        for sel in (
            SEL_INPUT_AREA,
            SEL_INPUT_AREA_ALT,
            SEL_INPUT_AREA_FALLBACK,
            '[contenteditable="true"]',
        ):
            loc = page.locator(sel).first
            try:
                if await loc.count() and await loc.is_visible():
                    return loc
            except Exception:
                continue
        return None

    async def get_self_uid(self) -> str:
        """Return the logged-in user's uid (config override takes priority)."""
        if self.self_uid_override:
            return self.self_uid_override
        if self.self_uid:
            return self.self_uid
        try:
            page = await self.ensure_page()
            uid = await page.evaluate(_GET_SELF_UID_JS)
            self.self_uid = str(uid or "")
        except Exception as e:
            logger.warning(f"[douyin] failed to read self uid: {e}")
        if not self.self_uid:
            logger.warning(
                "[douyin] self uid unknown; own messages may be echoed back. "
                "Fill the `self_uid` config item to override."
            )
        return self.self_uid

    async def get_nickname(self, uid: str) -> str:
        """Best-effort nickname lookup from the page's user info cache."""
        if not uid:
            return ""
        if uid in self._nicknames:
            return self._nicknames[uid]
        try:
            page = await self.ensure_page()
            name = await page.evaluate(_GET_NICKNAME_JS, uid)
        except Exception:
            name = ""
        self._nicknames[uid] = name or uid
        return self._nicknames[uid]

    async def get_self_nickname(self) -> str:
        """Return the logged-in user's nickname (used to detect @-mentions)."""
        if self._self_nickname:
            return self._self_nickname
        try:
            page = await self.ensure_page()
            name = await page.evaluate(_GET_SELF_NICKNAME_JS)
            self._self_nickname = str(name or "")
        except Exception as e:
            logger.debug(f"[douyin] failed to read self nickname: {e}")
        return self._self_nickname

    async def _get_last_own_bubble(self, page: Page) -> str | None:
        """Return the rendered text of the latest bubble sent by this account.

        None means no own bubble is currently visible.
        """
        try:
            return await page.evaluate(_LAST_OWN_BUBBLE_JS)
        except Exception as e:
            logger.debug(f"[douyin] read last own bubble failed: {e}")
            return None

    async def _wait_own_bubble(
        self, page: Page, prev: str | None, text: str
    ) -> tuple[str | None, bool]:
        """Wait for the own bubble list to update after pressing Enter.

        Returns:
            (observed_text, matched) where matched is True when the latest
            bubble contains the beginning of the sent text.
        """
        for _ in range(3):
            observed = await self._get_last_own_bubble(page)
            if observed and observed != prev:
                return observed, bool(text[:20]) and text[:20] in observed
            await asyncio.sleep(0.7)
        return await self._get_last_own_bubble(page), False

    async def _clear_sdk_cache_and_reload(self) -> None:
        """Force the IM SDK to resend get_by_conversation on next visit."""
        try:
            page = await self.ensure_page()
            await page.evaluate(
                """() => {
                    try { localStorage.clear(); } catch {}
                    try { sessionStorage.clear(); } catch {}
                    try { indexedDB.databases().then(dbs =>
                        dbs.forEach(db => indexedDB.deleteDatabase(db.name))); } catch {}
                }"""
            )
            await page.goto(CHAT_URL, wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(3)
        except Exception as e:
            logger.warning(f"[douyin] failed to clear SDK cache: {e}")
