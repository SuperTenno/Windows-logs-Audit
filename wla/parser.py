"""Windows 事件 XML 解析。

兼容多种来源：
* ``wevtutil qe <log> /f:RenderedXml`` 的连续 ``<Event>`` 输出；
* ``Get-WinEvent | ForEach-Object { $_.ToXml() }`` 的多行输出；
* 事件查看器导出的 ``<Events><Event>...</Event></Events>`` 文件；
* 带 BOM、XML 声明、命名空间前缀或少量非法字符的 XML。

解析器对单条事件失败保持容错：坏掉的事件计入 ``stats['errors']``，
不会影响其余事件的解析（原工具在一条坏 XML 上会直接崩溃）。
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, Optional
from xml.etree import ElementTree as ET

from . import knowledge
from .models import Event

_EVENT_RE = re.compile(r"<Event\b[^>]*>.*?</Event>", re.S | re.I)
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_BARE_AMP = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
_TIME_RE = re.compile(
    r"(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[T ]"
    r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:\.(?P<frac>\d{1,9}))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?"
)


def decode_text(data: Any) -> str:
    """把字节流解码为文本，兼容 UTF-8、UTF-16 与 GBK 系编码。"""
    if isinstance(data, str):
        return data.lstrip("\ufeff")
    if data is None:
        return ""
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    raw = bytes(data)
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        try:
            return raw.decode("utf-16").lstrip("\ufeff")
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "big5"):
        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        if "\x00" in text:
            continue
        return text.lstrip("\ufeff")
    return raw.decode("utf-8", errors="replace")


def parse_time(value: Any) -> Optional[dt.datetime]:
    """解析 Windows 事件时间戳，统一返回带时区的 UTC 时间。

    Python 3.11 之前的 ``datetime.fromisoformat`` 不支持 7 位小数秒，
    因此这里手动解析，避免整份日志时间变为 ``None``。
    """
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    match = _TIME_RE.search(text)
    if not match:
        return None
    fraction = (match.group("frac") or "0")[:6].ljust(6, "0")
    zone = match.group("tz")
    if not zone:
        offset_minutes = 0
    elif zone.upper() == "Z":
        offset_minutes = 0
    else:
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        try:
            offset_minutes = sign * (int(digits[:2]) * 60 + int(digits[2:4]))
        except (ValueError, IndexError):
            offset_minutes = 0
    try:
        return dt.datetime(
            int(match.group("y")),
            int(match.group("mo")),
            int(match.group("d")),
            int(match.group("h")),
            int(match.group("mi")),
            int(match.group("s")),
            int(fraction),
            tzinfo=dt.timezone(dt.timedelta(minutes=offset_minutes)),
        )
    except ValueError:
        return None


def _local(tag: str) -> str:
    """去掉命名空间，返回标签本地名。"""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child(node: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    if node is None:
        return None
    for child in node:
        if _local(child.tag) == name:
            return child
    return None


def _children(node: Optional[ET.Element], name: str) -> list[ET.Element]:
    if node is None:
        return []
    return [child for child in node if _local(child.tag) == name]


def _text(node: Optional[ET.Element], name: str = "") -> str:
    target = node if not name else _child(node, name)
    if target is None:
        return ""
    return (target.text or "").strip()


def _int(value: Any) -> Optional[int]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def _sanitize_xml(text: str) -> str:
    """修复常见 XML 非法内容后重试解析。"""
    cleaned = _ILLEGAL_XML.sub("", text)
    return _BARE_AMP.sub("&amp;", cleaned)


def _flatten_user_data(root: Optional[ET.Element]) -> dict[str, str]:
    """UserData 里的字段散落在多层嵌套中（如 RDP 会话事件的 EventXML）。"""
    data: dict[str, str] = {}
    if root is None:
        return data
    for node in root.iter():
        if node is root:
            continue
        if len(node):
            continue
        tag = _local(node.tag)
        text = (node.text or "").strip()
        if text and tag not in data:
            data[tag] = text
    return data


def _collect_event_data(root: Optional[ET.Element]) -> dict[str, str]:
    data: dict[str, str] = {}
    if root is None:
        return data
    position = 0
    for node in root.iter():
        if _local(node.tag) != "Data":
            continue
        name = node.get("Name") or f"param{position + 1}"
        position += 1
        if name in data:
            continue
        data[name] = (node.text or "").strip()
    return data


def parse_event_element(
    element: ET.Element, default_log: str = ""
) -> Optional[Event]:
    """把单个 ``<Event>`` 元素转换为 :class:`Event`。"""
    system = _child(element, "System")
    event_id_node = _child(system, "EventID") if system is not None else None
    event_id = _int(_text(event_id_node)) if event_id_node is not None else None
    if event_id is None:
        return None

    channel = _text(system, "Channel")
    log = knowledge.channel_key(channel) or default_log or "other"

    time_node = _child(system, "TimeCreated")
    timestamp = time_node.get("SystemTime") if time_node is not None else None

    provider_node = _child(system, "Provider")
    computer = _text(system, "Computer")
    record_id = _int(_text(system, "EventRecordID"))
    level = _int(_text(system, "Level"))

    data = _collect_event_data(_child(element, "EventData"))
    user_data = _flatten_user_data(_child(element, "UserData"))
    for key, value in user_data.items():
        data.setdefault(key, value)

    rendering = _child(element, "RenderingInfo")
    message = _text(rendering, "Message")

    # RenderedXml 的部分事件把字段放在 <Data> 之外的 <Binary> 中，忽略即可。

    return Event(
        log=log,
        event_id=event_id,
        time=parse_time(timestamp),
        data=data,
        record_id=record_id,
        provider=(provider_node.get("Name") or "") if provider_node is not None else "",
        computer=computer,
        level=level,
        channel=channel,
        message=message,
    )


def parse_events(
    text: str,
    default_log: str = "",
    stats: Optional[dict] = None,
    max_events: int = 0,
) -> list[Event]:
    """从任意含 ``<Event>`` 的文本中解析事件列表。

    :param default_log: 事件缺少 Channel 时使用的日志 key。
    :param stats: 可选统计字典，会写入 ``parsed`` / ``errors``。
    :param max_events: 大于 0 时最多解析该数量的事件。
    """
    if stats is None:
        stats = {}
    stats.setdefault("parsed", 0)
    stats.setdefault("errors", 0)

    if not text:
        return []

    events: list[Event] = []
    for match in _EVENT_RE.finditer(text):
        if max_events and len(events) >= max_events:
            break
        raw = match.group(0)
        element = None
        try:
            element = ET.fromstring(raw)
        except ET.ParseError:
            try:
                element = ET.fromstring(_sanitize_xml(raw))
            except ET.ParseError:
                stats["errors"] += 1
                continue
        event = parse_event_element(element, default_log)
        if event is None:
            stats["errors"] += 1
            continue
        events.append(event)
        stats["parsed"] += 1
    return events


def parse_event_file(
    path: str, default_log: str = "", stats: Optional[dict] = None
) -> list[Event]:
    """读取文件并解析（自动识别编码）。"""
    with open(path, "rb") as handle:
        raw = handle.read()
    return parse_events(decode_text(raw), default_log, stats)
