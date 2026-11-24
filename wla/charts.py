"""报告图表（matplotlib 可选）。"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from io import BytesIO
from typing import Iterable, Optional, Sequence

try:  # pragma: no cover - 取决于环境
    import matplotlib

    matplotlib.use("Agg")
    from matplotlib import font_manager
    from matplotlib import pyplot as plt

    MATPLOTLIB_AVAILABLE = True
except ImportError:  # pragma: no cover
    MATPLOTLIB_AVAILABLE = False
    plt = None


_CJK_FONTS = (
    "Microsoft YaHei",
    "SimHei",
    "Noto Sans CJK SC",
    "Source Han Sans SC",
    "WenQuanYi Zen Hei",
    "Arial Unicode MS",
)


def setup() -> bool:
    if not MATPLOTLIB_AVAILABLE:
        return False
    try:
        installed = {font.name for font in font_manager.fontManager.ttflist}
        for candidate in _CJK_FONTS:
            if candidate in installed:
                plt.rcParams["font.sans-serif"] = [candidate, "DejaVu Sans"]
                break
        plt.rcParams["axes.unicode_minus"] = False
        return True
    except Exception:  # noqa: BLE001
        return False


def _hide_spines(ax) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def _finish(fig) -> BytesIO:
    buffer = BytesIO()
    fig.tight_layout()
    fig.savefig(buffer, format="png", dpi=160, bbox_inches="tight")
    plt.close(fig)
    buffer.seek(0)
    return buffer


def severity_bar(counts: dict[str, int]) -> Optional[BytesIO]:
    if not setup():
        return None
    order = ["严重", "高危", "中危", "低危", "信息"]
    colors = ["#DC2626", "#EA580C", "#D97706", "#3B82F6", "#9CA3AF"]
    values = [counts.get(label, 0) for label in order]
    if not any(values):
        return None
    fig, ax = plt.subplots(figsize=(6.4, 2.8))
    bars = ax.bar(order, values, color=colors)
    for bar, value in zip(bars, values):
        if value:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                str(value),
                ha="center",
                va="bottom",
                fontsize=9,
            )
    ax.set_title("发现数量按严重级别分布")
    ax.set_ylabel("数量")
    _hide_spines(ax)
    return _finish(fig)


def top_barh(
    items: Sequence[tuple[str, int]],
    title: str,
    color: str = "#EA580C",
    limit: int = 10,
) -> Optional[BytesIO]:
    if not setup() or not items:
        return None
    data = list(items[:limit])[::-1]
    labels = [str(label)[:32] for label, _ in data]
    values = [value for _, value in data]
    fig, ax = plt.subplots(figsize=(6.8, max(2.6, 0.32 * len(data) + 1.2)))
    ax.barh(labels, values, color=color)
    for index, value in enumerate(values):
        ax.text(value, index, f" {value}", va="center", fontsize=8)
    ax.set_title(title)
    ax.set_xlabel("次数")
    _hide_spines(ax)
    return _finish(fig)


def hourly_line(
    times: Iterable[Optional[dt.datetime]],
    title: str = "登录失败时间分布",
) -> Optional[BytesIO]:
    if not setup():
        return None
    buckets = Counter()
    for value in times:
        if not value:
            continue
        try:
            local = value.astimezone()
        except (ValueError, OSError):
            local = value
        buckets[local.replace(minute=0, second=0, microsecond=0)] += 1
    if len(buckets) < 2:
        return None
    ordered = sorted(buckets.items())
    labels = [stamp.strftime("%m-%d %H:%M") for stamp, _ in ordered]
    values = [count for _, count in ordered]
    fig, ax = plt.subplots(figsize=(7.0, 2.8))
    ax.plot(labels, values, color="#DC2626", marker="o", markersize=3, linewidth=1.4)
    ax.fill_between(range(len(values)), values, color="#DC2626", alpha=0.12)
    step = max(1, len(labels) // 8)
    ax.set_xticks(range(0, len(labels), step))
    ax.set_xticklabels(
        [labels[i] for i in range(0, len(labels), step)],
        rotation=30,
        ha="right",
        fontsize=8,
    )
    ax.set_title(title)
    ax.set_ylabel("次数")
    _hide_spines(ax)
    return _finish(fig)
