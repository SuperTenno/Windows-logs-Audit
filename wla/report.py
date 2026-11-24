"""报告渲染：Word（主）、Markdown、JSON、HTML。"""

from __future__ import annotations

import base64
import datetime as dt
import html
import json
from pathlib import Path
from typing import Iterable, Optional, Sequence

from . import charts
from . import __version__
from .knowledge import LOG_LABELS
from .models import AuditReport, Finding, Severity, TACTIC_ORDER, fmt_time

try:  # pragma: no cover - 取决于环境
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Inches, Pt, RGBColor

    DOCX_AVAILABLE = True
except ImportError:  # pragma: no cover
    DOCX_AVAILABLE = False


_FONT_NAME = "微软雅黑"
_HEADING_COLOR = RGBColor(0x0B, 0x3D, 0x6B) if DOCX_AVAILABLE else None
_SUB_COLOR = RGBColor(0x1F, 0x5C, 0x99) if DOCX_AVAILABLE else None
_MUTED = RGBColor(0x60, 0x60, 0x60) if DOCX_AVAILABLE else None

_SEVERITY_RGB = {
    Severity.CRITICAL: RGBColor(0xC0, 0x1B, 0x1B),
    Severity.HIGH: RGBColor(0xD9, 0x48, 0x0D),
    Severity.MEDIUM: RGBColor(0xB4, 0x6A, 0x00),
    Severity.LOW: RGBColor(0x1D, 0x4E, 0xD8),
    Severity.INFO: RGBColor(0x55, 0x5F, 0x6B),
}


def _safe(value) -> str:
    return str(value) if value is not None else ""


# ---------------------------------------------------------------------------
# Word
# ---------------------------------------------------------------------------
class DocxReport:
    def __init__(self, report: AuditReport, with_charts: bool = True):
        if not DOCX_AVAILABLE:
            raise RuntimeError("未安装 python-docx，无法生成 Word 报告（pip install python-docx）")
        self.report = report
        self.with_charts = with_charts
        self.doc = Document()
        self._section_no = 0
        self._sub_no = 0
        self._setup()

    # ---- 基础样式 ----
    def _setup(self) -> None:
        section = self.doc.sections[0]
        section.page_width = Cm(21.0)
        section.page_height = Cm(29.7)
        section.left_margin = Cm(2.2)
        section.right_margin = Cm(2.2)
        section.top_margin = Cm(2.2)
        section.bottom_margin = Cm(2.0)

        normal = self.doc.styles["Normal"]
        normal.font.name = _FONT_NAME
        normal.font.size = Pt(10.5)
        rpr = normal.element.get_or_add_rPr()
        fonts = rpr.get_or_add_rFonts()
        fonts.set(qn("w:eastAsia"), _FONT_NAME)
        fonts.set(qn("w:ascii"), _FONT_NAME)
        fonts.set(qn("w:hAnsi"), _FONT_NAME)

        for level, size in ((1, 16), (2, 13), (3, 11.5)):
            style = self.doc.styles[f"Heading {level}"]
            style.font.name = _FONT_NAME
            style.font.size = Pt(size)
            style.font.color.rgb = _HEADING_COLOR if level == 1 else _SUB_COLOR
            style.font.bold = True
            style.element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), _FONT_NAME)

        self._add_footer(section)

    def _add_footer(self, section) -> None:
        footer = section.footer
        paragraph = footer.paragraphs[0]
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = paragraph.add_run(f"Windows 日志安全审计报告 · {self.report.target or '本地主机'}    第 ")
        run.font.size = Pt(8)
        run.font.color.rgb = _MUTED
        self._add_field(paragraph, "PAGE", "1", size=8)
        run = paragraph.add_run(" 页 / 共 ")
        run.font.size = Pt(8)
        run.font.color.rgb = _MUTED
        self._add_field(paragraph, "NUMPAGES", "1", size=8)
        run = paragraph.add_run(" 页")
        run.font.size = Pt(8)
        run.font.color.rgb = _MUTED

    def _add_field(self, paragraph, instruction: str, placeholder: str = "", size=None) -> None:
        run = paragraph.add_run()
        begin = OxmlElement("w:fldChar")
        begin.set(qn("w:fldCharType"), "begin")
        run._r.append(begin)

        run = paragraph.add_run()
        instr = OxmlElement("w:instrText")
        instr.set(qn("xml:space"), "preserve")
        instr.text = f" {instruction} "
        run._r.append(instr)

        run = paragraph.add_run()
        separate = OxmlElement("w:fldChar")
        separate.set(qn("w:fldCharType"), "separate")
        run._r.append(separate)

        run = paragraph.add_run(placeholder)
        if size:
            run.font.size = Pt(size)
            run.font.color.rgb = _MUTED

        run = paragraph.add_run()
        end = OxmlElement("w:fldChar")
        end.set(qn("w:fldCharType"), "end")
        run._r.append(end)

    # ---- 文本 / 表格 ----
    def _heading(self, text: str, level: int = 1) -> None:
        if level == 1:
            self._section_no += 1
            self._sub_no = 0
            text = f"{self._section_no}. {text}"
        elif level == 2:
            self._sub_no += 1
            text = f"{self._section_no}.{self._sub_no} {text}"
        self.doc.add_heading(text, level=level)

    def _h3(self, text: str) -> None:
        self.doc.add_heading(text, level=3)

    def _p(self, text: str = "", *, bold: bool = False, size=None, color=None, align=None) -> None:
        paragraph = self.doc.add_paragraph()
        run = paragraph.add_run(_safe(text))
        run.bold = bold
        if size:
            run.font.size = Pt(size)
        if color:
            run.font.color.rgb = color
        if align is not None:
            paragraph.alignment = align
        return paragraph

    def _bullet(self, text: str) -> None:
        try:
            self.doc.add_paragraph(_safe(text), style="List Bullet")
        except KeyError:
            self._p("• " + _safe(text))

    def _table(
        self,
        headers: Sequence[str],
        rows: Iterable[Sequence],
        widths: Optional[Sequence[float]] = None,
        header_color: Optional[str] = "0B3D6B",
    ):
        rows = list(rows)
        table = self.doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = bool(widths is None)
        header_cells = table.rows[0].cells
        for index, title in enumerate(headers):
            cell = header_cells[index]
            cell.text = ""
            paragraph = cell.paragraphs[0]
            run = paragraph.add_run(str(title))
            run.bold = True
            run.font.size = Pt(9.5)
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            if header_color:
                self._shade(cell, header_color)
        for row in rows:
            cells = table.add_row().cells
            for index, value in enumerate(row):
                cells[index].text = ""
                paragraph = cells[index].paragraphs[0]
                run = paragraph.add_run(_safe(value))
                run.font.size = Pt(9)
        if widths:
            for row in table.rows:
                for index, width in enumerate(widths):
                    if index < len(row.cells):
                        row.cells[index].width = Cm(width)
        self.doc.add_paragraph()
        return table

    def _shade(self, cell, color: str) -> None:
        tc_pr = cell._tc.get_or_add_tcPr()
        shading = OxmlElement("w:shd")
        shading.set(qn("w:val"), "clear")
        shading.set(qn("w:color"), "auto")
        shading.set(qn("w:fill"), color)
        tc_pr.append(shading)

    def _kv(self, pairs: Sequence[tuple[str, object]]) -> None:
        self._table(["项目", "内容"], pairs, widths=[4.2, 12.2])

    def _picture(self, buffer, width: float = 6.0) -> None:
        if buffer is None:
            return
        try:
            buffer.seek(0)
            self.doc.add_picture(buffer, width=Inches(width))
            self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        except Exception:  # noqa: BLE001 - 图表失败不应影响报告
            pass

    def _page_break(self) -> None:
        self.doc.add_page_break()

    # ---- 封面 / 目录 ----
    def _cover(self) -> None:
        report = self.report
        for _ in range(5):
            self.doc.add_paragraph()
        paragraph = self.doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = paragraph.add_run("Windows 主机安全审计报告")
        run.bold = True
        run.font.size = Pt(30)
        run.font.color.rgb = _HEADING_COLOR

        paragraph = self.doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = paragraph.add_run("— 日志深度分析与入侵痕迹排查 —")
        run.font.size = Pt(14)
        run.font.color.rgb = _MUTED

        for _ in range(3):
            self.doc.add_paragraph()

        mode_label = {
            "remote": "远程采集（WinRM）",
            "local": "本机采集",
            "offline": "离线日志分析",
            "demo": "内置演示数据",
        }.get(report.mode, report.mode)
        self._kv(
            [
                ("目标主机", report.target or "本机"),
                ("审计方式", mode_label),
                ("主机名", report.host_info.get("hostname", "-")),
                ("操作系统", report.host_info.get("os", "-")),
                ("生成时间", fmt_time(dt.datetime.now(dt.timezone.utc))),
                ("工具版本", f"windows_log_audit v{__version__}"),
            ]
        )

        paragraph = self.doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = paragraph.add_run("【内部资料 · 注意保密】")
        run.bold = True
        run.font.color.rgb = RGBColor(0xC0, 0x1B, 0x1B)
        self._page_break()

    def _toc(self) -> None:
        self.doc.add_heading("目录", level=1)
        paragraph = self.doc.add_paragraph()
        self._add_field(paragraph, 'TOC \\o "1-2" \\h \\z', "（在 Word 中右键选择“更新域”生成目录）")
        self._page_break()

    # ---- 摘要 ----
    def _summary(self) -> None:
        report = self.report
        self._heading("执行摘要")

        verdict = report.verdict or "未发现明显风险"
        severity = report.max_severity
        paragraph = self.doc.add_paragraph()
        run = paragraph.add_run(verdict)
        run.bold = True
        run.font.size = Pt(15)
        run.font.color.rgb = _SEVERITY_RGB[severity]

        self._p(
            f"本次审计共解析 {report.total_events} 条事件，产生 {len(report.findings)} 项发现"
            f"（严重 {report.severity_counts.get('严重', 0)} 项、"
            f"高危 {report.severity_counts.get('高危', 0)} 项、"
            f"中危 {report.severity_counts.get('中危', 0)} 项），"
            f"综合风险评分 {report.risk_score:.1f}。",
        )

        self._kv(
            [
                ("风险评分", f"{report.risk_score:.1f}"),
                ("最高级别", severity.label),
                ("发现数量", len(report.findings)),
                ("事件总数", report.total_events),
                ("采集模式", report.mode),
                ("分析区间", self._time_range()),
            ]
        )

        if self.with_charts:
            self._picture(charts.severity_bar(report.severity_counts), width=5.6)

        self._h3("关键发现 Top 10")
        rows = []
        for finding in report.sorted_findings()[:10]:
            rows.append(
                [
                    finding.severity.label,
                    finding.title,
                    finding.count,
                    fmt_time(finding.first_seen) if finding.first_seen else "-",
                ]
            )
        if rows:
            self._table(["级别", "发现", "次数", "首次出现"], rows, widths=[2.0, 9.5, 1.8, 3.4])
        else:
            self._p("未发现需要告警的安全事件。")

        if report.tactics:
            self._h3("攻击链阶段覆盖")
            self._table(
                ["ATT&CK 战术阶段", "发现数量"],
                [[tactic, count] for tactic, count in report.tactics.items()],
                widths=[9.0, 3.5],
            )
            stages = [t for t in TACTIC_ORDER if report.tactics.get(t)]
            if len(stages) >= 3:
                self._p(
                    "检测到跨阶段的攻击链：" + " → ".join(stages) + "。"
                    "多个阶段连续出现通常意味着主机已被实际控制，而非单一误报。",
                    color=_MUTED,
                )

        self._h3("入侵链路时间线")
        if report.timeline:
            rows = [
                [item["display"], item["severity"], item["title"]]
                for item in report.timeline[:25]
            ]
            self._table(["时间", "级别", "事件"], rows, widths=[3.6, 2.0, 11.0])
        else:
            self._p("未构建出可关联的攻击时间线（中危及以上发现不足）。")
        self._page_break()

    def _time_range(self) -> str:
        if self.report.timeline:
            return f"{self.report.timeline[0]['display']} ~ {self.report.timeline[-1]['display']}"
        return "-"

    # ---- 覆盖 ----
    def _coverage(self) -> None:
        report = self.report
        self._heading("审计范围与数据覆盖")
        self._p(
            "本报告基于 Windows 事件日志、IIS 访问日志与主机安全配置基线生成。"
            "日志审计只能反映“已被记录”的行为：若审核策略未开启或日志已被清除，"
            "结论的完整性会受到影响（见下方覆盖说明）。"
        )

        rows = []
        for item in report.collection:
            if item.get("log") == "posture":
                continue
            rows.append(
                [
                    item.get("label") or item.get("log", ""),
                    item.get("count", 0),
                    item.get("status", ""),
                    (item.get("error") or "")[:120],
                ]
            )
        if rows:
            self._table(["日志/数据源", "条数", "采集状态", "说明"], rows, widths=[5.2, 2.0, 2.4, 7.0])

        if report.coverage:
            self._h3("覆盖说明与局限")
            for note in report.coverage:
                self._bullet(note)

        posture = report.posture
        if posture:
            self._h3("主机配置基线")
            rows = []
            mapping = [
                ("hostname", "主机名"),
                ("os", "操作系统"),
                ("domain", "域/工作组"),
                ("uptime_days", "运行天数"),
                ("rdp_enabled", "RDP 已启用"),
                ("rdp_nla", "RDP 要求 NLA"),
                ("smb1", "SMBv1 已启用"),
                ("lsa_protection", "LSA 保护"),
                ("sysmon", "Sysmon"),
            ]
            for key, label in mapping:
                if key in posture:
                    rows.append([label, posture.get(key)])
            defender = posture.get("defender")
            if isinstance(defender, dict):
                rows.append(
                    [
                        "Defender",
                        f"实时保护={defender.get('realtime')}，防病毒={defender.get('antivirus')}",
                    ]
                )
            if rows:
                self._table(["项目", "取值"], rows, widths=[5.0, 11.4])
        self._page_break()

    # ---- 详细发现 ----
    def _findings(self) -> None:
        report = self.report
        self._heading("详细发现")
        detailed = [f for f in report.sorted_findings() if f.severity >= Severity.LOW]
        if not detailed:
            self._p("未发现低危及以上安全事件。若需要更灵敏的检测，可降低阈值或扩大采集时间范围。")
            return

        limit = 80
        for finding in detailed[:limit]:
            self._finding_block(finding)
        if len(detailed) > limit:
            self._p(
                f"另有 {len(detailed) - limit} 项低危发现未逐条展开，"
                "可在 JSON/Markdown 报告中查看完整列表。",
                color=_MUTED,
            )
        self._page_break()

    def _finding_block(self, finding: Finding) -> None:
        paragraph = self.doc.add_paragraph()
        run = paragraph.add_run(f"[{finding.severity.label}] {finding.title}")
        run.bold = True
        run.font.size = Pt(11.5)
        run.font.color.rgb = _SEVERITY_RGB[finding.severity]

        rows = [("规则编号", finding.rule_id)]
        if finding.technique:
            rows.append(("ATT&CK", finding.technique))
        if finding.tactic:
            rows.append(("战术阶段", finding.tactic))
        for key, value in finding.entities.items():
            if value:
                rows.append((f"实体/{key}", value))
        rows.append(("出现次数", finding.count))
        if finding.first_seen:
            rows.append(("时间范围", f"{fmt_time(finding.first_seen)} ~ {fmt_time(finding.last_seen)}"))
        self._table(["属性", "内容"], rows, widths=[3.4, 13.0], header_color="1F5C99")

        if finding.description:
            self._p(finding.description)
        if finding.evidence:
            self._p("证据：", bold=True)
            for line in finding.evidence:
                self._bullet(line)
        if finding.recommendation:
            self._p("处置建议：" + finding.recommendation, color=_MUTED)
        self.doc.add_paragraph()

    # ---- 认证 ----
    def _auth(self) -> None:
        report = self.report
        stats = report.logon_stats or {}
        self._heading("登录认证与暴力破解分析")
        self._kv(
            [
                ("登录成功", stats.get("success", 0)),
                ("登录失败", stats.get("failure", 0)),
                ("失败/成功比", stats.get("failure_success_ratio", 0)),
                ("RDP 会话", stats.get("rdp", 0)),
                ("公网来源成功登录", stats.get("external_success", 0)),
                ("公网来源失败登录", stats.get("external_failure", 0)),
                ("涉及账户数", stats.get("distinct_users", 0)),
            ]
        )

        if report.top_source_ips:
            self._h3("登录失败来源 Top 10")
            rows = []
            for ip, count in report.top_source_ips:
                rows.append([ip, count, report.geo.get(ip, "")])
            self._table(["来源 IP", "失败次数", "地理位置"], rows, widths=[6.0, 3.0, 6.0])
            if self.with_charts:
                self._picture(charts.top_barh(report.top_source_ips, "登录失败来源 IP", "#DC2626"), 5.8)

        if report.top_users:
            self._h3("成功登录账户 Top 10")
            self._table(
                ["账户", "成功次数"],
                [[user, count] for user, count in report.top_users],
                widths=[9.0, 4.0],
            )

        logon_types = stats.get("logon_types") or []
        if logon_types:
            labels = {
                "2": "2 交互式",
                "3": "3 网络",
                "4": "4 批处理",
                "5": "5 服务",
                "7": "7 解锁",
                "8": "8 明文网络",
                "9": "9 新凭据",
                "10": "10 远程桌面",
                "11": "11 缓存交互",
            }
            self._h3("登录类型分布")
            self._table(
                ["登录类型", "次数"],
                [[labels.get(str(t), str(t)), count] for t, count in logon_types],
                widths=[9.0, 4.0],
            )

        self._domain_findings(["AUTH-"])

    # ---- 通用领域发现 ----
    def _domain_findings(self, prefixes: Sequence[str]) -> None:
        findings = [
            f
            for f in self.report.sorted_findings()
            if any(f.rule_id.startswith(prefix) for prefix in prefixes)
        ]
        if not findings:
            self._p("本节未发现相关安全事件。", color=_MUTED)
            return
        rows = []
        for finding in findings[:30]:
            rows.append(
                [
                    finding.severity.label,
                    finding.title,
                    finding.count,
                    finding.rule_id,
                ]
            )
        self._table(["级别", "发现", "次数", "规则"], rows, widths=[2.0, 10.6, 1.8, 2.0])

    def _rdp(self) -> None:
        self._heading("远程桌面审计")
        stats = self.report.logon_stats or {}
        self._p(
            f"共检测到 {stats.get('rdp', 0)} 个远程桌面会话相关事件，"
            "其中公网来源登录会触发高危告警；内网 RDP 需结合资产清单判断是否属于横向移动。"
        )
        self._domain_findings(["AUTH-005", "AUTH-006", "AUTH-007"])
        if self.with_charts and self.report.top_source_ips:
            self._picture(
                charts.top_barh(self.report.top_source_ips[:8], "远程登录来源 IP", "#1F5C99"),
                5.6,
            )

    def _accounts(self) -> None:
        self._heading("账户与权限变更")
        self._p(
            "攻击者取得初始权限后通常会创建后门账户、重置口令或将账户加入管理员组。"
            "以下发现按时间与实体关联，若“新建账户”与“加入管理员组”同时出现，"
            "则极可能是完整攻击链。"
        )
        self._domain_findings(["ACCT-"])

    def _persistence(self) -> None:
        self._heading("持久化与执行痕迹")
        self._p(
            "持久化是入侵后最关键的驻留手段。本节覆盖服务安装、计划任务、注册表自启动、"
            "WMI 订阅、BITS 传输，以及可疑命令行、PowerShell 脚本块、LSASS 访问等执行痕迹。"
        )
        self._domain_findings(["PERSIST-", "EXEC-", "PS-"])

    def _defense(self) -> None:
        self._heading("防御规避与主机配置基线")
        self._p(
            "清除日志、关闭杀软、修改审核策略与防火墙是攻击者隐藏行踪的常见动作；"
            "主机配置缺陷（未启用 LSA 保护、SMBv1、RDP 无 NLA 等）则会放大入侵影响。"
        )
        self._domain_findings(["DEF-", "POST-"])

    def _iis(self) -> None:
        report = self.report
        stats = report.iis_stats or {}
        self._heading("Web（IIS）攻击分析")
        if not stats.get("total"):
            self._p("未采集到 IIS 访问日志（站点可能未使用 IIS，或日志路径不同）。", color=_MUTED)
            return

        self._kv(
            [
                ("请求总数", stats.get("total", 0)),
                ("独立来源 IP", stats.get("unique_ips", 0)),
                ("4xx 响应", stats.get("error_4xx", 0)),
                ("5xx 响应", stats.get("error_5xx", 0)),
                ("统计区间", f"{fmt_time(stats.get('first_seen'))} ~ {fmt_time(stats.get('last_seen'))}"),
                ("日志文件", "，".join(stats.get("files", [])[:3]) or "-"),
            ]
        )

        status_dist = stats.get("status_distribution") or []
        if status_dist:
            self._h3("HTTP 状态码分布")
            self._table(
                ["状态码", "数量"],
                [[str(code), count] for code, count in status_dist[:10]],
                widths=[5.0, 4.0],
            )

        top_ips = stats.get("geo_top_ips") or [
            (ip, count, "") for ip, count in (stats.get("top_ips") or [])[:10]
        ]
        if top_ips:
            self._h3("访问来源 Top 10")
            self._table(
                ["来源 IP", "请求数", "地理位置"],
                [[ip, count, geo] for ip, count, geo in top_ips[:10]],
                widths=[6.0, 3.0, 6.0],
            )

        top_urls = stats.get("top_urls") or []
        if top_urls:
            self._h3("高频访问路径 Top 10")
            self._table(
                ["路径", "次数"],
                [[url[:90], count] for url, count in top_urls[:10]],
                widths=[12.4, 3.0],
            )

        attacks = stats.get("attack_counts") or {}
        if attacks:
            self._h3("攻击类型统计")
            self._table(
                ["攻击类型", "命中次数"],
                [[name, count] for name, count in attacks.items()],
                widths=[11.0, 4.0],
            )

        self._h3("Web 攻击相关发现")
        self._domain_findings(["WEB-"])

    def _tomcat(self) -> None:
        report = self.report
        stats = report.tomcat_stats or {}
        self._heading("Web（Tomcat）攻击分析")
        if not stats.get("total") and not stats.get("catalina_events"):
            self._p("未采集到 Tomcat 日志（可通过 --tomcat-path 指定日志目录）。", color=_MUTED)
            return

        self._kv(
            [
                ("请求总数", stats.get("total", 0)),
                ("独立来源 IP", stats.get("unique_ips", 0)),
                ("4xx 响应", stats.get("error_4xx", 0)),
                ("5xx 响应", stats.get("error_5xx", 0)),
                ("Tomcat 版本", stats.get("version") or "未知"),
                ("Catalina 日志", stats.get("catalina_events", 0)),
                ("SEVERE 事件", stats.get("severe_events", 0)),
                (
                    "统计区间",
                    f"{fmt_time(stats.get('first_seen'))} ~ {fmt_time(stats.get('last_seen'))}",
                ),
            ]
        )

        status_dist = stats.get("status_distribution") or []
        if status_dist:
            self._h3("HTTP 状态码分布")
            self._table(
                ["状态码", "数量"],
                [[str(code), count] for code, count in status_dist[:10]],
                widths=[5.0, 4.0],
            )

        top_ips = stats.get("geo_top_ips") or [
            (ip, count, "") for ip, count in (stats.get("top_ips") or [])[:10]
        ]
        if top_ips:
            self._h3("访问来源 Top 10")
            self._table(
                ["来源 IP", "请求数", "地理位置"],
                [[ip, count, geo] for ip, count, geo in top_ips[:10]],
                widths=[6.0, 3.0, 6.0],
            )

        top_urls = stats.get("top_urls") or []
        if top_urls:
            self._h3("高频访问路径 Top 10")
            self._table(
                ["路径", "次数"],
                [[url[:90], count] for url, count in top_urls[:10]],
                widths=[12.4, 3.0],
            )

        attacks = stats.get("attack_counts") or {}
        if attacks:
            self._h3("攻击类型统计")
            self._table(
                ["攻击类型", "命中次数"],
                [[name, count] for name, count in attacks.items()],
                widths=[11.0, 4.0],
            )

        deployments = stats.get("deployments") or []
        if deployments:
            self._h3("Web 应用部署记录")
            self._table(
                ["时间", "部署路径"],
                [[item.get("time") or "-", item.get("path", "")] for item in deployments[:10]],
                widths=[4.5, 11.5],
            )

        self._h3("Tomcat 相关发现")
        self._domain_findings(["TOMCAT-"])

    # ---- IOC ----
    def _iocs(self) -> None:
        self._heading("IOC 清单")
        labels = {
            "ip": "IP 地址",
            "url": "URL",
            "file": "文件路径",
            "hash": "哈希",
            "process": "进程路径",
            "user": "账户",
            "service": "服务",
            "task": "计划任务",
            "registry": "注册表",
            "user_agent": "User-Agent",
        }
        found = False
        for key, label in labels.items():
            values = (self.report.iocs or {}).get(key) or []
            if not values:
                continue
            found = True
            self._h3(label)
            self._table([label, "序号"], [[v, i + 1] for i, v in enumerate(values[:30])], widths=[14.4, 2.0])
        if not found:
            self._p("未提取到可用的 IOC。", color=_MUTED)

        self._p(
            "以上 IOC 可用于在 SIEM/EDR 中做横向排查。请注意：公网 IP 可能为 NAT 出口，"
            "需结合时间与端口进一步确认。",
            color=_MUTED,
        )

    # ---- 建议 ----
    def _recommendations(self) -> None:
        report = self.report
        self._heading("处置建议")
        items: list[str] = []
        for finding in report.sorted_findings():
            if finding.severity >= Severity.HIGH and finding.recommendation:
                text = f"【{finding.severity.label}】{finding.title}：{finding.recommendation}"
                if text not in items:
                    items.append(text)
        generic = [
            "立即对高危主机做隔离与证据保全（内存、磁盘、日志），避免攻击者继续操作或清除痕迹。",
            "重置在该主机登录过的所有账户口令（尤其是管理员与域账户），并撤销现有会话与令牌。",
            "启用日志集中转发（WEF/SIEM），确保安全日志、PowerShell 脚本块日志、Sysmon 日志不落地丢失。",
            "按最小权限原则清理本地管理员组，启用 LAPS 管理本地口令，管理员账户启用 MFA。",
            "收敛暴露面：关闭不必要的 RDP/SMB/WinRM 公网访问，通过 VPN/堡垒机运维。",
            "及时安装安全补丁，启用 LSA 保护与 Credential Guard，禁用 SMBv1 与 NTLMv1。",
            "对关键数据做离线备份并定期演练恢复，防止勒索软件破坏备份。",
            "建立基线告警：新建管理员、服务安装、计划任务创建、日志清除、Defender 关闭。",
        ]
        self._p("针对本次发现的处置建议：", bold=True)
        if items:
            for index, item in enumerate(items[:20], 1):
                self._p(f"{index}. {item}")
        else:
            self._p("本次未发现高危问题，建议维持现有防护并定期复测。")
        self._p("通用加固建议：", bold=True)
        for index, item in enumerate(generic, 1):
            self._p(f"{index}. {item}")
        self._page_break()

    # ---- 附录 ----
    def _appendix(self) -> None:
        report = self.report
        self._heading("附录")
        self._h3("事件统计")
        rows = [
            [LOG_LABELS.get(key, key), count]
            for key, count in report.event_counts.items()
        ]
        if rows:
            self._table(["日志", "解析条数"], rows, widths=[9.0, 4.0])

        if report.collection:
            self._h3("采集明细")
            rows = []
            for item in report.collection:
                rows.append(
                    [
                        item.get("channel") or item.get("label") or item.get("log", ""),
                        item.get("count", 0),
                        item.get("status", ""),
                        (item.get("error") or "")[:100],
                    ]
                )
            self._table(["通道", "条数", "状态", "错误"], rows, widths=[6.2, 1.8, 2.2, 6.2])

        self._h3("分析参数")
        self._table(
            ["参数", "取值"],
            [[key, value] for key, value in (report.options or {}).items()],
            widths=[6.0, 10.0],
        )

        self._h3("严重级别说明")
        self._table(
            ["级别", "含义"],
            [
                ["严重", "高度疑似已被入侵，存在明确的攻击链证据，需立即响应。"],
                ["高危", "存在明显入侵迹象或可被直接利用的高风险配置。"],
                ["中危", "存在可疑行为或配置缺陷，需要进一步核实。"],
                ["低危", "弱信号或加固建议，建议纳入日常巡检。"],
                ["信息", "用于补充上下文的基线信息。"],
            ],
            widths=[2.4, 13.6],
        )

        self._p(
            f"报告生成时间：{fmt_time(dt.datetime.now(dt.timezone.utc))}；"
            f"解析失败事件：{report.parse_errors} 条；"
            f"工具：windows_log_audit v{__version__}。",
            color=_MUTED,
        )

    # ---- 构建 ----
    def build(self):
        self._cover()
        self._toc()
        self._summary()
        self._coverage()
        self._findings()
        self._auth()
        self._page_break()
        self._rdp()
        self._page_break()
        self._accounts()
        self._page_break()
        self._persistence()
        self._page_break()
        self._defense()
        self._page_break()
        self._iis()
        self._page_break()
        self._tomcat()
        self._page_break()
        self._iocs()
        self._page_break()
        self._recommendations()
        self._appendix()
        return self.doc

    def save(self, path: str) -> str:
        self.build()
        self.doc.save(path)
        return path


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def _md_cell(value) -> str:
    return _safe(value).replace("|", "\\|").replace("\n", " ")


def _md_table(headers: Sequence[str], rows: Iterable[Sequence]) -> str:
    lines = ["| " + " | ".join(_md_cell(h) for h in headers) + " |"]
    lines.append("|" + "|".join([" --- "] * len(headers)) + "|")
    for row in rows:
        lines.append("| " + " | ".join(_md_cell(cell) for cell in row) + " |")
    return "\n".join(lines)


def render_markdown(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append("# Windows 主机安全审计报告")
    lines.append("")
    lines.append(f"- 目标主机：{report.target or '本机'}")
    lines.append(f"- 审计方式：{report.mode}")
    lines.append(f"- 生成时间：{fmt_time(dt.datetime.now(dt.timezone.utc))}")
    lines.append(f"- 事件总数：{report.total_events}")
    lines.append(f"- 风险评分：{report.risk_score:.1f}（{report.verdict}）")
    lines.append("")
    lines.append("## 严重级别分布")
    lines.append("")
    lines.append(_md_table(["级别", "数量"], [[k, v] for k, v in report.severity_counts.items()]))
    lines.append("")

    if report.tactics:
        lines.append("## 攻击链阶段覆盖")
        lines.append("")
        lines.append(
            _md_table(
                ["ATT&CK 战术阶段", "发现数量"],
                [[tactic, count] for tactic, count in report.tactics.items()],
            )
        )
        stages = [t for t in TACTIC_ORDER if report.tactics.get(t)]
        if len(stages) >= 3:
            lines.append("")
            lines.append("检测到跨阶段攻击链：" + " → ".join(stages) + "。")
        lines.append("")

    lines.append("## 审计范围与覆盖")
    lines.append("")
    for note in report.coverage:
        lines.append(f"- {note}")
    lines.append("")
    lines.append(
        _md_table(
            ["日志", "条数", "状态", "说明"],
            [
                [
                    item.get("label") or item.get("log", ""),
                    item.get("count", 0),
                    item.get("status", ""),
                    item.get("error", ""),
                ]
                for item in report.collection
                if item.get("log") != "posture"
            ],
        )
    )
    lines.append("")

    lines.append("## 详细发现")
    lines.append("")
    tomcat = report.tomcat_stats or {}
    if tomcat.get("total") or tomcat.get("catalina_events"):
        lines.append("## Tomcat 中间件分析")
        lines.append("")
        lines.append(
            _md_table(
                ["指标", "取值"],
                [
                    ["请求总数", tomcat.get("total", 0)],
                    ["独立来源 IP", tomcat.get("unique_ips", 0)],
                    ["Tomcat 版本", tomcat.get("version") or "未知"],
                    ["Catalina 日志", tomcat.get("catalina_events", 0)],
                    ["SEVERE 事件", tomcat.get("severe_events", 0)],
                ],
            )
        )
        lines.append("")
        attacks = tomcat.get("attack_counts") or {}
        if attacks:
            lines.append(
                _md_table(
                    ["攻击类型", "命中次数"],
                    [[name, count] for name, count in attacks.items()],
                )
            )
            lines.append("")
        deployments = tomcat.get("deployments") or []
        if deployments:
            lines.append("### Web 应用部署记录")
            lines.append("")
            for item in deployments[:10]:
                lines.append(f"- `{item.get('time') or '-'}` {item.get('path', '')}")
            lines.append("")

    for index, finding in enumerate(report.sorted_findings(), 1):
        lines.append(f"### {index}. [{finding.severity.label}] {finding.title}")
        lines.append("")
        lines.append(f"- 规则：`{finding.rule_id}`")
        if finding.technique:
            lines.append(f"- ATT&CK：{finding.technique}")
        if finding.tactic:
            lines.append(f"- 战术：{finding.tactic}")
        for key, value in finding.entities.items():
            if value:
                lines.append(f"- {key}：{value}")
        lines.append(f"- 次数：{finding.count}")
        if finding.first_seen:
            lines.append(
                f"- 时间范围：{fmt_time(finding.first_seen)} ~ {fmt_time(finding.last_seen)}"
            )
        lines.append("")
        if finding.description:
            lines.append(finding.description)
            lines.append("")
        if finding.evidence:
            lines.append("**证据：**")
            lines.append("")
            for item in finding.evidence:
                lines.append(f"- `{item}`")
            lines.append("")
        if finding.recommendation:
            lines.append(f"**建议：** {finding.recommendation}")
            lines.append("")

    lines.append("## IOC 清单")
    lines.append("")
    for key, values in (report.iocs or {}).items():
        if not values:
            continue
        lines.append(f"### {key}")
        lines.append("")
        for value in values[:30]:
            lines.append(f"- `{value}`")
        lines.append("")

    lines.append("## 处置建议")
    lines.append("")
    for finding in report.sorted_findings():
        if finding.severity >= Severity.HIGH and finding.recommendation:
            lines.append(f"- **[{finding.severity.label}] {finding.title}**：{finding.recommendation}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def render_html(report: AuditReport, with_charts: bool = True) -> str:
    severity_class = {
        "严重": "critical",
        "高危": "high",
        "中危": "medium",
        "低危": "low",
        "信息": "info",
    }

    def table(headers: Sequence[str], rows: Iterable[Sequence]) -> str:
        rows = list(rows)
        if not rows:
            return "<p class='muted'>无数据</p>"
        head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{html.escape(_safe(cell))}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"<title>Windows 安全审计 - {html.escape(report.target or '本机')}</title>")
    parts.append(
        """<style>
        :root { --bg:#f6f8fb; --card:#fff; --text:#1f2937; --muted:#6b7280; --line:#e5e7eb; }
        * { box-sizing: border-box; }
        body { margin:0; background:var(--bg); color:var(--text);
               font-family: "Microsoft YaHei","PingFang SC",system-ui,sans-serif; line-height:1.65; }
        .wrap { max-width: 1080px; margin: 0 auto; padding: 32px 24px 80px; }
        h1 { font-size: 30px; margin: 0 0 8px; }
        h2 { margin-top: 44px; padding-bottom: 8px; border-bottom: 2px solid var(--line); }
        h3 { margin-top: 28px; }
        .sub { color: var(--muted); margin-bottom: 24px; }
        .verdict { display:inline-block; padding: 6px 14px; border-radius: 999px;
                   color:#fff; font-weight:700; margin: 8px 0 16px; }
        .critical { background:#c01b1b; } .high { background:#d9480d; }
        .medium { background:#b46a00; } .low { background:#1d4ed8; } .info { background:#555f6b; }
        .card { background:var(--card); border:1px solid var(--line); border-radius:10px;
                padding: 18px 20px; margin: 16px 0; }
        table { width:100%; border-collapse: collapse; margin: 12px 0 20px; font-size: 14px; }
        th, td { border:1px solid var(--line); padding: 8px 10px; text-align:left; vertical-align:top; }
        th { background:#0b3d6b; color:#fff; font-weight:600; }
        tr:nth-child(even) td { background:#fafbfc; }
        code, .mono { font-family: Consolas, monospace; font-size: 13px; background:#f3f4f6;
                      padding: 1px 5px; border-radius: 4px; }
        .muted { color: var(--muted); }
        .finding { background:var(--card); border:1px solid var(--line); border-left-width:5px;
                   border-radius:8px; padding: 16px 18px; margin: 18px 0; }
        .finding.critical { border-left-color:#c01b1b; }
        .finding.high { border-left-color:#d9480d; }
        .finding.medium { border-left-color:#b46a00; }
        .finding.low { border-left-color:#1d4ed8; }
        .finding.info { border-left-color:#555f6b; }
        ul { padding-left: 22px; }
        img { max-width: 100%; border:1px solid var(--line); border-radius:8px; margin: 8px 0; }
        </style></head><body><div class='wrap'>"""
    )
    parts.append("<h1>Windows 主机安全审计报告</h1>")
    parts.append(
        f"<div class='sub'>目标：{html.escape(report.target or '本机')} · "
        f"方式：{html.escape(report.mode)} · 生成时间：{html.escape(fmt_time(dt.datetime.now(dt.timezone.utc)))}</div>"
    )
    max_label = report.max_severity.label
    parts.append(
        f"<div class='verdict {severity_class.get(max_label, 'info')}'>{html.escape(report.verdict)}</div>"
    )
    parts.append(
        f"<div class='card'>风险评分 <b>{report.risk_score:.1f}</b> · 事件 <b>{report.total_events}</b> 条 · "
        f"发现 <b>{len(report.findings)}</b> 项（严重 {report.severity_counts.get('严重', 0)}，"
        f"高危 {report.severity_counts.get('高危', 0)}，中危 {report.severity_counts.get('中危', 0)}）</div>"
    )

    if with_charts:
        for name, buffer in (
            ("严重级别分布", charts.severity_bar(report.severity_counts)),
            ("登录失败来源", charts.top_barh(report.top_source_ips, "登录失败来源 IP", "#dc2626")),
        ):
            if buffer is None:
                continue
            encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
            parts.append(f"<img alt='{name}' src='data:image/png;base64,{encoded}'>")

    parts.append("<h2>执行摘要</h2>")
    key_rows = [
        [f.severity.label, f.title, f.count, fmt_time(f.first_seen) if f.first_seen else "-"]
        for f in report.sorted_findings()[:10]
    ]
    parts.append(table(["级别", "发现", "次数", "首次出现"], key_rows))

    if report.tactics:
        parts.append("<h2>攻击链阶段覆盖</h2>")
        parts.append(
            table(
                ["ATT&CK 战术阶段", "发现数量"],
                [[tactic, count] for tactic, count in report.tactics.items()],
            )
        )
        stages = [t for t in TACTIC_ORDER if report.tactics.get(t)]
        if len(stages) >= 3:
            parts.append(
                f"<p class='muted'>检测到跨阶段攻击链：{html.escape(' → '.join(stages))}。</p>"
            )

    parts.append("<h2>审计范围与数据覆盖</h2><ul>")
    for note in report.coverage:
        parts.append(f"<li>{html.escape(note)}</li>")
    parts.append("</ul>")
    parts.append(
        table(
            ["日志", "条数", "状态", "说明"],
            [
                [item.get("label") or item.get("log", ""), item.get("count", 0),
                 item.get("status", ""), item.get("error", "")]
                for item in report.collection
                if item.get("log") != "posture"
            ],
        )
    )

    tomcat = report.tomcat_stats or {}
    if tomcat.get("total") or tomcat.get("catalina_events"):
        parts.append("<h2>Tomcat 中间件分析</h2>")
        parts.append(
            table(
                ["指标", "取值"],
                [
                    ["请求总数", tomcat.get("total", 0)],
                    ["独立来源 IP", tomcat.get("unique_ips", 0)],
                    ["Tomcat 版本", tomcat.get("version") or "未知"],
                    ["Catalina 日志", tomcat.get("catalina_events", 0)],
                    ["SEVERE 事件", tomcat.get("severe_events", 0)],
                ],
            )
        )
        attacks = tomcat.get("attack_counts") or {}
        if attacks:
            parts.append(
                table(
                    ["攻击类型", "命中次数"],
                    [[name, count] for name, count in attacks.items()],
                )
            )
        deployments = tomcat.get("deployments") or []
        if deployments:
            parts.append("<h3>Web 应用部署记录</h3>")
            parts.append(
                table(
                    ["时间", "部署路径"],
                    [[item.get("time") or "-", item.get("path", "")] for item in deployments[:10]],
                )
            )

    if report.timeline:
        parts.append("<h2>入侵链路时间线</h2>")
        parts.append(
            table(
                ["时间", "级别", "事件"],
                [[item["display"], item["severity"], item["title"]] for item in report.timeline[:40]],
            )
        )

    parts.append("<h2>详细发现</h2>")
    for finding in report.sorted_findings():
        css = severity_class.get(finding.severity.label, "info")
        parts.append(f"<div class='finding {css}'>")
        parts.append(
            f"<h3>[{html.escape(finding.severity.label)}] {html.escape(finding.title)}</h3>"
        )
        meta = [f"规则 <code>{html.escape(finding.rule_id)}</code>"]
        if finding.technique:
            meta.append(f"ATT&CK {html.escape(finding.technique)}")
        meta.append(f"次数 {finding.count}")
        if finding.first_seen:
            meta.append(
                f"时间 {html.escape(fmt_time(finding.first_seen))} ~ {html.escape(fmt_time(finding.last_seen))}"
            )
        parts.append("<p class='muted'>" + " · ".join(meta) + "</p>")
        if finding.description:
            parts.append(f"<p>{html.escape(finding.description)}</p>")
        if finding.evidence:
            parts.append("<p><b>证据</b></p><ul>")
            for line in finding.evidence:
                parts.append(f"<li><span class='mono'>{html.escape(line)}</span></li>")
            parts.append("</ul>")
        if finding.recommendation:
            parts.append(f"<p><b>建议：</b>{html.escape(finding.recommendation)}</p>")
        parts.append("</div>")

    parts.append("<h2>IOC 清单</h2>")
    for key, values in (report.iocs or {}).items():
        if not values:
            continue
        parts.append(f"<h3>{html.escape(key)}</h3><ul>")
        for value in values[:30]:
            parts.append(f"<li><code>{html.escape(value)}</code></li>")
        parts.append("</ul>")

    parts.append("<h2>处置建议</h2><ul>")
    shown = 0
    for finding in report.sorted_findings():
        if finding.severity >= Severity.HIGH and finding.recommendation and shown < 20:
            parts.append(
                f"<li><b>[{html.escape(finding.severity.label)}] {html.escape(finding.title)}</b>："
                f"{html.escape(finding.recommendation)}</li>"
            )
            shown += 1
    if not shown:
        parts.append("<li>未发现高危问题，建议保持现有防护并定期复测。</li>")
    parts.append("</ul>")

    parts.append("</div></body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------
def _json_default(value):
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    return str(value)


def write_report(
    report: AuditReport,
    path: str,
    fmt: str = "docx",
    with_charts: bool = True,
) -> list[str]:
    """写出报告，返回实际生成的文件列表。"""
    fmt = (fmt or "docx").lower()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    formats = ["docx", "md", "json", "html"] if fmt == "all" else [fmt]
    if fmt == "all" and not DOCX_AVAILABLE:
        formats = ["md", "json", "html"]

    for current in formats:
        output = target if fmt != "all" else target.with_suffix(f".{current}")
        if fmt != "all":
            if output.suffix.lower() != f".{current}":
                output = output.with_suffix(f".{current}")
        if current == "docx":
            DocxReport(report, with_charts=with_charts).save(str(output))
        elif current == "md":
            output.write_text(render_markdown(report), encoding="utf-8")
        elif current == "html":
            output.write_text(render_html(report, with_charts), encoding="utf-8")
        elif current == "json":
            output.write_text(
                json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=_json_default),
                encoding="utf-8",
            )
        else:
            raise ValueError(f"不支持的报告格式: {current}")
        generated.append(str(output))
    return generated


def summarize(report: AuditReport, report_paths: Sequence[str] = ()) -> str:
    """生成控制台摘要。"""
    lines = [
        "",
        "=" * 68,
        f"审计结论：{report.verdict}",
        f"风险评分：{report.risk_score:.1f}    事件：{report.total_events}    发现：{len(report.findings)}",
        f"级别分布：严重 {report.severity_counts.get('严重', 0)} / "
        f"高危 {report.severity_counts.get('高危', 0)} / "
        f"中危 {report.severity_counts.get('中危', 0)} / "
        f"低危 {report.severity_counts.get('低危', 0)}",
        "-" * 68,
    ]
    top = [f for f in report.sorted_findings() if f.severity >= Severity.MEDIUM][:8]
    if top:
        lines.append("主要发现：")
        for finding in top:
            lines.append(f"  [{finding.severity.label}] {finding.title}（{finding.count} 次）")
    else:
        lines.append("未发现中危及以上事件。")
    if report_paths:
        lines.append("-" * 68)
        lines.append("报告文件：")
        for path in report_paths:
            lines.append(f"  {path}")
    lines.append("=" * 68)
    return "\n".join(lines)
