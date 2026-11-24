"""Windows 日志深度安全审计工具包。

模块划分::

    models      数据模型（事件 / 发现 / 报告）
    knowledge   事件 ID 知识库与可疑模式
    parser      Windows 事件 XML 解析
    collectors  WinRM / 本地 / 离线日志采集
    rules_*     各类入侵痕迹检测规则
    iis          IIS W3C 日志解析与 Web 攻击检测
    engine      规则编排、风险评估、IOC 与时间线
    report      Word / Markdown / JSON / HTML 报告
    demo        内置演示数据（无目标主机也能验证完整流程）
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
