"""
MobHound Scanner - Report Generator
======================================
Generates JSON and HTML reports from ScanResult.
"""

from __future__ import annotations

import json
import logging
import html as html_module
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from scanner.models import Finding, ScanResult, Severity

logger = logging.getLogger("mobhound.scanner.report")

SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

SEVERITY_BADGE: Dict[str, str] = {
    "CRITICAL": "ðŸ”´",
    "HIGH":     "ðŸŸ ",
    "MEDIUM":   "ðŸŸ¡",
    "LOW":      "ðŸ”µ",
    "INFO":     "âšª",
}


class ReportGenerator:
    """Generate JSON and HTML reports from a ScanResult."""

    def __init__(self, report_dir: Path):
        self._dir = report_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_json(self, result: ScanResult) -> Path:
        path = self._dir / f"scan_report_{result.scan_id[:8]}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info("JSON report saved to %s", path)
        return path

    def save_html(self, result: ScanResult) -> Path:
        path = self._dir / f"scan_report_{result.scan_id[:8]}.html"
        html = self._build_html(result)
        path.write_text(html, encoding="utf-8")
        logger.info("HTML report saved to %s", path)
        return path

    # â”€â”€â”€ HTML builder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _build_html(self, result: ScanResult) -> str:
        by_sev   = result.findings_by_severity()
        total    = len(result.findings)
        pkg      = result.package_name or result.apk_path
        malware  = self._malware_summary(result)

        counts = {s: len(by_sev[s]) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}

        findings_html = "\n".join(
            self._finding_card(f, i + 1)
            for i, f in enumerate(result.findings)
        )
        malware_html = self._malware_section_html(malware)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>MobHound Scan Report â€“ {pkg}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #f1f5f9; --text2: #94a3b8; --border: #475569;
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #2563eb; --info: #6b7280;
    --accent: #7c3aed;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; padding: 24px; }}
  h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 4px; }}
  .subtitle {{ color: var(--text2); margin-bottom: 24px; font-size: 0.9rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: var(--surface); border-radius: 12px; padding: 16px; text-align: center; border: 1px solid var(--border); }}
  .stat-num {{ font-size: 2rem; font-weight: 700; }}
  .stat-label {{ color: var(--text2); font-size: 0.8rem; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .c {{ color: var(--critical); }} .h {{ color: var(--high); }}
  .m {{ color: var(--medium); }} .l {{ color: var(--low); }}
  .i {{ color: var(--info); }}

  .ai-banner {{ background: var(--surface); border: 1px solid var(--accent); border-radius: 12px;
    padding: 16px 20px; margin-bottom: 28px; display: flex; align-items: center; gap: 16px; }}
  .ai-label {{ font-size: 1.1rem; font-weight: 700; color: var(--accent); }}
  .ai-conf {{ color: var(--text2); font-size: 0.85rem; }}

  .finding {{ background: var(--surface); border-radius: 12px; border: 1px solid var(--border);
    margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 18px;
    cursor: pointer; user-select: none; }}
  .finding-header:hover {{ background: var(--surface2); }}
  .badge {{ padding: 3px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700;
    color: #fff; text-transform: uppercase; }}
  .badge-CRITICAL {{ background: var(--critical); }}
  .badge-HIGH     {{ background: var(--high); }}
  .badge-MEDIUM   {{ background: var(--medium); }}
  .badge-LOW      {{ background: var(--low); }}
  .badge-INFO     {{ background: var(--info); }}
  .finding-num {{ color: var(--text2); font-size: 0.8rem; min-width: 28px; }}
  .finding-title {{ flex: 1; font-weight: 600; }}
  .finding-body {{ padding: 0 18px 16px; border-top: 1px solid var(--border); display: none; }}
  .finding-body.open {{ display: block; }}
  .section {{ margin-top: 14px; }}
  .section-title {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text2); margin-bottom: 6px; }}
  p {{ color: var(--text); line-height: 1.6; font-size: 0.9rem; }}
  pre {{ background: #0f172a; border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 14px; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap;
    color: #a5f3fc; margin-top: 4px; }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
    background: var(--surface2); color: var(--text2); margin: 2px; }}
  .conf-bar {{ height: 6px; border-radius: 3px; background: var(--surface2); margin-top: 4px; }}
  .conf-fill {{ height: 6px; border-radius: 3px; background: var(--accent); }}
  .filter-bar {{ margin-bottom: 20px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 6px 14px; border-radius: 8px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text2); cursor: pointer; font-size: 0.82rem; }}
  .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}
  .source-tag {{ font-size: 0.7rem; padding: 2px 7px; border-radius: 4px;
    background: var(--surface2); color: var(--text2); }}
  footer {{ margin-top: 40px; text-align: center; color: var(--text2); font-size: 0.8rem; }}
</style>
</head>
<body>

<h1>ðŸ¾ MobHound Scan Report</h1>
<div class="subtitle">
  Package: <strong>{pkg}</strong> &nbsp;|&nbsp;
  Scan ID: {result.scan_id[:8]} &nbsp;|&nbsp;
  {result.scan_started[:10]}
</div>

<!-- AI Banner -->
<div class="ai-banner">
  <div>
    <div class="ai-label">ðŸ¤– AI Risk: {result.ai_risk_label}</div>
    <div class="ai-conf">Model confidence: {result.ai_confidence:.0%}</div>
  </div>
  <div style="flex:1"></div>
  <div style="text-align:right">
    <div style="font-size:0.85rem;color:var(--text2)">Total Findings</div>
    <div style="font-size:1.8rem;font-weight:700">{total}</div>
  </div>
</div>

<!-- Summary grid -->
<div class="grid">
  <div class="stat-card"><div class="stat-num c">{counts["CRITICAL"]}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card"><div class="stat-num h">{counts["HIGH"]}</div><div class="stat-label">High</div></div>
  <div class="stat-card"><div class="stat-num m">{counts["MEDIUM"]}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card"><div class="stat-num l">{counts["LOW"]}</div><div class="stat-label">Low</div></div>
  <div class="stat-card"><div class="stat-num" style="color:var(--accent)">{result.static_findings_count}</div><div class="stat-label">Static</div></div>
  <div class="stat-card"><div class="stat-num" style="color:#10b981">{result.dynamic_findings_count}</div><div class="stat-label">Dynamic</div></div>
</div>

<!-- Malware Analysis -->
{malware_html}

<!-- Filter bar -->
<div class="filter-bar">
  <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total})</button>
  <button class="filter-btn" onclick="filterFindings('CRITICAL')">ðŸ”´ Critical ({counts["CRITICAL"]})</button>
  <button class="filter-btn" onclick="filterFindings('HIGH')">ðŸŸ  High ({counts["HIGH"]})</button>
  <button class="filter-btn" onclick="filterFindings('MEDIUM')">ðŸŸ¡ Medium ({counts["MEDIUM"]})</button>
  <button class="filter-btn" onclick="filterFindings('LOW')">ðŸ”µ Low ({counts["LOW"]})</button>
</div>

<!-- Findings -->
<div id="findings-list">
{findings_html}
</div>

<footer>
  Generated by MobHound v2.0 &nbsp;|&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
</footer>

<script>
function toggleFinding(id) {{
  const body = document.getElementById('body-' + id);
  body.classList.toggle('open');
}}
function filterFindings(severity) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {{
    if (severity === 'ALL' || f.dataset.severity === severity) {{
      f.style.display = '';
    }} else {{
      f.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>"""

    def _malware_summary(self, result: ScanResult) -> Dict[str, object]:
        malware = (result.metadata or {}).get("malware_analysis", {}) or {}
        ai_result = malware.get("ai_result", {}) or {}
        risk_result = malware.get("risk_result", {}) or {}
        yara_result = malware.get("yara_result", {}) or {}
        permission_result = malware.get("permission_result", {}) or {}
        bootstrap = malware.get("bootstrap", {}) or {}
        flags = (permission_result.get("policy_evaluation") or {}).get("flags", []) or []
        matched_rules = sorted({
            match.get("rule", "")
            for match in yara_result.get("matches", []) or []
            if match.get("rule")
        })
        return {
            "available": bool(malware),
            "enabled": bool(malware.get("enabled")),
            "prediction": ai_result.get("prediction"),
            "confidence": ai_result.get("confidence"),
            "risk_score": risk_result.get("final_risk_score"),
            "risk_level": risk_result.get("risk_level"),
            "yara_match_count": len(yara_result.get("matches", []) or []),
            "matched_rules": matched_rules,
            "permission_flag_count": len(flags),
            "permission_flags": flags,
            "top_reasons": ai_result.get("top_reasons", []),
            "model_kind": ai_result.get("model_kind"),
            "model_path": bootstrap.get("model_path"),
            "train_result": bootstrap.get("train_result"),
            "findings": malware.get("findings", []) or [],
        }

    def _malware_section_html(self, malware: Dict[str, object]) -> str:
        if not malware.get("available"):
            return """
<div class="ai-banner" style="border-color:var(--border);">
  <div>
    <div class="ai-label">🧬 Malware Analysis</div>
    <div class="ai-conf">This scan did not run the malware-analysis pipeline.</div>
  </div>
</div>"""

        flags = malware.get("permission_flags", []) or []
        reasons = malware.get("top_reasons", []) or []
        rules = malware.get("matched_rules", []) or []
        findings = malware.get("findings", []) or []

        def _finding_value(finding, key, default):
            if isinstance(finding, dict):
                return finding.get(key, default)
            return getattr(finding, key, default)

        flag_text = ", ".join(flag.get("flag", "") for flag in flags[:4]) or "none"
        reason_text = "<br/>".join(reasons[:4]) or "No explanation returned."
        rules_text = ", ".join(rules[:6]) or "none"
        findings_text = "".join(
            f"<li><b>{html_module.escape(str(_finding_value(finding, 'title', 'Malware finding')))}</b>"
            f" — {html_module.escape(str(_finding_value(finding, 'severity', 'INFO')))}"
            f" — {html_module.escape(str(_finding_value(finding, 'category', 'Malware')))}</li>"
            for finding in findings[:8]
        ) or "<li>None</li>"
        return f"""
<div class="ai-banner" style="border-color:var(--accent);">
  <div>
    <div class="ai-label">🧬 Malware Analysis: {malware.get('prediction') or 'unknown'}</div>
    <div class="ai-conf">Confidence: {float(malware.get('confidence') or 0.0):.0%} | Risk: {malware.get('risk_level') or 'Unknown'} ({malware.get('risk_score') if malware.get('risk_score') is not None else 'N/A'}/100)</div>
  </div>
  <div style="flex:1"></div>
  <div style="text-align:right">
    <div style="font-size:0.85rem;color:var(--text2)">YARA Matches</div>
    <div style="font-size:1.8rem;font-weight:700">{malware.get('yara_match_count', 0)}</div>
  </div>
</div>
<div class="finding" style="margin-bottom:28px;">
  <div class="finding-header" style="cursor:default;">
    <span class="finding-title">Malware details</span>
    <span class="source-tag">malware</span>
  </div>
  <div class="finding-body open" style="display:block;">
    <div class="section"><div class="section-title">Model</div><p>{malware.get('model_kind') or 'N/A'}</p></div>
    <div class="section"><div class="section-title">Prediction</div><p>{malware.get('prediction') or 'N/A'} &nbsp;({float(malware.get('confidence') or 0.0):.0%})</p></div>
    <div class="section"><div class="section-title">Matched YARA Rules</div><p>{rules_text}</p></div>
    <div class="section"><div class="section-title">Permission Flags</div><p>{flag_text}</p></div>
    <div class="section"><div class="section-title">Top Reasons</div><p>{reason_text}</p></div>
    <div class="section"><div class="section-title">Malware Findings</div><ul style="margin-left:18px;">{findings_text}</ul></div>
  </div>
</div>"""
    def _finding_card(self, f: Finding, num: int) -> str:
        sev     = f.severity.value
        conf_w  = int(f.confidence * 100)
        tags    = " ".join(f'<span class="pill">{t}</span>' for t in f.tags)
        evidence= "\n".join(f.evidence[:6])
        rec     = f.recommendation or "No recommendation provided."
        cwe     = f'<span class="pill">{f.cwe_id}</span>' if f.cwe_id else ""
        owasp   = f'<span class="pill">{f.owasp_mobile}</span>' if f.owasp_mobile else ""
        source  = f'<span class="source-tag">{f.source.value}</span>'
        files   = " ".join(
            f'<span class="pill">{Path(fp).name}</span>'
            for fp in f.affected_files[:4]
        )

        return f"""
<div class="finding" id="finding-{num}" data-severity="{sev}">
  <div class="finding-header" onclick="toggleFinding({num})">
    <span class="finding-num">#{num}</span>
    <span class="badge badge-{sev}">{sev}</span>
    <span class="finding-title">{f.title}</span>
    {source}
  </div>
  <div class="finding-body" id="body-{num}">

    <div class="section">
      <div class="section-title">Description</div>
      <p>{f.description}</p>
    </div>

    <div class="section">
      <div class="section-title">Confidence &nbsp;{conf_w}%</div>
      <div class="conf-bar"><div class="conf-fill" style="width:{conf_w}%"></div></div>
    </div>

    {'<div class="section"><div class="section-title">Mappings</div>' + cwe + owasp + '</div>' if cwe or owasp else ''}

    {'<div class="section"><div class="section-title">Affected Files</div>' + files + '</div>' if files else ''}

    {'<div class="section"><div class="section-title">Evidence</div><pre>' + evidence + '</pre></div>' if evidence else ''}

    <div class="section">
      <div class="section-title">Recommendation</div>
      <p>{rec}</p>
    </div>

    {'<div class="section"><div class="section-title">Tags</div>' + tags + '</div>' if tags else ''}

  </div>
</div>"""


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Unified reporter â€” JSON + HTML + PDF
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class UnifiedReporter:
    """
    Generates all report formats in one call.
    Usage:
        reporter = UnifiedReporter(report_dir)
        paths    = reporter.save_all(result)
        # paths = {"json": Path, "html": Path, "pdf": Path | None}
    """

    def __init__(self, report_dir: Path):
        from scanner.reports.pdf_generator import PDFReportGenerator
        self._json_html = ReportGenerator(report_dir)
        self._pdf       = PDFReportGenerator(report_dir)

    def save_all(self, result) -> dict:
        paths = {}
        paths["json"] = self._json_html.save_json(result)
        paths["html"] = self._json_html.save_html(result)
        paths["pdf"]  = self._pdf.save_pdf(result)
        return paths
