"""MobHound Scanner - PDF Report Generator (v3 Professional)"""
from __future__ import annotations
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from scanner.models import Finding, ScanResult, Severity

logger = logging.getLogger("mobhound.scanner.pdf")

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate,
        Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable, KeepTogether)
    REPORTLAB_AVAILABLE = True
    PAGE_W, PAGE_H = A4
except ImportError:
    REPORTLAB_AVAILABLE = False
    PAGE_W, PAGE_H = (612, 792)  # A4 default dimensions in points
C_PURPLE   = colors.HexColor("#5b21b6") if REPORTLAB_AVAILABLE else None
C_PURPLE_L = colors.HexColor("#7c3aed") if REPORTLAB_AVAILABLE else None
C_PURPLE_BG= colors.HexColor("#f5f3ff") if REPORTLAB_AVAILABLE else None
C_CRITICAL = colors.HexColor("#dc2626") if REPORTLAB_AVAILABLE else None
C_HIGH     = colors.HexColor("#ea580c") if REPORTLAB_AVAILABLE else None
C_MEDIUM   = colors.HexColor("#d97706") if REPORTLAB_AVAILABLE else None
C_LOW      = colors.HexColor("#2563eb") if REPORTLAB_AVAILABLE else None
C_INFO     = colors.HexColor("#6b7280") if REPORTLAB_AVAILABLE else None
C_BLACK    = colors.HexColor("#111827") if REPORTLAB_AVAILABLE else None
C_GRAY     = colors.HexColor("#374151") if REPORTLAB_AVAILABLE else None
C_GRAY2    = colors.HexColor("#6b7280") if REPORTLAB_AVAILABLE else None
C_GRAY_BG  = colors.HexColor("#f9fafb") if REPORTLAB_AVAILABLE else None
C_GRAY_LINE= colors.HexColor("#e5e7eb") if REPORTLAB_AVAILABLE else None
C_WHITE    = colors.white if REPORTLAB_AVAILABLE else None

SEV_COLORS = {"CRITICAL":C_CRITICAL,"HIGH":C_HIGH,"MEDIUM":C_MEDIUM,"LOW":C_LOW,"INFO":C_INFO}
SEV_BG     = {
    "CRITICAL": colors.HexColor("#fee2e2") if REPORTLAB_AVAILABLE else None,
    "HIGH":     colors.HexColor("#ffedd5") if REPORTLAB_AVAILABLE else None,
    "MEDIUM":   colors.HexColor("#fef3c7") if REPORTLAB_AVAILABLE else None,
    "LOW":      colors.HexColor("#dbeafe") if REPORTLAB_AVAILABLE else None,
    "INFO":     colors.HexColor("#f3f4f6") if REPORTLAB_AVAILABLE else None,
}

class PDFReportGenerator:
    def __init__(self, report_dir: Path):
        self._dir = report_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def save_pdf(self, result: ScanResult) -> Optional[Path]:
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab not installed"); return None
        path = self._dir / f"scan_report_{result.scan_id[:8]}.pdf"
        self._build(result, path)
        logger.info("PDF report saved -> %s", path)
        return path

    def _build(self, result, path):
        styles = self._styles()
        doc = BaseDocTemplate(str(path), pagesize=A4,
            leftMargin=1.8*cm, rightMargin=1.8*cm,
            topMargin=2.2*cm, bottomMargin=2*cm,
            title=f"MobHound - {result.package_name or result.apk_path}",
            author="MobHound v1.0")
        frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
        doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=self._page_deco)])
        story = []
        story += self._cover(result, styles)
        story += self._summary(result, styles)
        story += self._malware_section(result, styles)
        story += self._findings_section(result, styles)
        story += self._appendix(result, styles)
        doc.build(story)

    def _page_deco(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_PURPLE)
        canvas.rect(0, PAGE_H-10*mm, PAGE_W, 10*mm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(1.8*cm, PAGE_H-6.5*mm, "MobHound v1.0 | Security Analysis Report")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(PAGE_W-1.8*cm, PAGE_H-6.5*mm, "CONFIDENTIAL")
        canvas.setStrokeColor(C_GRAY_LINE)
        canvas.setLineWidth(0.5)
        canvas.line(1.8*cm, 1.5*cm, PAGE_W-1.8*cm, 1.5*cm)
        canvas.setFillColor(C_GRAY2)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(1.8*cm, 0.9*cm, "MobHound v2.0 â€” Android Security Analysis")
        canvas.drawRightString(PAGE_W-1.8*cm, 0.9*cm, f"Page {doc.page}")
        canvas.restoreState()

    def _cover(self, result, styles):
        story = [Spacer(1, 0.8*cm)]
        logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets", "icons", "mobhound1.png"))
        if os.path.exists(logo_path):
            try:
                from reportlab.platypus import Image as RLImage
                logo_img = RLImage(logo_path, width=2.0*cm, height=2.0*cm)
                logo_table = Table([[
                    logo_img,
                    Paragraph(
                        "<font size=28 color='#5b21b6'><b>MobHound</b></font><br/>"
                        "<font size=11 color='#7c3aed'>Mobile Application Testing Tool</font>",
                        styles["cover_sub"],
                    ),
                ]], colWidths=[2.5*cm, 14*cm])
                logo_table.setStyle(TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ]))
                story.append(logo_table)
                story.append(Spacer(1, 0.4*cm))
            except Exception:
                story.append(Paragraph("MobHound", styles["cover_title"]))
        story.append(Paragraph("Android Security Analysis Report", styles["cover_title"]))
        story.append(Spacer(1, 0.3*cm))
        story.append(HRFlowable(width="100%", thickness=3, color=C_PURPLE, spaceAfter=6))
        story.append(Paragraph("Dawood University of Engineering & Technology | Dept. of Cyber Security | FYP 2025-2026", styles["cover_sub"]))
        story.append(Spacer(1, 0.8*cm))

        pkg = result.package_name or result.apk_path
        info = [["Package", pkg[:60]],["Scan ID", result.scan_id[:16]],
                ["Date", result.scan_started[:10]],["Duration", self._dur(result)]]
        it = Table(info, colWidths=[3.5*cm, 12*cm])
        it.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,-1),C_PURPLE_BG),("TEXTCOLOR",(0,0),(0,-1),C_PURPLE),
            ("TEXTCOLOR",(1,0),(1,-1),C_GRAY),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),9),("TOPPADDING",(0,0),(-1,-1),7),
            ("BOTTOMPADDING",(0,0),(-1,-1),7),("LEFTPADDING",(0,0),(0,-1),10),
            ("LEFTPADDING",(1,0),(1,-1),8),("LINEBELOW",(0,0),(-1,-2),0.5,C_GRAY_LINE),
            ("BOX",(0,0),(-1,-1),1,C_GRAY_LINE)]))
        story.append(it)
        story.append(Spacer(1, 1*cm))

        risk_c_map = {"CRITICAL_RISK":C_CRITICAL,"HIGH_RISK":C_HIGH,"MEDIUM_RISK":C_MEDIUM,"LOW_RISK":C_LOW}
        risk_bg_map = {
            "CRITICAL_RISK":colors.HexColor("#fee2e2"),"HIGH_RISK":colors.HexColor("#ffedd5"),
            "MEDIUM_RISK":colors.HexColor("#fef3c7"),"LOW_RISK":colors.HexColor("#dbeafe")}
        rc = risk_c_map.get(result.ai_risk_label, C_INFO)
        rb = risk_bg_map.get(result.ai_risk_label, colors.HexColor("#f3f4f6"))

        risk_tbl = Table([[
            Paragraph("AI RISK ASSESSMENT", styles["risk_label"]),
            Paragraph(result.ai_risk_label.replace("_"," "), styles["risk_value"]),
            Paragraph(f"Confidence: {result.ai_confidence:.0%}", styles["risk_conf"]),
        ]], colWidths=[5*cm, 6*cm, 4.5*cm])
        risk_tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),rb),("TEXTCOLOR",(1,0),(1,0),rc),
            ("BOX",(0,0),(-1,-1),2,rc),("TOPPADDING",(0,0),(-1,-1),14),
            ("BOTTOMPADDING",(0,0),(-1,-1),14),("LEFTPADDING",(0,0),(-1,-1),12),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
        story.append(risk_tbl)
        story.append(Spacer(1, 1*cm))

        by_sev = result.findings_by_severity()
        sev_rows = [[Paragraph(s, styles["sev_label"]), Paragraph(str(len(by_sev.get(s,[]))), styles["sev_count"])]
                    for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]]
        rs = []
        for i,s in enumerate(["CRITICAL","HIGH","MEDIUM","LOW","INFO"]):
            rs += [("BACKGROUND",(0,i),(-1,i),SEV_BG[s]),("TEXTCOLOR",(0,i),(0,i),SEV_COLORS[s])]
        st = Table(sev_rows, colWidths=[5*cm, 2.5*cm])
        st.setStyle(TableStyle([("FONTSIZE",(0,0),(-1,-1),10),("TOPPADDING",(0,0),(-1,-1),8),
            ("BOTTOMPADDING",(0,0),(-1,-1),8),("LEFTPADDING",(0,0),(-1,-1),12),
            ("BOX",(0,0),(-1,-1),1,C_GRAY_LINE),("LINEBELOW",(0,0),(-1,-2),0.5,C_GRAY_LINE),*rs]))
        story.append(st)
        story.append(PageBreak())
        return story

    def _summary(self, result, styles):
        story = [Paragraph("Executive Summary", styles["h1"]),
                 HRFlowable(width="100%", thickness=2, color=C_PURPLE, spaceAfter=10)]
        total = len(result.findings)
        by_sev = result.findings_by_severity()
        crit = len(by_sev.get("CRITICAL",[]))
        high = len(by_sev.get("HIGH",[]))
        story.append(Paragraph(
            f"MobHound performed a comprehensive static and dynamic security analysis. "
            f"The scan identified <b>{total} security findings</b>, including "
            f"<b>{crit} critical</b> and <b>{high} high</b> severity issues. "
            f"The AI risk classification is <b>{result.ai_risk_label.replace('_',' ')}</b> "
            f"with {result.ai_confidence:.0%} confidence.", styles["body"]))
        story.append(Spacer(1, 0.5*cm))

        stats = [["Metric","Count"],["Total Findings",str(total)],
                 ["Critical",str(crit)],["High",str(high)],
                 ["Medium",str(len(by_sev.get("MEDIUM",[])))],
                 ["Low",str(len(by_sev.get("LOW",[])))],
                 ["Static Findings",str(result.static_findings_count)],
                 ["Dynamic Findings",str(result.dynamic_findings_count)],
                 ["AI Findings",str(result.ai_findings_count)]]
        st = Table(stats, colWidths=[7*cm, 4*cm])
        st.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_PURPLE),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(0,1),(-1,-1),"Helvetica"),
            ("FONTSIZE",(0,0),(-1,-1),9),("ROWBACKGROUNDS",(0,1),(-1,-1),[C_GRAY_BG,C_WHITE]),
            ("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7),
            ("LEFTPADDING",(0,0),(-1,-1),10),("BOX",(0,0),(-1,-1),1,C_GRAY_LINE),
            ("LINEBELOW",(0,0),(-1,-2),0.5,C_GRAY_LINE)]))
        story.append(st)
        story.append(Spacer(1, 0.5*cm))

        top = [f for f in result.findings if f.severity.value in ("CRITICAL","HIGH")][:5]
        if top:
            story.append(Paragraph("Top Priority Findings", styles["h2"]))
            for i,f in enumerate(top,1):
                story.append(Paragraph(f"<b>{i}.</b>  [{f.severity.value}]  {f.title}", styles["top_item"]))
        story.append(PageBreak())
        return story

    def _malware_section(self, result, styles):
        malware = (result.metadata or {}).get("malware_analysis", {}) or {}
        story = [Paragraph("Malware Analysis", styles["h1"]),
                 HRFlowable(width="100%", thickness=2, color=C_PURPLE, spaceAfter=10)]

        if not malware:
            story.append(Paragraph("Malware analysis was not run for this scan.", styles["body"]))
            story.append(PageBreak())
            return story

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
        malware_findings = malware.get("findings", []) or []

        def _finding_value(finding, key, default):
            if isinstance(finding, dict):
                return finding.get(key, default)
            return getattr(finding, key, default)

        summary_rows = [
            ["Enabled", "Yes" if malware.get("enabled") else "No"],
            ["Prediction", str(ai_result.get("prediction", "N/A"))],
            ["Confidence", f"{float(ai_result.get('confidence', 0.0)):.0%}"],
            ["Risk", f"{risk_result.get('risk_level', 'Unknown')} ({risk_result.get('final_risk_score', 'N/A')}/100)"],
            ["YARA matches", str(len(yara_result.get("matches", []) or []))],
            ["Permission flags", str(len(flags))],
            ["Model kind", str(ai_result.get("model_kind", "N/A"))],
            ["Model path", str(bootstrap.get("model_path", "N/A"))],
        ]
        table = Table(summary_rows, colWidths=[4.2*cm, 11.3*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_PURPLE_BG),
            ("TEXTCOLOR", (0, 0), (0, -1), C_PURPLE),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_GRAY_BG, C_WHITE]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("BOX", (0, 0), (-1, -1), 1, C_GRAY_LINE),
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, C_GRAY_LINE),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.35*cm))

        if matched_rules:
            story.append(Paragraph("Matched YARA Rules", styles["h2"]))
            story.append(Paragraph(", ".join(matched_rules[:8]), styles["body"]))
        if flags:
            story.append(Spacer(1, 0.25*cm))
            story.append(Paragraph("Permission Flags", styles["h2"]))
            for flag in flags[:5]:
                story.append(Paragraph(f"• <b>{flag.get('flag')}</b>: {flag.get('detail', '')}", styles["body"]))
        reasons = ai_result.get("top_reasons", []) or []
        if reasons:
            story.append(Spacer(1, 0.25*cm))
            story.append(Paragraph("Top Reasons", styles["h2"]))
            for reason in reasons[:5]:
                story.append(Paragraph(f"• {reason}", styles["body"]))
        if malware_findings:
            story.append(Spacer(1, 0.25*cm))
            story.append(Paragraph("Malware Findings", styles["h2"]))
            for finding in malware_findings[:8]:
                title = _finding_value(finding, "title", "Malware finding")
                severity = _finding_value(finding, "severity", "INFO")
                category = _finding_value(finding, "category", "Malware")
                story.append(Paragraph(f"• <b>{title}</b> — {severity} — {category}", styles["body"]))
        story.append(PageBreak())
        return story
    def _findings_section(self, result, styles):
        story = [Paragraph("Detailed Findings", styles["h1"]),
                 HRFlowable(width="100%", thickness=2, color=C_PURPLE, spaceAfter=10)]
        for i,f in enumerate(result.findings, 1):
            story.append(KeepTogether(self._finding_card(f, i, styles)))
        return story

    def _finding_card(self, f, num, styles):
        sev = f.severity.value
        sc  = SEV_COLORS.get(sev, C_INFO)
        sb  = SEV_BG.get(sev, C_GRAY_BG)
        conf= f"{int(f.confidence*100)}%"
        block = []
        hdr = Table([[
            Paragraph(f"#{num}", styles["fn"]),
            Paragraph(sev, styles["badge"]),
            Paragraph(f.title, styles["ftitle"]),
            Paragraph(conf, styles["fconf"]),
        ]], colWidths=[1.2*cm, 2.2*cm, 11*cm, 1.1*cm])
        hdr.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),sb),("BACKGROUND",(1,0),(1,0),sc),
            ("TEXTCOLOR",(1,0),(1,0),C_WHITE),("TOPPADDING",(0,0),(-1,-1),7),
            ("BOTTOMPADDING",(0,0),(-1,-1),7),("LEFTPADDING",(0,0),(-1,-1),5),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("BOX",(0,0),(-1,-1),0.5,sc)]))
        block.append(hdr)

        rows = [("Description", f.description or "No description")]
        m = " | ".join(filter(None,[f.cwe_id, f.cve_id, f.owasp_mobile]))
        if m: rows.append(("Mappings", m))
        if f.evidence: rows.append(("Evidence", "\n".join(f.evidence[:3])))
        if f.recommendation: rows.append(("Fix", f.recommendation))

        body = Table([[Paragraph(k,styles["fkey"]),Paragraph(v,styles["fval"])] for k,v in rows],
                     colWidths=[2.2*cm,13.3*cm])
        body.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,-1),C_GRAY_BG),("TEXTCOLOR",(0,0),(0,-1),C_GRAY),
            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LEFTPADDING",(0,0),(0,-1),6),("LEFTPADDING",(1,0),(1,-1),5),
            ("VALIGN",(0,0),(-1,-1),"TOP"),("LINEBELOW",(0,0),(-1,-2),0.3,C_GRAY_LINE),
            ("BOX",(0,0),(-1,-1),0.5,C_GRAY_LINE)]))
        block.append(body)
        block.append(Spacer(1, 0.35*cm))
        return block

    def _appendix(self, result, styles):
        story = [PageBreak(), Paragraph("Appendix â€” Scan Metadata", styles["h1"]),
                 HRFlowable(width="100%", thickness=2, color=C_PURPLE, spaceAfter=10)]
        meta = [["Scan ID",result.scan_id],["APK",result.apk_path[:60]],
                ["Package",result.package_name or "unknown"],
                ["Started",result.scan_started[:19].replace("T"," ")],
                ["Finished",(result.scan_finished or "")[:19].replace("T"," ")],
                ["AI Label",result.ai_risk_label],["AI Confidence",f"{result.ai_confidence:.1%}"]]
        mt = Table(meta, colWidths=[4*cm,11.5*cm])
        mt.setStyle(TableStyle([
            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8.5),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_GRAY_BG,C_WHITE]),
            ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),8),("BOX",(0,0),(-1,-1),1,C_GRAY_LINE),
            ("LINEBELOW",(0,0),(-1,-2),0.4,C_GRAY_LINE)]))
        story.append(mt)

        if result.feature_vector:
            story.append(Spacer(1,0.5*cm))
            story.append(Paragraph("AI Feature Vector", styles["h2"]))
            fv=result.feature_vector; names=fv.feature_names(); vals=fv.to_list()
            fv_data=[["Feature","Value"]]+[[names[i],str(int(vals[i]) if vals[i]==int(vals[i]) else round(vals[i],3))] for i in range(len(names))]
            ft=Table(fv_data, colWidths=[8*cm,3*cm])
            ft.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),C_PURPLE),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(0,1),(-1,-1),"Helvetica"),
                ("FONTSIZE",(0,0),(-1,-1),8),("ROWBACKGROUNDS",(0,1),(-1,-1),[C_GRAY_BG,C_WHITE]),
                ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                ("LEFTPADDING",(0,0),(-1,-1),8),("BOX",(0,0),(-1,-1),1,C_GRAY_LINE),
                ("LINEBELOW",(0,0),(-1,-2),0.3,C_GRAY_LINE)]))
            story.append(ft)
        return story

    @staticmethod
    def _dur(result):
        try:
            from datetime import datetime
            s=datetime.fromisoformat(result.scan_started)
            e=datetime.fromisoformat(result.scan_finished) if result.scan_finished else s
            sec=int((e-s).total_seconds())
            return f"{sec}s" if sec<60 else f"{sec//60}m {sec%60}s"
        except: return "N/A"

    def _styles(self):
        def S(n,**k): return ParagraphStyle(n,**k)
        return {
            "cover_title":S("cover_title",fontSize=28,fontName="Helvetica-Bold",textColor=C_BLACK,leading=34,spaceAfter=4),
            "cover_sub":S("cover_sub",fontSize=11,fontName="Helvetica",textColor=C_GRAY2,spaceAfter=6),
            "risk_label":S("risk_label",fontSize=8,fontName="Helvetica-Bold",textColor=C_GRAY2),
            "risk_value":S("risk_value",fontSize=15,fontName="Helvetica-Bold",textColor=C_BLACK),
            "risk_conf":S("risk_conf",fontSize=9,fontName="Helvetica",textColor=C_GRAY2,alignment=TA_RIGHT),
            "sev_label":S("sev_label",fontSize=10,fontName="Helvetica-Bold",textColor=C_BLACK),
            "sev_count":S("sev_count",fontSize=10,fontName="Helvetica-Bold",textColor=C_BLACK,alignment=TA_CENTER),
            "h1":S("h1",fontSize=16,fontName="Helvetica-Bold",textColor=C_PURPLE,spaceBefore=6,spaceAfter=4),
            "h2":S("h2",fontSize=12,fontName="Helvetica-Bold",textColor=C_GRAY,spaceBefore=10,spaceAfter=4),
            "body":S("body",fontSize=9.5,fontName="Helvetica",textColor=C_GRAY,leading=15),
            "top_item":S("top_item",fontSize=9,fontName="Helvetica",textColor=C_GRAY,leading=14,spaceAfter=3),
            "fn":S("fn",fontSize=8,fontName="Helvetica-Bold",textColor=C_GRAY2,alignment=TA_CENTER),
            "badge":S("badge",fontSize=8,fontName="Helvetica-Bold",textColor=C_WHITE,alignment=TA_CENTER),
            "ftitle":S("ftitle",fontSize=9,fontName="Helvetica-Bold",textColor=C_BLACK,leading=12),
            "fconf":S("fconf",fontSize=8,fontName="Helvetica",textColor=C_GRAY2,alignment=TA_RIGHT),
            "fkey":S("fkey",fontSize=8,fontName="Helvetica-Bold",textColor=C_GRAY),
            "fval":S("fval",fontSize=8,fontName="Helvetica",textColor=C_BLACK,leading=12),
        }
