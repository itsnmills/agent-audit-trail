#!/usr/bin/env python3
"""
PDF and Markdown report generation for HIPAA compliance assessments.

Produces two report formats:
  1. PDF  — Formal audit report suitable for CISO, board presentation, OCR audit response
  2. Markdown — Machine-readable format for git tracking and developer consumption

Report structure follows ISACA AI Audit framework:
  1. Executive Summary
  2. Scope and Regulatory Context
  3. Audit Methodology
  4. Agent Inventory
  5. Action Telemetry
  6. Compliance Control Assessment (full control-by-control table)
  7. Violations Summary
  8. NIST AI RMF Alignment
  9. Gap Analysis and Remediation Roadmap
  10. Recommendations

HIPAA grounding:
  §164.316(b) — Documentation: policies and procedures must be documented
  §164.316(b)(2)(i) — Retained for 6 years
  §164.308(a)(1) — Risk analysis must be documented
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import ORGANIZATION_NAME, REPORT_OUTPUT_DIR
from .models import ComplianceControl, ComplianceReport, ViolationRecord

logger = logging.getLogger(__name__)

# Severity colors for PDF
_SEVERITY_COLORS = {
    "critical":      (0.85, 0.15, 0.15),  # Red
    "high":          (0.90, 0.45, 0.10),  # Orange
    "medium":        (0.95, 0.75, 0.10),  # Yellow
    "low":           (0.20, 0.60, 0.20),  # Green
    "informational": (0.40, 0.60, 0.80),  # Blue
}

_STATUS_COLORS = {
    "compliant":            (0.18, 0.55, 0.18),  # Green
    "partially_compliant":  (0.85, 0.60, 0.10),  # Amber
    "non_compliant":        (0.80, 0.15, 0.15),  # Red
    "not_assessed":         (0.55, 0.55, 0.55),  # Gray
}

_RATING_COLORS = {
    "Compliant":                         (0.18, 0.55, 0.18),
    "Substantially Compliant":           (0.30, 0.65, 0.30),
    "Partially Compliant":               (0.85, 0.60, 0.10),
    "Non-Compliant":                     (0.80, 0.15, 0.15),
    "Critical — Immediate Action Required": (0.60, 0.05, 0.05),
}


class ReportGenerator:
    """
    Generates HIPAA compliance audit reports in PDF and Markdown format.

    Usage::

        generator = ReportGenerator(output_dir=Path("reports"))
        pdf_path = generator.generate_pdf(report, controls, violations)
        md_path  = generator.generate_markdown(report, controls, violations)
    """

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else REPORT_OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # PDF Report
    # ------------------------------------------------------------------

    def generate_pdf(
        self,
        report: ComplianceReport,
        controls: list[ComplianceControl],
        violations: list[ViolationRecord],
        filename: Optional[str] = None,
    ) -> Path:
        """
        Generate a formal PDF compliance report.

        Requires reportlab. Falls back to Markdown if reportlab is unavailable.

        §164.316(b): This PDF serves as the formal documentation artifact
        required for HIPAA compliance recordkeeping (6-year retention).

        Args:
            report:     ComplianceReport with summary data.
            controls:   Assessed ComplianceControl list.
            violations: ViolationRecord list for the period.
            filename:   Output filename (auto-generated if None).

        Returns:
            Path to the generated PDF file.
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak, HRFlowable,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        except ImportError:
            logger.warning("reportlab not installed. Falling back to Markdown report.")
            return self.generate_markdown(report, controls, violations, filename)

        if filename is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"hipaa_compliance_report_{ts}.pdf"
        output_path = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()
        # Custom styles
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=20,
            spaceAfter=6,
            textColor=colors.HexColor("#1a2744"),
        )
        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=11,
            spaceAfter=12,
            textColor=colors.HexColor("#4a5568"),
        )
        h1_style = ParagraphStyle(
            "H1",
            parent=styles["Heading1"],
            fontSize=14,
            spaceBefore=18,
            spaceAfter=6,
            textColor=colors.HexColor("#1a2744"),
            borderPad=4,
        )
        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=12,
            spaceBefore=12,
            spaceAfter=4,
            textColor=colors.HexColor("#2d3748"),
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            spaceAfter=4,
            leading=13,
        )
        small_style = ParagraphStyle(
            "Small",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
        )
        finding_style = ParagraphStyle(
            "Finding",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            leftIndent=10,
        )

        story = []

        # ---- Cover ----
        story.append(Spacer(1, 0.5 * inch))
        story.append(Paragraph("AI AGENT AUDIT TRAIL", title_style))
        story.append(Paragraph("HIPAA Compliance Assessment Report", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a2744")))
        story.append(Spacer(1, 0.2 * inch))

        cover_data = [
            ["Organization", report.organization_name],
            ["Report Period", f"{report.report_period_start[:10]} to {report.report_period_end[:10]}"],
            ["Generated", report.generated_at[:19].replace("T", " ") + " UTC"],
            ["Report ID", report.report_id],
            ["Overall Score", f"{report.overall_score:.1f} / 100"],
            ["Compliance Rating", report.overall_rating],
        ]
        cover_table = Table(cover_data, colWidths=[2.0 * inch, 4.5 * inch])
        cover_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf2f7")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(cover_table)
        story.append(Spacer(1, 0.2 * inch))

        # Rating box
        rating_color = _RATING_COLORS.get(report.overall_rating, (0.5, 0.5, 0.5))
        rl_color = colors.Color(*rating_color)
        rating_data = [[f"Overall Compliance Rating: {report.overall_rating}  ({report.overall_score:.1f}/100)"]]
        rating_table = Table(rating_data, colWidths=[6.5 * inch])
        rating_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), rl_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 13),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 12),
            ("ROUNDEDCORNERS", [4]),
        ]))
        story.append(rating_table)
        story.append(PageBreak())

        # ---- Section 1: Executive Summary ----
        story.append(Paragraph("1. Executive Summary", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))

        summary_text = (
            f"This report presents the findings of the HIPAA Security Rule compliance assessment "
            f"for AI agents operating within {report.organization_name}'s healthcare network. "
            f"The assessment covers {report.controls_assessed} compliance controls spanning "
            f"HIPAA §164.312 Technical Safeguards, §164.502(b) Minimum Necessary, "
            f"NIST AI RMF functions, and 2025 HIPAA Security Rule amendments.<br/><br/>"
            f"During the assessment period, <b>{report.total_agents} AI agents</b> were inventoried, "
            f"generating <b>{report.total_actions:,} audit events</b> across "
            f"<b>{report.phi_records_accessed:,} patient records</b>. "
            f"The overall compliance score is <b>{report.overall_score:.1f}/100</b> "
            f"(<b>{report.overall_rating}</b>).<br/><br/>"
            f"<b>{report.total_violations} compliance violations</b> were detected: "
            f"{report.violations_by_severity.get('critical', 0)} critical, "
            f"{report.violations_by_severity.get('high', 0)} high, "
            f"{report.violations_by_severity.get('medium', 0)} medium, "
            f"{report.violations_by_severity.get('low', 0)} low. "
            f"<b>{report.open_violations} violations remain open</b> and require remediation."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 0.2 * inch))

        # Key metrics grid
        metrics = [
            ["Metric", "Value", "Metric", "Value"],
            ["Agents Inventoried", str(report.total_agents),
             "Actions Logged", f"{report.total_actions:,}"],
            ["Controls Assessed", str(report.controls_assessed),
             "Controls Compliant", str(report.controls_compliant)],
            ["Controls Non-Compliant", str(report.controls_non_compliant),
             "PHI Records Accessed", f"{report.phi_records_accessed:,}"],
            ["Total Violations", str(report.total_violations),
             "Open Violations", str(report.open_violations)],
            ["Critical Violations", str(report.violations_by_severity.get("critical", 0)),
             "Remediated Violations", str(report.remediated_violations)],
        ]
        metrics_table = Table(metrics, colWidths=[2.0 * inch, 1.25 * inch, 2.0 * inch, 1.25 * inch])
        metrics_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2744")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 1), (2, -1), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(metrics_table)
        story.append(PageBreak())

        # ---- Section 2: Scope and Regulatory Context ----
        story.append(Paragraph("2. Scope and Regulatory Context", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Paragraph(
            "This assessment evaluates compliance with the following regulatory frameworks:",
            body_style,
        ))
        reg_data = [
            ["Framework", "Scope", "Key Requirements Assessed"],
            ["HIPAA Security Rule\n§164.312", "Technical Safeguards",
             "Access Control, Audit Controls, Integrity,\nAuthentication, Transmission Security"],
            ["HIPAA Privacy Rule\n§164.502(b)", "Minimum Necessary",
             "PHI access scope, operation-level enforcement,\naccess justification"],
            ["2025 HIPAA Amendments", "Updated Requirements",
             "Encryption now mandatory, FIPS 140-3 required,\nMFA codified, BA direct liability"],
            ["NIST AI RMF 1.0", "AI Risk Management",
             "Govern, Map, Measure, Manage functions\nfor healthcare AI systems"],
            ["ONC HTI-1", "AI Transparency",
             "FAVES principles for predictive DSIs\nin certified health IT"],
            ["FDA AI Guidance 2025", "AI/ML Validation",
             "ALCOA+, GMLP, traceability,\nbias mitigation, drift detection"],
        ]
        reg_table = Table(reg_data, colWidths=[1.5 * inch, 1.4 * inch, 3.6 * inch])
        reg_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2744")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(reg_table)
        story.append(PageBreak())

        # ---- Section 3: Control Assessment ----
        story.append(Paragraph("3. Compliance Control Assessment", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Paragraph(
            f"Full assessment of {len(controls)} compliance controls. "
            "Required controls are weighted 2× in scoring. Status: "
            "✓ Compliant | ⚠ Partial | ✗ Non-Compliant | — Not Assessed",
            body_style,
        ))
        story.append(Spacer(1, 0.1 * inch))

        ctrl_header = ["ID", "HIPAA §", "Standard", "Type", "Status", "Score"]
        ctrl_data = [ctrl_header]
        for c in controls:
            status_symbol = {
                "compliant": "✓ Compliant",
                "partially_compliant": "⚠ Partial",
                "non_compliant": "✗ Non-Compliant",
                "not_assessed": "— N/A",
            }.get(c.status, c.status)
            ctrl_data.append([
                c.control_id,
                c.hipaa_section,
                Paragraph(c.hipaa_standard[:55], small_style),
                c.requirement_type.title(),
                status_symbol,
                f"{c.risk_score:.1f}",
            ])

        ctrl_table = Table(ctrl_data, colWidths=[0.6*inch, 1.1*inch, 2.4*inch, 0.8*inch, 1.1*inch, 0.45*inch])
        ctrl_style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2744")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ])
        # Color-code status column
        for row_idx, c in enumerate(controls, 1):
            status_color = _STATUS_COLORS.get(c.status, (0.5, 0.5, 0.5))
            rl_sc = colors.Color(*status_color)
            ctrl_style.add("TEXTCOLOR", (4, row_idx), (4, row_idx), rl_sc)
            ctrl_style.add("FONTNAME", (4, row_idx), (4, row_idx), "Helvetica-Bold")
            if c.status == "non_compliant":
                ctrl_style.add("BACKGROUND", (4, row_idx), (4, row_idx), colors.HexColor("#fff5f5"))
        ctrl_table.setStyle(ctrl_style)
        story.append(ctrl_table)
        story.append(PageBreak())

        # ---- Section 4: Gap Analysis ----
        story.append(Paragraph("4. Gap Analysis and Remediation Roadmap", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        non_compliant = [c for c in controls if c.status in {"non_compliant", "partially_compliant"}]
        non_compliant.sort(key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(c.severity, 5))

        if non_compliant:
            for i, c in enumerate(non_compliant[:15], 1):
                sev_color = colors.Color(*_SEVERITY_COLORS.get(c.severity, (0.5, 0.5, 0.5)))
                story.append(Paragraph(
                    f"<b>GAP-{i:02d}: {c.control_id} — {c.hipaa_standard}</b>",
                    h2_style,
                ))
                gap_detail = [
                    ["HIPAA Section", c.hipaa_section, "Severity", c.severity.upper()],
                    ["Status", c.status.replace("_", " ").title(), "Risk Score", f"{c.risk_score:.1f}/10"],
                    ["Requirement", c.requirement_type.title(), "NIST CSF", c.nist_csf_mapping or "—"],
                ]
                gd_table = Table(gap_detail, colWidths=[1.2*inch, 2.0*inch, 1.2*inch, 2.1*inch])
                gd_table.setStyle(TableStyle([
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7fafc")),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(gd_table)
                story.append(Paragraph(f"<b>Finding:</b> {c.finding}", finding_style))
                story.append(Spacer(1, 0.05 * inch))
        else:
            story.append(Paragraph("No gaps identified — all assessed controls are compliant.", body_style))
        story.append(PageBreak())

        # ---- Section 5: NIST AI RMF ----
        story.append(Paragraph("5. NIST AI RMF Alignment", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        rmf = report.nist_ai_rmf_scores
        if rmf:
            rmf_data = [["NIST AI RMF Function", "Score", "Rating"]]
            for func, score in rmf.items():
                pct = f"{score * 100:.1f}%"
                rating = "Strong" if score >= 0.9 else "Adequate" if score >= 0.7 else "Needs Improvement" if score >= 0.5 else "Deficient"
                rmf_data.append([func.title(), pct, rating])
            rmf_table = Table(rmf_data, colWidths=[2.5 * inch, 1.5 * inch, 2.5 * inch])
            rmf_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2744")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(rmf_table)

        # ---- Section 6: Recommendations ----
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("6. Priority Recommendations", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        if report.recommendations:
            rec_data = [["#", "Recommendation", "HIPAA §", "Effort", "Severity"]]
            for r in report.recommendations[:10]:
                rec_data.append([
                    str(r.get("priority", "")),
                    Paragraph(r.get("title", ""), small_style),
                    r.get("hipaa_ref", ""),
                    r.get("effort", "").title(),
                    r.get("severity", "").upper(),
                ])
            rec_table = Table(rec_data, colWidths=[0.3*inch, 3.0*inch, 1.2*inch, 0.7*inch, 0.8*inch])
            rec_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2744")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(rec_table)

        # Footer disclaimer
        story.append(Spacer(1, 0.3 * inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Paragraph(
            f"<i>Generated by AI Agent Audit Trail Generator | Report ID: {report.report_id} | "
            f"Per §164.316(b)(2)(i), this document must be retained for 6 years. | "
            f"Confidential — HIPAA Compliance Documentation</i>",
            ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7, textColor=colors.HexColor("#718096")),
        ))

        doc.build(story)
        logger.info("PDF report generated: %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Markdown Report
    # ------------------------------------------------------------------

    def generate_markdown(
        self,
        report: ComplianceReport,
        controls: list[ComplianceControl],
        violations: list[ViolationRecord],
        filename: Optional[str] = None,
    ) -> Path:
        """
        Generate a Markdown compliance report.

        The Markdown format is suitable for git tracking, developer consumption,
        and rendering in GitHub, Confluence, or documentation sites.

        Args:
            report:     ComplianceReport summary.
            controls:   Assessed controls.
            violations: Violations for the period.
            filename:   Output filename (auto-generated if None).

        Returns:
            Path to the generated .md file.
        """
        if filename is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"hipaa_compliance_report_{ts}.md"
        output_path = self.output_dir / filename

        lines: list[str] = []

        def h(level: int, text: str) -> None:
            lines.append(f"\n{'#' * level} {text}\n")

        def p(text: str) -> None:
            lines.append(text)
            lines.append("")

        def table(headers: list[str], rows: list[list[str]]) -> None:
            lines.append("| " + " | ".join(headers) + " |")
            lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
            for row in rows:
                lines.append("| " + " | ".join(str(c) for c in row) + " |")
            lines.append("")

        # Header
        lines.append(f"# AI Agent Audit Trail — HIPAA Compliance Report")
        lines.append(f"## {report.organization_name}")
        lines.append("")
        lines.append(f"**Report Period:** {report.report_period_start[:10]} to {report.report_period_end[:10]}")
        lines.append(f"**Generated:** {report.generated_at[:19].replace('T', ' ')} UTC")
        lines.append(f"**Report ID:** `{report.report_id}`")
        lines.append("")
        lines.append(f"> **Overall Compliance Score: {report.overall_score:.1f}/100 — {report.overall_rating}**")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Table of Contents
        h(2, "Table of Contents")
        for i, section in enumerate([
            "Executive Summary", "Regulatory Scope", "Agent Inventory",
            "Action Telemetry", "Compliance Control Assessment",
            "Violations", "NIST AI RMF Alignment", "Gap Analysis",
            "Recommendations",
        ], 1):
            lines.append(f"{i}. [{section}](#{section.lower().replace(' ', '-')})")
        lines.append("")

        # 1. Executive Summary
        h(2, "1. Executive Summary")
        p(
            f"This report presents the HIPAA Security Rule compliance assessment for AI agents "
            f"operating within **{report.organization_name}**. The assessment evaluated "
            f"**{report.controls_assessed} compliance controls** across HIPAA §164.312 Technical "
            f"Safeguards, §164.502(b) Minimum Necessary, NIST AI RMF, and 2025 HIPAA amendments."
        )
        table(
            ["Metric", "Value"],
            [
                ["Overall Score", f"{report.overall_score:.1f}/100"],
                ["Overall Rating", report.overall_rating],
                ["AI Agents Inventoried", str(report.total_agents)],
                ["Total Actions Logged", f"{report.total_actions:,}"],
                ["PHI Records Accessed", f"{report.phi_records_accessed:,}"],
                ["Controls Assessed", str(report.controls_assessed)],
                ["Controls Compliant", f"{report.controls_compliant} ({100*report.compliance_rate:.1f}%)"],
                ["Controls Non-Compliant", str(report.controls_non_compliant)],
                ["Controls Partially Compliant", str(report.controls_partially_compliant)],
                ["Total Violations", str(report.total_violations)],
                ["Open Violations", str(report.open_violations)],
                ["Critical Violations", str(report.violations_by_severity.get("critical", 0))],
            ],
        )

        # 2. Regulatory Scope
        h(2, "2. Regulatory Scope")
        table(
            ["Framework", "Key Sections Assessed"],
            [
                ["HIPAA Security Rule", "§164.312(a) Access Control, §164.312(b) Audit Controls, §164.312(c) Integrity, §164.312(d) Authentication, §164.312(e) Transmission Security"],
                ["HIPAA Privacy Rule", "§164.502(b) Minimum Necessary"],
                ["HIPAA 2025 Amendments", "Encryption mandatory, FIPS 140-3 required, MFA codified, BA direct liability"],
                ["NIST AI RMF 1.0", "Govern, Map, Measure, Manage functions"],
                ["ONC HTI-1", "FAVES principles for predictive DSIs"],
                ["FDA AI Guidance 2025", "ALCOA+, GMLP, traceability, bias mitigation"],
            ],
        )

        # 3. Agent Inventory
        h(2, "3. Agent Inventory")
        table(
            ["Metric", "Count"],
            [
                ["Total Agents", str(report.total_agents)],
                *[
                    [f"Risk Tier: {tier.title()}", str(cnt)]
                    for tier, cnt in sorted(report.agents_by_risk_tier.items())
                ],
                *[
                    [f"Status: {status.title()}", str(cnt)]
                    for status, cnt in sorted(report.agents_by_status.items())
                ],
            ],
        )

        # 4. Action Telemetry
        h(2, "4. Action Telemetry")
        table(
            ["Operation", "Count"],
            [[op, str(cnt)] for op, cnt in sorted(report.actions_by_operation.items(), key=lambda x: -x[1])],
        )
        if report.actions_by_phi_category:
            h(3, "PHI Categories Accessed")
            table(
                ["PHI Category", "Occurrences"],
                [[cat, str(cnt)] for cat, cnt in sorted(report.actions_by_phi_category.items(), key=lambda x: -x[1])],
            )

        # 5. Compliance Control Assessment
        h(2, "5. Compliance Control Assessment")
        status_emoji = {
            "compliant": "✅",
            "partially_compliant": "⚠️",
            "non_compliant": "❌",
            "not_assessed": "➖",
        }
        table(
            ["Control ID", "HIPAA §", "Standard", "Type", "Status", "Risk Score", "Finding"],
            [
                [
                    c.control_id,
                    c.hipaa_section,
                    c.hipaa_standard[:50] + ("…" if len(c.hipaa_standard) > 50 else ""),
                    c.requirement_type,
                    status_emoji.get(c.status, c.status),
                    f"{c.risk_score:.1f}",
                    (c.finding[:80] + "…") if c.finding and len(c.finding) > 80 else (c.finding or "—"),
                ]
                for c in controls
            ],
        )

        # 6. Violations
        h(2, "6. Violations")
        h(3, "By Severity")
        table(
            ["Severity", "Count"],
            [
                [s.title(), str(report.violations_by_severity.get(s, 0))]
                for s in ["critical", "high", "medium", "low"]
            ],
        )
        h(3, "By Type")
        if report.violations_by_type:
            table(
                ["Violation Type", "Count"],
                [[vt.replace("_", " ").title(), str(cnt)]
                 for vt, cnt in sorted(report.violations_by_type.items(), key=lambda x: -x[1])],
            )

        # Recent critical violations
        critical_v = [v for v in violations if v.severity == "critical"][:10]
        if critical_v:
            h(3, "Critical Violations")
            for v in critical_v:
                lines.append(f"#### {v.violation_type.replace('_', ' ').title()}")
                lines.append(f"- **Agent:** `{v.agent_id}`")
                lines.append(f"- **Action ID:** `{v.action_id}`")
                lines.append(f"- **HIPAA §:** {v.hipaa_section}")
                lines.append(f"- **PHI Impact:** {v.phi_impact}")
                lines.append(f"- **Patient Count:** {v.patient_count}")
                lines.append(f"- **Description:** {v.description}")
                if v.remediation_action:
                    lines.append(f"- **Remediation:** {v.remediation_action}")
                lines.append("")

        # 7. NIST AI RMF
        h(2, "7. NIST AI RMF Alignment")
        if report.nist_ai_rmf_scores:
            table(
                ["Function", "Score", "Assessment"],
                [
                    [
                        f.title(),
                        f"{s * 100:.1f}%",
                        "Strong" if s >= 0.9 else "Adequate" if s >= 0.7 else "Needs Improvement" if s >= 0.5 else "Deficient",
                    ]
                    for f, s in sorted(report.nist_ai_rmf_scores.items())
                ],
            )

        # 8. Gap Analysis
        h(2, "8. Gap Analysis")
        gaps = [c for c in controls if c.status in {"non_compliant", "partially_compliant"}]
        gaps.sort(key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(c.severity, 4))
        if gaps:
            for i, g in enumerate(gaps, 1):
                lines.append(f"### GAP-{i:02d}: {g.control_id} — {g.hipaa_standard}")
                lines.append(f"- **HIPAA Section:** {g.hipaa_section}")
                lines.append(f"- **Status:** {g.status.replace('_', ' ').title()}")
                lines.append(f"- **Severity:** {g.severity.upper()}")
                lines.append(f"- **Risk Score:** {g.risk_score:.1f}/10")
                lines.append(f"- **Finding:** {g.finding}")
                if g.remediation:
                    lines.append(f"- **Remediation:** {g.remediation}")
                lines.append("")
        else:
            p("No gaps identified — all assessed controls are compliant.")

        # 9. Recommendations
        h(2, "9. Recommendations")
        if report.recommendations:
            table(
                ["Priority", "Title", "HIPAA §", "Effort", "Severity"],
                [
                    [
                        str(r.get("priority", "")),
                        r.get("title", "")[:60],
                        r.get("hipaa_ref", ""),
                        r.get("effort", "").title(),
                        r.get("severity", "").upper(),
                    ]
                    for r in report.recommendations
                ],
            )

        # Footer
        lines.append("---")
        lines.append("")
        lines.append(
            f"*Generated by AI Agent Audit Trail Generator | "
            f"Report ID: `{report.report_id}` | "
            f"Per §164.316(b)(2)(i), retain for 6 years | "
            f"Confidential — HIPAA Compliance Documentation*"
        )

        output_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown report generated: %s", output_path)
        return output_path
