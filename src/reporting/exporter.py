"""Reporting and Export Engine for Privacy Contradiction Finder.

Generates structured CSV and JSON audit reports with forensic provenance metadata,
executive summaries, and legal/ethical disclaimers.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
import pandas as pd

from src.analysis.contradiction_detector import AuditReport, AuditFinding


SYSTEM_DISCLAIMER = (
    "Preliminary privacy analysis — not proof of misconduct or legal advice. "
    "A permission request indicates technical authorization by the Android OS; "
    "it does not establish that data was collected, stored, or transmitted off-device. "
    "Definitive conclusions require dynamic traffic analysis and runtime binary inspection."
)


def findings_to_dataframe(findings: list[AuditFinding]) -> pd.DataFrame:
    """Convert a list of AuditFinding instances into a clean Pandas DataFrame for dashboard display."""
    if not findings:
        return pd.DataFrame()

    rows = []
    for f in findings:
        rows.append({
            "Permission": f.permission_name,
            "Domain": f.domain,
            "Classification": f.classification.value,
            "Risk Level": f.risk_level.value,
            "Confidence": f.confidence,
            "Policy Quote": f.policy_statement[:120] + ("..." if len(f.policy_statement) > 120 else ""),
            "Conflict Summary": f.conflict_explanation[:150] + ("..." if len(f.conflict_explanation) > 150 else ""),
        })

    return pd.DataFrame(rows)


def generate_csv_report(report: AuditReport) -> str:
    """Generate a RFC 4180-compliant CSV report string.

    Args:
        report: Completed AuditReport instance.

    Returns:
        CSV formatted string.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    # Header metadata rows
    writer.writerow(["# PRIVACY CONTRADICTION FINDER AUDIT REPORT"])
    writer.writerow(["# Application Name", report.app_name])
    writer.writerow(["# Stated Purpose", report.stated_purpose])
    writer.writerow(["# Evidence Source", report.evidence_source])
    writer.writerow(["# Overall Risk", report.overall_app_risk.value])
    writer.writerow(["# Contradictions Identified", report.contradiction_count])
    writer.writerow(["# Privacy Concerns Identified", report.concern_count])
    writer.writerow(["# Aligned Declarations", report.aligned_count])
    writer.writerow(["# Disclaimer", SYSTEM_DISCLAIMER])
    writer.writerow([])  # Blank separator

    # Findings Table Header
    headers = [
        "Permission Name",
        "Privacy Domain",
        "Classification",
        "Risk Level",
        "Confidence",
        "Policy Statement Quote",
        "Policy Section Hint",
        "Permission Evidence Source",
        "Conflict / Transparency Analysis",
        "Purpose Necessity Assessment",
        "Additional Evidence Needed",
        "Practical Recommendation",
    ]
    writer.writerow(headers)

    # Findings Rows
    for f in report.findings:
        writer.writerow([
            f.permission_name,
            f.domain,
            f.classification.value,
            f.risk_level.value,
            f.confidence,
            f.policy_statement,
            f.policy_section,
            f.permission_evidence,
            f.conflict_explanation,
            f.purpose_alignment,
            f.additional_evidence_needed,
            f.practical_recommendation,
        ])

    return output.getvalue()


def generate_json_report(report: AuditReport) -> str:
    """Generate a structured, schema-validated JSON audit report.

    Args:
        report: Completed AuditReport instance.

    Returns:
        Indented JSON string.
    """
    payload = {
        "report_metadata": {
            "system_name": "Privacy Contradiction Finder",
            "version": "1.0.0",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "ethical_disclaimer": SYSTEM_DISCLAIMER,
        },
        "application_profile": {
            "name": report.app_name,
            "stated_purpose": report.stated_purpose,
            "evidence_source": report.evidence_source,
            "policy_character_count": report.policy_character_count,
        },
        "audit_summary": {
            "overall_app_risk": report.overall_app_risk.value,
            "privacy_trust_score": report.trust_score,
            "privacy_trust_grade": report.trust_grade,
            "total_permissions_audited": len(report.findings),
            "potential_contradictions_count": report.contradiction_count,
            "possible_privacy_concerns_count": report.concern_count,
            "aligned_permissions_count": report.aligned_count,
            "insufficient_evidence_count": report.insufficient_count,
            "executive_summary": report.summary_message,
        },
        "detailed_findings": [f.to_dict() for f in report.findings],
    }

    return json.dumps(payload, indent=2, ensure_ascii=False)


def generate_pdf_report(report: AuditReport) -> bytes:
    """Generate a formatted forensic PDF audit report using PyMuPDF.

    Args:
        report: Completed AuditReport instance.

    Returns:
        Raw bytes of the generated PDF document.
    """
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)  # A4 standard points
    y = 50

    # Header title
    page.insert_text((50, y), "PRIVYSCAN FORENSIC AUDIT DOSSIER", fontsize=16, color=(0.2, 0.4, 0.8))
    y += 20
    page.insert_text((50, y), "Privacy Contradiction Finder v2.0 | Academic & Security Audit", fontsize=9, color=(0.4, 0.4, 0.4))
    y += 30

    # Application Profile
    page.insert_text((50, y), f"Application: {report.app_name}", fontsize=12, color=(0, 0, 0))
    y += 18
    page.insert_text((50, y), f"Stated Purpose: {report.stated_purpose[:75]}", fontsize=10, color=(0.3, 0.3, 0.3))
    y += 18
    page.insert_text((50, y), f"Evidence Source: {report.evidence_source}", fontsize=10, color=(0.3, 0.3, 0.3))
    y += 18
    page.insert_text((50, y), f"Overall Risk: {report.overall_app_risk.value}  |  Trust Score: {report.trust_score}/100 ({report.trust_grade})", fontsize=11, color=(0.8, 0.2, 0.2) if report.overall_app_risk.value == "High" else (0.2, 0.6, 0.2))
    y += 30

    # Summary Statistics
    stats_text = (
        f"Contradictions: {report.contradiction_count}   |   "
        f"Concerns: {report.concern_count}   |   "
        f"Aligned: {report.aligned_count}   |   "
        f"Total Permissions: {len(report.findings)}"
    )
    page.insert_text((50, y), stats_text, fontsize=10, color=(0.1, 0.1, 0.1))
    y += 25

    page.draw_line((50, y), (545, y), color=(0.7, 0.7, 0.7), width=1)
    y += 20

    # Findings List
    page.insert_text((50, y), "DETAILED FINDINGS & EVIDENCE:", fontsize=12, color=(0.1, 0.1, 0.1))
    y += 20

    for idx, f in enumerate(report.findings, start=1):
        if y > 740:
            page = doc.new_page(width=595, height=842)
            y = 50

        # Finding Header
        title = f"{idx}. {f.permission_name} ({f.domain}) — {f.classification.value}"
        color = (0.8, 0.1, 0.1) if "Contradiction" in f.classification.value else (0.8, 0.5, 0.1) if "Concern" in f.classification.value else (0.1, 0.6, 0.3)
        page.insert_text((50, y), title, fontsize=10, color=color)
        y += 15

        # Policy Quote
        quote_snippet = f"Policy Quote: \"{f.policy_statement[:85]}...\""
        page.insert_text((65, y), quote_snippet, fontsize=8, color=(0.25, 0.25, 0.25))
        y += 13

        # Conflict Explanation
        conflict_snippet = f"Analysis: {f.conflict_explanation[:90]}..."
        page.insert_text((65, y), conflict_snippet, fontsize=8, color=(0.25, 0.25, 0.25))
        y += 13

        # Recommended Action
        action_snippet = f"Next Step: {f.practical_recommendation[:90]}..."
        page.insert_text((65, y), action_snippet, fontsize=8, color=(0.35, 0.35, 0.35))
        y += 20

    # Footer Disclaimer
    if y > 770:
        page = doc.new_page(width=595, height=842)
        y = 50

    y = max(y + 10, 770)
    page.draw_line((50, y), (545, y), color=(0.8, 0.8, 0.8), width=0.5)
    y += 15
    page.insert_text((50, y), "Disclaimer: Preliminary privacy analysis. A permission request does not establish that data is collected or transmitted.", fontsize=7, color=(0.5, 0.5, 0.5))

    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes

