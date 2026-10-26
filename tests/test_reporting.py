"""Unit tests for the reporting and export module (CSV & JSON)."""

from __future__ import annotations

import json
import pytest
import pandas as pd

from src.analysis.contradiction_detector import (
    AuditReport,
    AuditFinding,
    FindingClassification,
    RiskLevel,
)
from src.reporting.exporter import (
    findings_to_dataframe,
    generate_csv_report,
    generate_json_report,
    generate_pdf_report,
    SYSTEM_DISCLAIMER,
)


@pytest.fixture
def sample_audit_report() -> AuditReport:
    """Fixture providing a mock AuditReport for testing export generation."""
    finding1 = AuditFinding(
        permission_name="ACCESS_FINE_LOCATION",
        domain="Location",
        classification=FindingClassification.POTENTIAL_CONTRADICTION,
        risk_level=RiskLevel.HIGH,
        confidence="High",
        policy_statement="We do not collect precise location data.",
        policy_section="Section 1: Location",
        permission_evidence="The app requests ACCESS_FINE_LOCATION via AndroidManifest.xml.",
        conflict_explanation="Policy denies location, but permission authorizes GPS access.",
        additional_evidence_needed="Network PCAP traffic analysis.",
        practical_recommendation="Revoke permission in Android settings.",
        purpose_alignment="May be unnecessary for flashlight utility.",
    )
    return AuditReport(
        app_name="TorchGlow Pro",
        stated_purpose="Flashlight utility",
        evidence_source="Decompiled AndroidManifest.xml",
        policy_character_count=500,
        findings=[finding1],
        contradiction_count=1,
        concern_count=0,
        aligned_count=0,
        insufficient_count=0,
        overall_app_risk=RiskLevel.HIGH,
        summary_message="1 contradiction found.",
    )


def test_findings_to_dataframe(sample_audit_report: AuditReport):
    df = findings_to_dataframe(sample_audit_report.findings)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 1
    assert "Permission" in df.columns
    assert "Classification" in df.columns
    assert df.iloc[0]["Permission"] == "ACCESS_FINE_LOCATION"


def test_findings_to_dataframe_empty():
    df = findings_to_dataframe([])
    assert isinstance(df, pd.DataFrame)
    assert df.empty


def test_generate_csv_report(sample_audit_report: AuditReport):
    csv_str = generate_csv_report(sample_audit_report)
    assert "TorchGlow Pro" in csv_str
    assert "ACCESS_FINE_LOCATION" in csv_str
    assert "Potential Contradiction" in csv_str
    assert "Preliminary privacy analysis" in csv_str


def test_generate_json_report(sample_audit_report: AuditReport):
    json_str = generate_json_report(sample_audit_report)
    data = json.loads(json_str)

    assert "report_metadata" in data
    assert "application_profile" in data
    assert "audit_summary" in data
    assert "detailed_findings" in data

    assert data["application_profile"]["name"] == "TorchGlow Pro"
    assert data["audit_summary"]["potential_contradictions_count"] == 1
    assert len(data["detailed_findings"]) == 1
    assert data["detailed_findings"][0]["permission_name"] == "ACCESS_FINE_LOCATION"
    assert "Preliminary privacy analysis" in data["report_metadata"]["ethical_disclaimer"]


def test_generate_pdf_report(sample_audit_report: AuditReport):
    pdf_bytes = generate_pdf_report(sample_audit_report)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")

