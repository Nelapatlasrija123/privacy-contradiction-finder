"""Unit tests for Rule Analyzer, Claim Extractor, and Contradiction Detection Engine."""

from __future__ import annotations

import pytest

from src.permissions.permission_db import PrivacyDomain
from src.analysis.rule_analyzer import (
    PolicyStance,
    PolicyClaim,
    split_into_sentences,
    analyze_sentence_for_domain,
    extract_policy_claims,
    resolve_domain_overall_stance,
)
from src.analysis.contradiction_detector import (
    FindingClassification,
    RiskLevel,
    detect_contradictions,
    evaluate_purpose_alignment,
)
from src.permissions.permission_db import get_permission_info


# ---------------------------------------------------------
# Test Sentence Splitting & Claim Extraction
# ---------------------------------------------------------

def test_split_into_sentences():
    text = (
        "Section 1: Information Collection\n"
        "We do not collect precise location data. We never record audio from your phone."
    )
    records = split_into_sentences(text)
    assert len(records) == 2
    assert "Section 1" in records[0][1]
    assert "location data" in records[0][0]


def test_analyze_sentence_denial():
    sentence = "We never collect, track, or share your GPS coordinates."
    stance, conf = analyze_sentence_for_domain(sentence, PrivacyDomain.LOCATION)
    assert stance == PolicyStance.DENIES_COLLECTION
    assert conf >= 0.90


def test_analyze_sentence_collection():
    sentence = "We collect your precise location to provide live navigation updates."
    stance, conf = analyze_sentence_for_domain(sentence, PrivacyDomain.LOCATION)
    assert stance == PolicyStance.CLAIMS_COLLECTION
    assert conf >= 0.85


def test_analyze_sentence_consent():
    sentence = "With your explicit permission, we may access your device contacts list."
    stance, conf = analyze_sentence_for_domain(sentence, PrivacyDomain.CONTACTS)
    assert stance == PolicyStance.REQUIRES_CONSENT
    assert conf >= 0.80


# ---------------------------------------------------------
# Test Contradiction Detection Engine
# ---------------------------------------------------------

def test_detect_contradictions_high_risk_contradiction():
    policy = (
        "Privacy Policy for Flashlight Utility:\n"
        "1. Location: We do not collect, track, or share your precise location data or GPS coordinates.\n"
        "2. Microphone: We never record audio or monitor microphone conversations.\n"
    )
    perms = ["ACCESS_FINE_LOCATION", "RECORD_AUDIO"]
    report = detect_contradictions(
        app_name="Torch Utility",
        policy_text=policy,
        permissions=perms,
        evidence_source="Decompiled AndroidManifest.xml",
        stated_purpose="A simple flashlight app using the phone LED.",
    )

    assert report.contradiction_count == 2
    assert report.overall_app_risk == RiskLevel.HIGH
    for finding in report.findings:
        assert finding.classification == FindingClassification.POTENTIAL_CONTRADICTION
        assert finding.risk_level == RiskLevel.HIGH
        assert "not establish that" in finding.conflict_explanation.lower()
        assert "Frida" in finding.additional_evidence_needed or "PCAP" in finding.additional_evidence_needed


def test_detect_contradictions_transparent_alignment():
    policy = (
        "NaviRoute Privacy Policy:\n"
        "We collect precise location data (GPS coordinates) to provide turn-by-turn navigation.\n"
        "We may access your contacts if you choose to share your live ETA.\n"
    )
    perms = ["ACCESS_FINE_LOCATION", "READ_CONTACTS"]
    report = detect_contradictions(
        app_name="NaviRoute Maps",
        policy_text=policy,
        permissions=perms,
        evidence_source="Play Store Data Safety",
        stated_purpose="GPS navigation and live turn-by-turn routing app.",
    )

    assert report.contradiction_count == 0
    assert report.overall_app_risk == RiskLevel.LOW
    for finding in report.findings:
        assert finding.classification == FindingClassification.NO_CONTRADICTION
        assert finding.risk_level == RiskLevel.LOW


def test_detect_contradictions_omission_privacy_concern():
    policy = (
        "Simple Note Keeper Privacy Notice:\n"
        "We store your notes locally on your device. We do not sell your data.\n"
    )
    perms = ["READ_CONTACTS"]
    report = detect_contradictions(
        app_name="Simple Notes",
        policy_text=policy,
        permissions=perms,
        evidence_source="Decompiled AndroidManifest.xml",
        stated_purpose="Offline notes organizer.",
    )

    assert report.contradiction_count == 0
    assert report.concern_count == 1
    assert report.overall_app_risk == RiskLevel.MEDIUM
    finding = report.findings[0]
    assert finding.classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN
    assert finding.risk_level == RiskLevel.MEDIUM
    assert "omits any explicit disclosure" in finding.conflict_explanation or "does not mention" in finding.conflict_explanation


def test_purpose_alignment_detection():
    loc_perm = get_permission_info("ACCESS_FINE_LOCATION")
    # Aligned purpose
    nav_alignment = evaluate_purpose_alignment(loc_perm, "Turn-by-turn GPS route navigation")
    assert "Plausibly aligned" in nav_alignment

    # Unaligned purpose
    torch_alignment = evaluate_purpose_alignment(loc_perm, "Simple LED torchlight utility")
    assert "May be unnecessary" in torch_alignment
