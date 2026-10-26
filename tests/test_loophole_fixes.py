"""Regression tests for the loopholes raised in faculty review, plus sharing and evidence-level logic.

Each test is named after the question or loophole it closes.
"""

from __future__ import annotations

from src.permissions.permission_db import PrivacyDomain, ProtectionLevel, get_permission_info
from src.analysis.rule_analyzer import PolicyStance, analyze_sentence_for_domain
from src.analysis.contradiction_detector import (
    EvidenceLevel,
    FindingClassification,
    RiskLevel,
    detect_contradictions,
)

MANIFEST = "Decompiled AndroidManifest.xml"


# ---------------------------------------------------------
# Loophole 1: "do not sell" was read as "do not collect"
# ---------------------------------------------------------

def test_not_selling_is_not_a_collection_denial():
    sentence = "We collect your precise location to provide navigation, but we do not sell it to anyone."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.LOCATION)
    assert stance == PolicyStance.CLAIMS_COLLECTION


def test_not_selling_is_a_sharing_denial():
    sentence = "We collect your precise location to provide navigation, but we do not sell it to anyone."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.THIRD_PARTY_SHARING)
    assert stance == PolicyStance.DENIES_COLLECTION


def test_collect_and_sell_denied_together_still_denies_collection():
    sentence = "We do not collect, track, or share your GPS coordinates."
    assert analyze_sentence_for_domain(sentence, PrivacyDomain.LOCATION)[0] == PolicyStance.DENIES_COLLECTION
    assert analyze_sentence_for_domain(sentence, PrivacyDomain.THIRD_PARTY_SHARING)[0] == PolicyStance.DENIES_COLLECTION


def test_no_false_contradiction_for_disclosed_location():
    report = detect_contradictions(
        app_name="Maps",
        policy_text="We collect your precise location for navigation, but we never sell it.",
        permissions=["ACCESS_FINE_LOCATION"],
        evidence_source=MANIFEST,
        stated_purpose="Navigation app",
    )
    assert report.contradiction_count == 0
    assert report.findings[0].classification == FindingClassification.NO_CONTRADICTION


# ---------------------------------------------------------
# Loophole 2: "contact us" counted as a contacts disclosure
# ---------------------------------------------------------

def test_contact_us_is_not_a_contacts_disclosure():
    sentence = "If you have questions, contact us at help@example.com and we will reply."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.CONTACTS)
    assert stance is None


def test_contact_us_does_not_hide_undisclosed_contacts_permission():
    report = detect_contradictions(
        app_name="Notes",
        policy_text="If you have questions, contact us at help@example.com and we will use your email to reply.",
        permissions=["READ_CONTACTS"],
        evidence_source=MANIFEST,
    )
    assert report.findings[0].classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN


# ---------------------------------------------------------
# Loophole 3: any use of the word "use" counted as disclosure
# ---------------------------------------------------------

def test_user_action_is_not_a_collection_disclosure():
    sentence = "You can use the microphone button to start the timer."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.MICROPHONE)
    assert stance == PolicyStance.AMBIGUOUS


def test_company_using_data_is_still_a_disclosure():
    sentence = "We use your microphone audio to power voice search."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.MICROPHONE)
    assert stance == PolicyStance.CLAIMS_COLLECTION


# ---------------------------------------------------------
# Loophole 4: negation applied to the whole sentence
# ---------------------------------------------------------

def test_negation_only_applies_to_its_own_clause():
    sentence = "We record audio when you hold the voice button, but we never share it."
    # The negation is in the second clause, which does not name the microphone domain.
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.MICROPHONE)
    assert stance == PolicyStance.CLAIMS_COLLECTION


def test_qualified_denial_is_consent_gating_not_a_contradiction():
    sentence = "We do not track your background location without your active initiation."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.LOCATION)
    assert stance == PolicyStance.REQUIRES_CONSENT


def test_unqualified_denial_is_still_a_denial():
    sentence = "We do not collect, track, or share your geographic location data or GPS coordinates."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.LOCATION)
    assert stance == PolicyStance.DENIES_COLLECTION


def test_purpose_statement_counts_as_disclosure():
    sentence = "The camera permission is required solely to activate the hardware camera LED torch."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.CAMERA)
    assert stance == PolicyStance.CLAIMS_COLLECTION


# ---------------------------------------------------------
# Loophole 5: common permissions were missing from the database
# ---------------------------------------------------------

def test_missing_permissions_are_now_known():
    assert get_permission_info("android.permission.INTERNET").domain == PrivacyDomain.CONNECTIVITY_NETWORK
    assert get_permission_info("com.google.android.gms.permission.AD_ID").domain == PrivacyDomain.THIRD_PARTY_SHARING
    for sms in ("READ_SMS", "RECEIVE_SMS", "SEND_SMS"):
        assert get_permission_info(sms).protection_level == ProtectionLevel.DANGEROUS


def test_undisclosed_advertising_id_is_a_concern():
    report = detect_contradictions(
        app_name="Weather",
        policy_text="We collect your location to show local weather.",
        permissions=["com.google.android.gms.permission.AD_ID"],
        evidence_source=MANIFEST,
    )
    assert report.findings[0].classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN


# ---------------------------------------------------------
# Question 1: sharing when the policy says nothing about it
# ---------------------------------------------------------

def test_tracker_with_silent_policy_is_undisclosed_sharing():
    report = detect_contradictions(
        app_name="Weather",
        policy_text="We collect your location to show local weather.",
        permissions=["ACCESS_FINE_LOCATION"],
        evidence_source=MANIFEST,
        sdk_entries=["com.google.android.gms.ads", "com.appsflyer.AppsFlyerLib"],
    )
    sdk_findings = [f for f in report.findings if f.permission_name.startswith("SDK:")]
    assert len(sdk_findings) == 2
    assert all(f.classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN for f in sdk_findings)
    assert all(f.evidence_level == EvidenceLevel.CODE_PRESENT.value for f in sdk_findings)
    assert len(report.trackers_detected) == 2


def test_user_sharing_is_not_third_party_disclosure():
    sentence = "You can share weather photos with the community if you choose to share them."
    stance, _ = analyze_sentence_for_domain(sentence, PrivacyDomain.THIRD_PARTY_SHARING)
    assert stance is None


def test_gradle_coordinates_are_accepted_as_sdk_input():
    report = detect_contradictions(
        app_name="Weather",
        policy_text="We collect your location to show local weather.",
        permissions=[],
        evidence_source=MANIFEST,
        sdk_entries=["com.google.android.gms:play-services-ads:22.6.0"],
    )
    assert len(report.trackers_detected) == 1


def test_internet_permission_is_not_flagged_as_unjustified():
    report = detect_contradictions(
        app_name="Weather",
        policy_text="We collect your location to show local weather.",
        permissions=["INTERNET"],
        evidence_source=MANIFEST,
        stated_purpose="Weather forecasts",
    )
    assert "May be unnecessary" not in report.findings[0].purpose_alignment
    assert report.trust_score == 100


def test_tracker_with_sharing_denial_is_contradiction():
    report = detect_contradictions(
        app_name="Torch",
        policy_text="We never share or sell your information with third parties or advertisers.",
        permissions=[],
        evidence_source=MANIFEST,
        sdk_entries=["com.google.android.gms.ads"],
    )
    assert report.contradiction_count == 1
    assert report.findings[0].risk_level == RiskLevel.HIGH


def test_tracker_with_disclosed_sharing_is_aligned():
    report = detect_contradictions(
        app_name="Game",
        policy_text="We share device identifiers with advertising partners to show ads.",
        permissions=[],
        evidence_source=MANIFEST,
        sdk_entries=["com.unity3d.ads"],
    )
    assert report.findings[0].classification == FindingClassification.NO_CONTRADICTION


# ---------------------------------------------------------
# Question 2: Terms & Conditions linked to permissions
# ---------------------------------------------------------

def test_terms_content_licence_is_linked_to_camera_permission():
    report = detect_contradictions(
        app_name="PhotoApp",
        policy_text="We access your camera only with your permission.",
        permissions=["CAMERA"],
        evidence_source=MANIFEST,
        terms_text=(
            "You grant us a worldwide, royalty-free licence to use any photos you upload. "
            "These terms are governed by the laws of India."
        ),
    )
    assert report.terms_notes
    assert any("Licence" in note for note in report.terms_notes)


# ---------------------------------------------------------
# Question 3: a permission alone does not prove collection
# ---------------------------------------------------------

def test_declared_permission_costs_less_than_observed_transmission():
    kwargs = dict(
        app_name="Torch",
        policy_text="We do not collect your location.",
        permissions=["ACCESS_FINE_LOCATION"],
        evidence_source=MANIFEST,
        stated_purpose="Navigation app",
    )
    declared = detect_contradictions(**kwargs)
    observed = detect_contradictions(**kwargs, evidence_level=EvidenceLevel.TRANSMISSION_OBSERVED)
    assert declared.contradiction_count == observed.contradiction_count == 1
    assert declared.trust_score > observed.trust_score
    assert declared.findings[0].evidence_level == EvidenceLevel.DECLARED.value
    assert declared.score_breakdown


def test_runtime_source_implies_runtime_level():
    report = detect_contradictions(
        app_name="X",
        policy_text="",
        permissions=["CAMERA"],
        evidence_source="Dynamic Runtime Request Observation",
    )
    assert report.evidence_level == EvidenceLevel.RUNTIME_OBSERVED.value
