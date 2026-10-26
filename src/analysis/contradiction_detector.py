"""Core Contradiction Detection Engine.

Cross-references extracted privacy policy claims against declared Android permissions.
Categorizes findings into:
- Potential Contradiction
- Possible Privacy Concern
- No Contradiction Identified
- Insufficient Evidence

Assigns justified risk levels, confidence scores, verification steps, and practical recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any

from src.permissions.permission_db import (
    PrivacyDomain,
    ProtectionLevel,
    PermissionInfo,
    get_permission_info,
    explain_evidence_source,
    normalize_permission_name,
)
from src.analysis.rule_analyzer import (
    PolicyStance,
    PolicyClaim,
    extract_policy_claims,
    resolve_domain_overall_stance,
)


class FindingClassification(str, Enum):
    POTENTIAL_CONTRADICTION = "Potential Contradiction"
    POSSIBLE_PRIVACY_CONCERN = "Possible Privacy Concern"
    NO_CONTRADICTION = "No Contradiction Identified in Available Evidence"
    INSUFFICIENT_EVIDENCE = "Insufficient Evidence"


class RiskLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class AuditFinding:
    permission_name: str
    domain: str
    classification: FindingClassification
    risk_level: RiskLevel
    confidence: str  # "High", "Medium", "Low"
    policy_statement: str
    policy_section: str
    permission_evidence: str
    conflict_explanation: str
    additional_evidence_needed: str
    practical_recommendation: str
    purpose_alignment: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["classification"] = self.classification.value
        d["risk_level"] = self.risk_level.value
        return d


@dataclass
class AuditReport:
    app_name: str
    stated_purpose: str
    evidence_source: str
    policy_character_count: int
    findings: list[AuditFinding]
    contradiction_count: int
    concern_count: int
    aligned_count: int
    insufficient_count: int
    overall_app_risk: RiskLevel
    summary_message: str
    trust_score: int = 100
    trust_grade: str = "A+ (Excellent Transparency)"


def evaluate_purpose_alignment(
    permission_info: PermissionInfo, stated_purpose: str
) -> str:
    """Assess whether a permission appears plausibly justified by the app's stated purpose."""
    if not stated_purpose or not stated_purpose.strip():
        return "Stated purpose was not provided; cannot assess functional necessity."

    purpose_lower = stated_purpose.lower()
    domain = permission_info.domain

    # Purpose heuristic mapping
    domain_purpose_keywords = {
        PrivacyDomain.LOCATION: ["navigation", "map", "route", "gps", "travel", "weather", "delivery", "ride", "run", "fitness"],
        PrivacyDomain.CAMERA: ["photo", "camera", "video", "scan", "qr", "barcode", "torch", "flashlight", "filter"],
        PrivacyDomain.MICROPHONE: ["voice", "audio", "record", "call", "assistant", "speech", "sound", "dictat", "music"],
        PrivacyDomain.CONTACTS: ["contact", "friends", "social", "address", "invite", "chat", "messaging", "share"],
        PrivacyDomain.STORAGE_FILES: ["save", "file", "photo", "gallery", "image", "media", "document", "download"],
        PrivacyDomain.PHONE_TELEPHONY: ["call", "dial", "phone", "telecom", "sms", "cellular"],
        PrivacyDomain.BIOMETRICS_SENSORS: ["heart", "pulse", "health", "fitness", "sensor", "step", "biometric"],
        PrivacyDomain.CONNECTIVITY_NETWORK: ["bluetooth", "connect", "device", "accessory", "network"],
    }

    keywords = domain_purpose_keywords.get(domain, [])
    for kw in keywords:
        if kw in purpose_lower:
            return f"Plausibly aligned with app purpose ('{kw}' mentioned in stated purpose)."

    return f"May be unnecessary for the stated purpose ('{stated_purpose[:50]}...'). Requires functional justification."


def detect_contradictions(
    app_name: str,
    policy_text: str,
    permissions: list[str],
    evidence_source: str,
    stated_purpose: str = "",
) -> AuditReport:
    """Compare policy claims against permission evidence and generate an audit report.

    Args:
        app_name: Name of the application.
        policy_text: Sanitized policy text.
        permissions: List of requested Android permission strings.
        evidence_source: Label of evidence origin (e.g. Manifest, Runtime, Play Store).
        stated_purpose: Optional user-provided description of the app's function.

    Returns:
        Structured AuditReport with detailed findings and statistics.
    """
    # 1. Normalize permissions and retrieve knowledge base metadata
    cleaned_perms = [normalize_permission_name(p) for p in permissions if normalize_permission_name(p)]
    unique_perms = list(dict.fromkeys(cleaned_perms))

    # 2. Extract policy claims across domains
    claims_by_domain = extract_policy_claims(policy_text)

    # 3. Analyze each permission against its corresponding domain stance
    findings: list[AuditFinding] = []
    source_context = explain_evidence_source(evidence_source)

    for perm_name in unique_perms:
        perm_info = get_permission_info(perm_name)
        domain = perm_info.domain

        # Resolve domain claim in policy
        domain_claims = claims_by_domain.get(domain, [])
        stance, quote, section, confidence_val = resolve_domain_overall_stance(domain_claims)
        purpose_note = evaluate_purpose_alignment(perm_info, stated_purpose)

        # Evidentiary description
        perm_evidence_str = (
            f"The app requests `{perm_info.name}` ({perm_info.short_description}) "
            f"documented via {source_context['source_type']}."
        )

        # Contradiction Logic Matrix
        if stance == PolicyStance.DENIES_COLLECTION:
            # Case 1: Policy denies collection, but app requests permission
            # Justify Risk: High only if dangerous runtime permission; Medium if normal
            if perm_info.protection_level == ProtectionLevel.DANGEROUS:
                risk = RiskLevel.HIGH
                confidence = "High" if source_context["evidentiary_weight"].startswith("High") else "Medium"
            else:
                risk = RiskLevel.MEDIUM
                confidence = "Medium"

            classification = FindingClassification.POTENTIAL_CONTRADICTION
            explanation = (
                f"Potential privacy contradiction — the privacy policy appears to deny or disclaim collection "
                f"or tracking of {domain.value} data, yet the application declares `{perm_info.name}`. "
                f"A permission request alone does not establish that {domain.value.lower()} data is actually "
                f"collected or transmitted. However, requesting the technical capability directly conflicts "
                f"with an unqualified denial statement."
            )
            verification_needed = (
                f"Perform dynamic network traffic inspection (PCAP/mitmproxy) and Android API hooking "
                f"(e.g., Frida) to monitor if the app calls privileged APIs for `{perm_info.name}` and "
                f"whether payload bytes are transmitted to remote servers."
            )
            recommendation = (
                f"Review the policy wording to clarify whether this capability is ever invoked. "
                f"If the app does not need this data, remove `{perm_info.name}` from the AndroidManifest.xml. "
                f"Users should consider revoking this permission in Android Settings."
            )

        elif stance == PolicyStance.NOT_MENTIONED:
            # Case 2: Permission requested, but policy completely silent
            if perm_info.protection_level == ProtectionLevel.DANGEROUS:
                risk = RiskLevel.MEDIUM
                confidence = "High"
                classification = FindingClassification.POSSIBLE_PRIVACY_CONCERN
                explanation = (
                    f"Possible privacy concern (transparency omission) — the app requests `{perm_info.name}`, "
                    f"which grants access to {domain.value.lower()}, but the privacy policy does not mention "
                    f"or explain how this data is handled, stored, or protected."
                )
                verification_needed = (
                    "Inspect the privacy policy for missing disclosure sections or supplemental disclosures. "
                    "Confirm whether third-party SDKs inside the APK are bundling this permission."
                )
                recommendation = (
                    "Update the privacy policy to explicitly disclose whether and why this data is accessed. "
                    "Transparency guidelines under GDPR and CCPA require clear disclosure of collected resources."
                )
            else:
                risk = RiskLevel.LOW
                confidence = "Medium"
                classification = FindingClassification.INSUFFICIENT_EVIDENCE
                explanation = (
                    f"Normal install-time permission `{perm_info.name}` requested without dedicated policy mention. "
                    "Normal permissions pose low inherent privacy risk."
                )
                verification_needed = "Check if permission is bundled by common utility libraries."
                recommendation = "Standard disclosure recommended."

        elif stance == PolicyStance.CLAIMS_COLLECTION:
            # Case 3: Policy transparently declares collection
            classification = FindingClassification.NO_CONTRADICTION
            risk = RiskLevel.LOW
            confidence = "High"
            explanation = (
                f"No contradiction identified in available evidence — the privacy policy transparently declares "
                f"collection or processing of {domain.value.lower()} data, which aligns with declared `{perm_info.name}`."
            )
            verification_needed = (
                "Verify that data usage strictly adheres to the stated purposes in the policy."
            )
            recommendation = (
                "Maintain data minimization practices and provide in-app disclosure before requesting consent."
            )

        elif stance == PolicyStance.REQUIRES_CONSENT:
            # Case 4: Policy specifies user opt-in or permission gating
            classification = FindingClassification.NO_CONTRADICTION
            risk = RiskLevel.LOW
            confidence = "High"
            explanation = (
                f"No contradiction identified — the policy states that {domain.value.lower()} is accessed only "
                f"with user consent or opt-in, consistent with Android runtime permission model."
            )
            verification_needed = (
                "Ensure runtime consent dialog correctly explains purpose before OS permission prompt appears."
            )
            recommendation = (
                "Follow Android best practices for runtime permission justification rationale dialogs."
            )

        else:
            # Case 5: Ambiguous / Vague Claim
            classification = FindingClassification.INSUFFICIENT_EVIDENCE
            risk = RiskLevel.MEDIUM if perm_info.protection_level == ProtectionLevel.DANGEROUS else RiskLevel.LOW
            confidence = "Low"
            explanation = (
                f"Insufficient evidence to conclude — policy statements regarding {domain.value.lower()} are "
                f"ambiguous or vague, making it impossible to determine alignment with `{perm_info.name}`."
            )
            verification_needed = "Clarification of ambiguous terms in legal policy."
            recommendation = "Request clear legal documentation from app developer."

        finding = AuditFinding(
            permission_name=perm_info.name,
            domain=domain.value,
            classification=classification,
            risk_level=risk,
            confidence=confidence,
            policy_statement=quote,
            policy_section=section,
            permission_evidence=perm_evidence_str,
            conflict_explanation=explanation,
            additional_evidence_needed=verification_needed,
            practical_recommendation=recommendation,
            purpose_alignment=purpose_note,
        )
        findings.append(finding)

    # 4. Compute Summary Statistics
    contradictions = sum(1 for f in findings if f.classification == FindingClassification.POTENTIAL_CONTRADICTION)
    concerns = sum(1 for f in findings if f.classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN)
    aligned = sum(1 for f in findings if f.classification == FindingClassification.NO_CONTRADICTION)
    insufficient = sum(1 for f in findings if f.classification == FindingClassification.INSUFFICIENT_EVIDENCE)

    # Calculate Privacy Trust Score (0 to 100)
    score = 100
    score -= contradictions * 30
    score -= concerns * 15
    overprivileged_count = sum(1 for f in findings if "May be unnecessary" in f.purpose_alignment)
    score -= overprivileged_count * 10
    score = max(5, min(100, score))

    if score >= 90:
        grade = "A+ (Excellent Transparency)"
    elif score >= 75:
        grade = "B (Good / Low Risk)"
    elif score >= 55:
        grade = "C (Moderate Transparency Concerns)"
    elif score >= 35:
        grade = "D (Poor / High Discrepancy)"
    else:
        grade = "F (Critical Privacy Contradictions)"

    # Calculate overall risk strictly based on justified findings
    if contradictions > 0:
        overall_risk = RiskLevel.HIGH
        summary_msg = (
            f"Audit completed: {contradictions} potential contradiction(s) and {concerns} privacy concern(s) "
            f"identified. The policy explicitly denies collecting data that requested permissions enable."
        )
    elif concerns > 0:
        overall_risk = RiskLevel.MEDIUM
        summary_msg = (
            f"Audit completed: {concerns} possible privacy concern(s) identified due to unmentioned "
            f"sensitive permissions. No explicit policy denials were contradicted."
        )
    else:
        overall_risk = RiskLevel.LOW
        summary_msg = (
            "Audit completed: No contradictions identified in available evidence. "
            "Policy statements align with declared Android permissions."
        )

    return AuditReport(
        app_name=app_name,
        stated_purpose=stated_purpose or "Not specified",
        evidence_source=evidence_source,
        policy_character_count=len(policy_text),
        findings=findings,
        contradiction_count=contradictions,
        concern_count=concerns,
        aligned_count=aligned,
        insufficient_count=insufficient,
        overall_app_risk=overall_risk,
        summary_message=summary_msg,
        trust_score=score,
        trust_grade=grade,
    )
