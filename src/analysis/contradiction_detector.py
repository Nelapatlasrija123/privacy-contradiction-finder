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

from dataclasses import dataclass, asdict, field
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
from src.analysis.tracker_detector import DetectedTracker, TrackerCategory, detect_trackers, parse_sdk_input
from src.analysis.terms_analyzer import analyze_terms, related_permissions_note


class EvidenceLevel(str, Enum):
    """How far the evidence goes: from "the app can ask for it" up to "data was seen leaving the device"."""

    DECLARED = "Level 1 - Declared (manifest / store listing)"
    CODE_PRESENT = "Level 2 - Code present in the APK"
    RUNTIME_OBSERVED = "Level 3 - Observed at runtime"
    TRANSMISSION_OBSERVED = "Level 4 - Data seen leaving the device"


EVIDENCE_LEVEL_ORDER = list(EvidenceLevel)

# Share of the full score penalty a finding carries at each evidence level.
# A declared permission only proves capability, so it costs half as much as observed transmission.
EVIDENCE_WEIGHT: dict[EvidenceLevel, float] = {
    EvidenceLevel.DECLARED: 0.5,
    EvidenceLevel.CODE_PRESENT: 0.75,
    EvidenceLevel.RUNTIME_OBSERVED: 0.9,
    EvidenceLevel.TRANSMISSION_OBSERVED: 1.0,
}

# Full penalties (before evidence weighting). A contradiction is a false statement, so it costs
# twice an omission; an unjustified permission is a data-minimisation issue and costs least.
CONTRADICTION_PENALTY = 30
CONCERN_PENALTY = 15
OVERPRIVILEGED_PENALTY = 10


def evidence_level_for_source(evidence_source: str) -> EvidenceLevel:
    """Default evidence level implied by where the permission list came from."""
    source_lower = evidence_source.lower()
    if "pcap" in source_lower or "traffic" in source_lower or "mitm" in source_lower:
        return EvidenceLevel.TRANSMISSION_OBSERVED
    if "runtime" in source_lower or "dynamic" in source_lower:
        return EvidenceLevel.RUNTIME_OBSERVED
    return EvidenceLevel.DECLARED


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
    evidence_level: str = EvidenceLevel.DECLARED.value

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
    evidence_level: str = EvidenceLevel.DECLARED.value
    trackers_detected: list[dict[str, str]] = field(default_factory=list)
    terms_notes: list[str] = field(default_factory=list)
    score_breakdown: list[str] = field(default_factory=list)


def evaluate_purpose_alignment(
    permission_info: PermissionInfo, stated_purpose: str
) -> str:
    """Assess whether a permission appears plausibly justified by the app's stated purpose."""
    if not stated_purpose or not stated_purpose.strip():
        return "Stated purpose was not provided; cannot assess functional necessity."

    # Low-risk install-time permissions (INTERNET, network state) are needed by almost every app
    if (
        permission_info.protection_level == ProtectionLevel.NORMAL
        and permission_info.inherent_privacy_risk == "Low"
        and permission_info.domain != PrivacyDomain.SYSTEM_OTHER
    ):
        return "Routine low-risk permission used by most apps; no specific justification needed."

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
    sdk_entries: list[str] | None = None,
    terms_text: str = "",
    evidence_level: EvidenceLevel | None = None,
) -> AuditReport:
    """Compare policy claims against permission evidence and generate an audit report.

    Args:
        app_name: Name of the application.
        policy_text: Sanitized policy text.
        permissions: List of requested Android permission strings.
        evidence_source: Label of evidence origin (e.g. Manifest, Runtime, Play Store).
        stated_purpose: Optional user-provided description of the app's function.
        sdk_entries: Optional SDK / library package names found in the APK (third-party sharing evidence).
        terms_text: Optional Terms & Conditions text, scanned for clauses that affect permissions.
        evidence_level: How far the permission evidence goes; defaults to what the source implies.

    Returns:
        Structured AuditReport with detailed findings and statistics.
    """
    level = evidence_level or evidence_level_for_source(evidence_source)

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
            # Case 2: Permission requested, but policy completely silent.
            # AD_ID is a "normal" permission but exists only for advertising/analytics, so silence about
            # third-party sharing is treated like silence about a dangerous permission.
            if (
                perm_info.protection_level == ProtectionLevel.DANGEROUS
                or domain == PrivacyDomain.THIRD_PARTY_SHARING
            ):
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
            evidence_level=level.value,
        )
        findings.append(finding)

    # 3b. Third-party SDKs bundled in the APK are direct evidence of sharing, even when the policy is silent
    sharing_stance, sharing_quote, sharing_section, _ = resolve_domain_overall_stance(
        claims_by_domain.get(PrivacyDomain.THIRD_PARTY_SHARING, [])
    )
    sdk_level = max(level, EvidenceLevel.CODE_PRESENT, key=EVIDENCE_LEVEL_ORDER.index)
    # Accept raw lines (Gradle coordinates, Exodus output) as well as already-parsed package names
    trackers = detect_trackers(parse_sdk_input("\n".join(sdk_entries or [])))
    for tracker in trackers:
        findings.append(
            _tracker_finding(tracker, sharing_stance, sharing_quote, sharing_section, sdk_level)
        )

    # 3c. Terms & Conditions clauses that change how much a permission matters
    permission_domains = {get_permission_info(p).domain for p in unique_perms}
    if trackers:
        permission_domains.add(PrivacyDomain.THIRD_PARTY_SHARING)
    terms_notes = related_permissions_note(analyze_terms(terms_text), permission_domains) if terms_text else []

    # 4. Compute Summary Statistics
    contradictions = sum(1 for f in findings if f.classification == FindingClassification.POTENTIAL_CONTRADICTION)
    concerns = sum(1 for f in findings if f.classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN)
    aligned = sum(1 for f in findings if f.classification == FindingClassification.NO_CONTRADICTION)
    insufficient = sum(1 for f in findings if f.classification == FindingClassification.INSUFFICIENT_EVIDENCE)

    # Calculate Privacy Trust Score (0 to 100). Each penalty is scaled by how strong the evidence is,
    # so a permission that is only declared never counts as much as data seen leaving the device.
    score_breakdown: list[str] = []
    penalty_total = 0.0
    for f in findings:
        weight = EVIDENCE_WEIGHT[EvidenceLevel(f.evidence_level)]
        if f.classification == FindingClassification.POTENTIAL_CONTRADICTION:
            base, reason = CONTRADICTION_PENALTY, "contradiction"
        elif f.classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN:
            base, reason = CONCERN_PENALTY, "undisclosed"
        else:
            base, reason = 0, ""
        if base:
            penalty_total += base * weight
            score_breakdown.append(f"-{base * weight:g}  {f.permission_name}: {reason} ({base} x {weight:g} evidence weight)")
        if "May be unnecessary" in f.purpose_alignment:
            penalty_total += OVERPRIVILEGED_PENALTY * weight
            score_breakdown.append(
                f"-{OVERPRIVILEGED_PENALTY * weight:g}  {f.permission_name}: not justified by stated purpose "
                f"({OVERPRIVILEGED_PENALTY} x {weight:g} evidence weight)"
            )
    score = max(5, min(100, round(100 - penalty_total)))

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
        evidence_level=level.value,
        trackers_detected=[
            {"name": t.name, "company": t.company, "category": t.category.value, "matched": t.matched_package}
            for t in trackers
        ],
        terms_notes=terms_notes,
        score_breakdown=score_breakdown,
    )


def _tracker_finding(
    tracker: DetectedTracker,
    sharing_stance: PolicyStance,
    quote: str,
    section: str,
    level: EvidenceLevel,
) -> AuditFinding:
    """Compare one bundled third-party SDK against what the policy says about sharing."""
    is_ad_tracker = tracker.category in (TrackerCategory.ADVERTISING, TrackerCategory.ATTRIBUTION)
    evidence = (
        f"The APK bundles the {tracker.name} SDK by {tracker.company} ({tracker.category.value}), "
        f"matched from `{tracker.matched_package}`. {tracker.data_typically_shared}"
    )

    if sharing_stance == PolicyStance.DENIES_COLLECTION:
        classification = FindingClassification.POTENTIAL_CONTRADICTION
        risk = RiskLevel.HIGH if is_ad_tracker else RiskLevel.MEDIUM
        confidence = "Medium"
        explanation = (
            f"Potential contradiction — the policy denies sharing data with third parties, yet the app "
            f"contains {tracker.company}'s {tracker.name} SDK, which exists to send data to {tracker.company}."
        )
    elif sharing_stance in (PolicyStance.CLAIMS_COLLECTION, PolicyStance.REQUIRES_CONSENT):
        classification = FindingClassification.NO_CONTRADICTION
        risk = RiskLevel.LOW
        confidence = "Medium"
        explanation = (
            f"No contradiction identified — the policy discloses sharing with third parties, consistent "
            f"with the bundled {tracker.name} SDK. Check that {tracker.company} is named or covered."
        )
    elif sharing_stance == PolicyStance.AMBIGUOUS:
        classification = FindingClassification.INSUFFICIENT_EVIDENCE
        risk = RiskLevel.MEDIUM
        confidence = "Low"
        explanation = (
            f"Insufficient evidence — the policy mentions third parties only vaguely, so it is unclear "
            f"whether data sent to {tracker.company} by {tracker.name} is covered."
        )
    else:
        classification = FindingClassification.POSSIBLE_PRIVACY_CONCERN
        risk = RiskLevel.MEDIUM
        confidence = "High"
        explanation = (
            f"Possible privacy concern (undisclosed sharing) — the policy never mentions third-party sharing, "
            f"but the app contains {tracker.company}'s {tracker.name} SDK. The policy's silence does not mean "
            f"no sharing happens; the bundled SDK is the evidence."
        )

    return AuditFinding(
        permission_name=f"SDK: {tracker.name}",
        domain=PrivacyDomain.THIRD_PARTY_SHARING.value,
        classification=classification,
        risk_level=risk,
        confidence=confidence,
        policy_statement=quote,
        policy_section=section,
        permission_evidence=evidence,
        conflict_explanation=explanation,
        additional_evidence_needed=(
            f"Capture the app's traffic with mitmproxy and look for requests to {tracker.company} domains "
            "to confirm data actually leaves the device (evidence level 4)."
        ),
        practical_recommendation=(
            f"Name {tracker.company} and the data shared with it in the policy, or remove the SDK if unused."
        ),
        purpose_alignment="Not applicable — third-party SDK, not an app permission.",
        evidence_level=level.value,
    )
