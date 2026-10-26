"""Rule-based policy claim extraction engine.

Extracts semantic data access and collection claims from privacy policy text
using deterministic regular expressions, negation analysis, and domain lexicons.
Operates 100% locally and offline without external API dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from src.permissions.permission_db import PrivacyDomain


class PolicyStance(str, Enum):
    DENIES_COLLECTION = "Denies Collection / Access"
    CLAIMS_COLLECTION = "Claims Collection / Use"
    REQUIRES_CONSENT = "Requires User Consent / Opt-in"
    AMBIGUOUS = "Ambiguous / Vague Claim"
    NOT_MENTIONED = "Not Mentioned in Policy"


@dataclass(frozen=True)
class PolicyClaim:
    domain: PrivacyDomain
    stance: PolicyStance
    exact_quote: str
    section_hint: str
    confidence: float  # 0.0 to 1.0
    source: str = "Rule-Based Extractor"


# Domain-specific keyword vocabulary
DOMAIN_KEYWORDS: dict[PrivacyDomain, list[str]] = {
    PrivacyDomain.LOCATION: [
        "location",
        "gps",
        "geographic",
        "geolocation",
        "precise location",
        "coarse location",
        "coordinates",
        "latitude",
        "longitude",
        "where you are",
    ],
    PrivacyDomain.CAMERA: [
        "camera",
        "photograph",
        "take photos",
        "video recording",
        "lens",
        "webcam",
        "torch",
        "flash",
    ],
    PrivacyDomain.MICROPHONE: [
        "microphone",
        "audio",
        "record audio",
        "sound recording",
        "voice",
        "listen",
        "wiretap",
        "eavesdrop",
    ],
    PrivacyDomain.CONTACTS: [
        "contact",
        "contacts",
        "address book",
        "phonebook",
        "contacts list",
        "phone numbers",
        "friends list",
    ],
    PrivacyDomain.STORAGE_FILES: [
        "photo",
        "photos",
        "gallery",
        "images",
        "videos",
        "files",
        "external storage",
        "sd card",
        "documents",
    ],
    PrivacyDomain.PHONE_TELEPHONY: [
        "phone state",
        "cellular",
        "call log",
        "phone calls",
        "imei",
        "imsi",
        "sim card",
        "carrier",
        "phone status",
    ],
    PrivacyDomain.BIOMETRICS_SENSORS: [
        "biometric",
        "body sensor",
        "heart rate",
        "pulse",
        "step count",
        "physical activity",
        "fitness data",
    ],
    PrivacyDomain.CONNECTIVITY_NETWORK: [
        "bluetooth",
        "wi-fi",
        "wifi",
        "network state",
        "bssid",
        "ssid",
        "nearby devices",
    ],
}

# Regex patterns for explicit negation / denial of collection
DENIAL_PATTERNS = [
    re.compile(r"\b(?:we\s+)?(?:do\s+not|don'?t|never|neither|cannot)\s+(?:collect|track|store|record|access|share|sell|gather|transmit|monitor|use)\b", re.IGNORECASE),
    re.compile(r"\bno\s+(?:personal|location|audio|camera|contact|biometric|user)\s+(?:data|information|recordings?)\s+(?:is|are|will\s+be)\s+(?:collected|tracked|stored|shared|accessed)\b", re.IGNORECASE),
    re.compile(r"\bwithout\s+(?:collecting|tracking|storing|accessing)\b", re.IGNORECASE),
    re.compile(r"\bnot\s+(?:read|accessed|harvested|retained)\b", re.IGNORECASE),
    re.compile(r"\bsolely\s+to\s+toggle\s+(?:the\s+)?(?:hardware\s+)?(?:led|torch|flash)\b", re.IGNORECASE),
    re.compile(r"\bno\s+(?:photos|videos|audio|voice)\s+(?:are|is)\s+(?:ever\s+)?(?:captured|stored|transmitted)\b", re.IGNORECASE),
]

# Regex patterns for user consent / opt-in
CONSENT_PATTERNS = [
    re.compile(r"\b(?:with|upon|only\s+with)\s+your\s+(?:explicit\s+)?(?:consent|permission|authorization|approval)\b", re.IGNORECASE),
    re.compile(r"\bif\s+you\s+(?:choose|opt|elect)\s+to\s+(?:share|enable|allow|grant)\b", re.IGNORECASE),
    re.compile(r"\bonly\s+when\s+you\s+(?:actively\s+)?(?:press|tap|request|permit)\b", re.IGNORECASE),
    re.compile(r"\byou\s+can\s+(?:revoke|disable|turn\s+off)\s+(?:this|these)\s+permissions?\b", re.IGNORECASE),
]

# Regex patterns for affirmative collection
COLLECTION_PATTERNS = [
    re.compile(r"\b(?:we\s+)?(?:collect|gather|track|record|store|process|use|receive|access)\b", re.IGNORECASE),
    re.compile(r"\bmay\s+(?:collect|record|use|process|access)\b", re.IGNORECASE),
    re.compile(r"\bto\s+provide\s+(?:navigation|features|routing|services|voice\s+search)\b", re.IGNORECASE),
]


def split_into_sentences(text: str) -> list[tuple[str, str]]:
    """Split text into sentences and track approximate section headings.

    Returns:
        List of tuples: (sentence_text, section_hint)
    """
    if not text:
        return []

    lines = [line.strip() for line in text.split("\n") if line.strip()]
    sentence_records: list[tuple[str, str]] = []
    current_section = "General Policy"

    for line in lines:
        # Detect true section headings:
        # Must be short, end with colon or contain words like 'Section/Privacy Policy', and NOT end with terminal sentence punctuation (. or ?)
        is_heading = (
            (line.endswith(":") and len(line) < 100)
            or (
                len(line) < 60
                and not line.endswith((".", "?", "!"))
                and (
                    bool(re.match(r"^(?:Section\s+[0-9]+|[A-Z\s]{4,}|[0-9]+[\.\)]\s+[A-Za-z\s]+$)", line))
                    or "policy" in line.lower()
                )
            )
        )

        if is_heading:
            current_section = line.rstrip(":")
            continue

        # Split line into sentence chunks using standard terminal punctuation
        raw_sentences = re.split(r"(?<=[.!?])\s+", line)
        for s in raw_sentences:
            s_clean = s.strip()
            if len(s_clean) >= 15:  # Filter out noise fragments
                sentence_records.append((s_clean, current_section))

    return sentence_records


def analyze_sentence_for_domain(
    sentence: str, domain: PrivacyDomain
) -> tuple[PolicyStance | None, float]:
    """Determine whether a sentence addresses a given privacy domain and evaluate its stance.

    Returns:
        (PolicyStance, confidence_score) or (None, 0.0) if not relevant.
    """
    sentence_lower = sentence.lower()
    keywords = DOMAIN_KEYWORDS.get(domain, [])

    # Check if any domain keyword is present in this sentence
    matched_keyword = False
    for kw in keywords:
        if re.search(rf"\b{re.escape(kw)}\b", sentence_lower):
            matched_keyword = True
            break

    if not matched_keyword:
        return None, 0.0

    # 1. Check for explicit denial (Highest Priority)
    for pattern in DENIAL_PATTERNS:
        if pattern.search(sentence):
            return PolicyStance.DENIES_COLLECTION, 0.95

    # 2. Check for consent-gated collection
    for pattern in CONSENT_PATTERNS:
        if pattern.search(sentence):
            return PolicyStance.REQUIRES_CONSENT, 0.85

    # 3. Check for affirmative collection
    for pattern in COLLECTION_PATTERNS:
        if pattern.search(sentence):
            return PolicyStance.CLAIMS_COLLECTION, 0.90

    # Fallback: mentions domain without clear stance
    return PolicyStance.AMBIGUOUS, 0.60


def extract_policy_claims(policy_text: str) -> dict[PrivacyDomain, list[PolicyClaim]]:
    """Analyze privacy policy text and extract structured claims across all privacy domains.

    Args:
        policy_text: Sanitized plain text of the privacy policy.

    Returns:
        Mapping of PrivacyDomain to list of PolicyClaim instances.
    """
    claims_by_domain: dict[PrivacyDomain, list[PolicyClaim]] = {
        dom: [] for dom in PrivacyDomain
    }

    if not policy_text or not policy_text.strip():
        return claims_by_domain

    sentences = split_into_sentences(policy_text)

    for sentence, section_hint in sentences:
        for domain in PrivacyDomain:
            stance, confidence = analyze_sentence_for_domain(sentence, domain)
            if stance is not None:
                claim = PolicyClaim(
                    domain=domain,
                    stance=stance,
                    exact_quote=sentence,
                    section_hint=section_hint,
                    confidence=confidence,
                    source="Rule-Based Extractor",
                )
                claims_by_domain[domain].append(claim)

    return claims_by_domain


def resolve_domain_overall_stance(
    claims: list[PolicyClaim],
) -> tuple[PolicyStance, str, str, float]:
    """Synthesize multiple claims within a single domain into a single representative stance.

    Priority order:
        1. DENIES_COLLECTION (Explicit denials take strict precedence in contradiction audits)
        2. REQUIRES_CONSENT
        3. CLAIMS_COLLECTION
        4. AMBIGUOUS
        5. NOT_MENTIONED

    Returns:
        (overall_stance, best_quote, section_hint, confidence)
    """
    if not claims:
        return (
            PolicyStance.NOT_MENTIONED,
            "No statements regarding this data category were identified in the policy.",
            "Policy Body",
            0.0,
        )

    # Sort claims by priority
    denials = [c for c in claims if c.stance == PolicyStance.DENIES_COLLECTION]
    if denials:
        best = max(denials, key=lambda c: c.confidence)
        return best.stance, best.exact_quote, best.section_hint, best.confidence

    consents = [c for c in claims if c.stance == PolicyStance.REQUIRES_CONSENT]
    if consents:
        best = max(consents, key=lambda c: c.confidence)
        return best.stance, best.exact_quote, best.section_hint, best.confidence

    collections = [c for c in claims if c.stance == PolicyStance.CLAIMS_COLLECTION]
    if collections:
        best = max(collections, key=lambda c: c.confidence)
        return best.stance, best.exact_quote, best.section_hint, best.confidence

    ambiguous = [c for c in claims if c.stance == PolicyStance.AMBIGUOUS]
    if ambiguous:
        best = max(ambiguous, key=lambda c: c.confidence)
        return best.stance, best.exact_quote, best.section_hint, best.confidence

    return (
        PolicyStance.NOT_MENTIONED,
        "No statements regarding this data category were identified in the policy.",
        "Policy Body",
        0.0,
    )
