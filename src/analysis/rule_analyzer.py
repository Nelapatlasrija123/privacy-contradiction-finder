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
        # Bare "contact" is deliberately excluded: "contact us at ..." appears in almost every
        # policy and would otherwise be mistaken for a disclosure about the address book.
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
        "sms",
        "text messages",
        "otp",
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
    PrivacyDomain.THIRD_PARTY_SHARING: [
        "third party",
        "third parties",
        "third-party",
        "partner",
        "partners",
        "advertiser",
        "advertisers",
        "advertising",
        "ads",
        "affiliates",
        "service providers",
        "analytics",
        "sdk",
        "sdks",
        "share",
        "shared",
        "sharing",
        "sell",
        "sold",
        "disclose",
        "disclosed",
    ],
}

# Verbs that describe gathering data on the device vs. passing it on to someone else.
# Keeping them apart stops "we never sell your location" from being read as "we never collect it".
COLLECTION_VERBS = (
    "collect", "track", "store", "record", "access", "gather", "transmit", "monitor",
    "use", "read", "upload", "capture", "save", "retain", "harvest", "request",
)
SHARING_VERBS = ("share", "sell", "disclose", "rent", "trade", "transfer")

_VERB = r"(?:" + "|".join(COLLECTION_VERBS + SHARING_VERBS) + r")"

# Negation followed by a verb list, e.g. "do not collect, track, or share"
NEGATED_VERB_CHAIN = re.compile(
    r"\b(?:do\s+not|does\s+not|did\s+not|don[’']?t|doesn[’']?t|never|will\s+not|won[’']?t|"
    r"shall\s+not|cannot|can\s?not|neither)\s+"
    r"(?:(?:ever|actively|knowingly|intentionally|otherwise)\s+)?"
    r"((?:" + _VERB + r"(?:,\s*|\s+)(?:(?:or|and|nor)\s+)?)*" + _VERB + r")\b",
    re.IGNORECASE,
)

# Other phrasings that deny collection outright
DENIAL_PATTERNS = [
    re.compile(r"\bno\s+(?:personal|location|audio|camera|contact|biometric|user)\s+(?:data|information|recordings?)\s+(?:is|are|will\s+be)\s+(?:collected|tracked|stored|accessed)\b", re.IGNORECASE),
    re.compile(r"\bwithout\s+(?:collecting|tracking|storing|accessing)\b", re.IGNORECASE),
    re.compile(r"\bnot\s+(?:read|accessed|harvested|retained)\b", re.IGNORECASE),
    re.compile(r"\bsolely\s+to\s+toggle\s+(?:the\s+)?(?:hardware\s+)?(?:led|torch|flash)\b", re.IGNORECASE),
    re.compile(r"\bno\s+(?:photos|videos|audio|voice)\s+(?:are|is)\s+(?:ever\s+)?(?:captured|stored|transmitted)\b", re.IGNORECASE),
]

# Phrasings that deny passing data to anyone else
SHARING_DENIAL_PATTERNS = [
    re.compile(r"\bno\s+(?:\w+\s+){0,2}(?:data|information)\s+(?:is|are|will\s+be)\s+(?:ever\s+)?(?:\w+\s+or\s+)?(?:shared|sold|disclosed|rented)\b", re.IGNORECASE),
    re.compile(r"\b(?:not|never)\s+(?:be\s+)?(?:shared|sold|disclosed|rented)\b", re.IGNORECASE),
]

# Phrasings that admit passing data to someone else
SHARING_PATTERNS = [
    re.compile(r"\b(?:share|sell|disclose|transfer|provide)s?\b[^.]*\b(?:third[\s-]part(?:y|ies)|partners?|advertis\w*|affiliates?|service\s+providers?|analytics)\b", re.IGNORECASE),
    re.compile(r"\b(?:is|are|may\s+be|will\s+be)\s+(?:shared|sold|disclosed|transferred)\b", re.IGNORECASE),
    re.compile(r"\b(?:use|uses|work\s+with|partner\s+with|integrate)\b[^.]*\b(?:third[\s-]part\w*|advertis\w*|analytics|sdks?)\b", re.IGNORECASE),
]

# Names of outside recipients; a sharing statement only counts when one of these is involved
THIRD_PARTY_TERMS = re.compile(
    r"\b(?:third[\s-]part(?:y|ies)|partners?|advertis\w*|ads|affiliates?|service\s+providers?|"
    r"analytics|sdks?|sell|sells|sold)\b",
    re.IGNORECASE,
)

# Contrast words split a sentence into clauses so a negation only applies to its own clause:
# "We collect your location, but we never sell it" -> two clauses with different stances.
CLAUSE_SPLITTER = re.compile(r"\s*;\s*|,?\s+\b(?:but|however|although|though|whereas|except\s+that)\b\s+", re.IGNORECASE)

# Regex patterns for user consent / opt-in
CONSENT_PATTERNS = [
    re.compile(r"\b(?:with|upon|only\s+with)\s+your\s+(?:explicit\s+)?(?:consent|permission|authorization|approval)\b", re.IGNORECASE),
    re.compile(r"\bif\s+you\s+(?:choose|opt|elect)\s+to\s+(?:share|enable|allow|grant)\b", re.IGNORECASE),
    re.compile(r"\bonly\s+when\s+you\s+(?:actively\s+)?(?:press|tap|request|permit)\b", re.IGNORECASE),
    re.compile(r"\byou\s+can\s+(?:revoke|disable|turn\s+off)\s+(?:this|these)\s+permissions?\b", re.IGNORECASE),
]

# Regex patterns for affirmative collection.
# Weak verbs ("use", "access") only count when the company is the subject, so a sentence like
# "You can use the microphone button" is not mistaken for a disclosure.
COLLECTION_PATTERNS = [
    re.compile(r"\b(?:we|the\s+app|this\s+app|our\s+app)\s+(?:may\s+|also\s+|will\s+|can\s+)?(?:collect|gather|track|record|store|process|use|receive|access|obtain|request)s?\b", re.IGNORECASE),
    re.compile(r"\b(?:is|are|may\s+be|will\s+be)\s+(?:collected|gathered|tracked|recorded|stored|processed|obtained)\b", re.IGNORECASE),
    re.compile(r"\b(?:collect|gather|track|record)(?:s|ed|ing)?\b", re.IGNORECASE),
    re.compile(r"\bto\s+provide\s+(?:navigation|features|routing|services|voice\s+search)\b", re.IGNORECASE),
    # Purpose statements: "the camera permission is required solely to activate the torch"
    re.compile(r"\b(?:is|are)\s+(?:required|requested|used|needed)\s+(?:solely\s+|only\s+)?(?:to|for)\b", re.IGNORECASE),
]

# A denial with a condition attached is a limit on use, not a blanket denial:
# "We do not track your location without your active initiation" is consent-gating.
QUALIFIED_DENIAL = re.compile(
    r"\b(?:without\s+your|unless|except\s+(?:when|with|if)|when\s+you\s+are\s+not|while\s+you\s+are\s+not|"
    r"other\s+than|in\s+the\s+background)\b",
    re.IGNORECASE,
)


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
    keywords = DOMAIN_KEYWORDS.get(domain, [])

    # Only clauses that actually name the domain are judged, so a negation in a
    # neighbouring clause ("..., but we never sell it") cannot flip this domain's stance.
    clauses = [c for c in CLAUSE_SPLITTER.split(sentence) if c and c.strip()]
    relevant = [c for c in clauses if _mentions_any(c, keywords)]
    if domain == PrivacyDomain.THIRD_PARTY_SHARING:
        # "You can share photos with the community" is the user sharing, not the company passing data on.
        # Keep only clauses that name an outside party or deny sharing outright.
        relevant = [c for c in relevant if THIRD_PARTY_TERMS.search(c) or _is_sharing_denial(c)]
    if not relevant:
        return None, 0.0

    stances = [_clause_stance(c, domain) for c in relevant]
    for stance, confidence in (
        (PolicyStance.DENIES_COLLECTION, 0.95),
        (PolicyStance.REQUIRES_CONSENT, 0.85),
        (PolicyStance.CLAIMS_COLLECTION, 0.90),
    ):
        if stance in stances:
            return stance, confidence

    # Fallback: mentions domain without clear stance
    return PolicyStance.AMBIGUOUS, 0.60


def _mentions_any(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(re.search(rf"\b{re.escape(kw)}\b", text_lower) for kw in keywords)


def _denied_verbs(clause: str) -> set[str]:
    """Return the verbs negated in a clause, e.g. {"collect", "share"} for "we do not collect or share"."""
    denied: set[str] = set()
    for match in NEGATED_VERB_CHAIN.finditer(clause):
        denied.update(v.lower() for v in re.findall(_VERB, match.group(1), re.IGNORECASE))
    return denied


def _is_sharing_denial(clause: str) -> bool:
    return bool(_denied_verbs(clause) & set(SHARING_VERBS)) or any(
        p.search(clause) for p in SHARING_DENIAL_PATTERNS
    )


def _clause_stance(clause: str, domain: PrivacyDomain) -> PolicyStance:
    """Classify one clause. Sharing statements are judged separately from collection statements."""
    denied = _denied_verbs(clause)
    is_sharing_domain = domain == PrivacyDomain.THIRD_PARTY_SHARING

    if is_sharing_domain:
        is_denial = _is_sharing_denial(clause)
    else:
        is_denial = bool(denied & set(COLLECTION_VERBS)) or any(p.search(clause) for p in DENIAL_PATTERNS)
    if is_denial:
        if QUALIFIED_DENIAL.search(clause):
            return PolicyStance.REQUIRES_CONSENT
        return PolicyStance.DENIES_COLLECTION

    if any(p.search(clause) for p in CONSENT_PATTERNS):
        return PolicyStance.REQUIRES_CONSENT

    affirmative = SHARING_PATTERNS if is_sharing_domain else COLLECTION_PATTERNS
    # A verb that sits inside a negation ("we never record") is not an admission.
    clause_without_negations = NEGATED_VERB_CHAIN.sub(" ", clause)
    if any(p.search(clause_without_negations) for p in affirmative):
        return PolicyStance.CLAIMS_COLLECTION

    return PolicyStance.AMBIGUOUS


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
