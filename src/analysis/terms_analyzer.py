"""Terms & Conditions clause analyzer.

Explains the relationship between an app's Terms and Conditions (the user
contract), its privacy policy (the data disclosure) and its Android permissions
(the technical capability). The three connect through specific T&C clauses:

1. Incorporation of the privacy policy by reference ("by using the app you agree
   to our Privacy Policy") - the policy becomes part of the contract.
2. Licences over user content (photos, videos, recordings) - these make CAMERA,
   MICROPHONE and STORAGE permissions more significant.
3. Blanket consent to data collection / processing.
4. Third-party sharing / advertising clauses.
5. Unilateral change clauses - which weaken any promise made in the policy.

Operates 100% locally with deterministic, case-insensitive regular expressions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from src.analysis.rule_analyzer import split_into_sentences
from src.permissions.permission_db import PrivacyDomain


class TermsClauseType(str, Enum):
    INCORPORATES_PRIVACY_POLICY = "Incorporates Privacy Policy by Reference"
    CONTENT_LICENSE = "Licence Over User Content"
    CONSENT_TO_COLLECTION = "Blanket Consent to Data Collection"
    THIRD_PARTY_SHARING = "Third-Party Sharing / Advertising"
    UNILATERAL_CHANGES = "Unilateral Right to Change Terms"


@dataclass(frozen=True)
class TermsClause:
    clause_type: TermsClauseType
    exact_quote: str  # verbatim sentence from the input
    section_hint: str
    related_domains: tuple[PrivacyDomain, ...]
    permission_link: str  # plain-English link between this clause and app permissions


# ---------------------------------------------------------
# Clause detection patterns (flat alternations only - no nested quantifiers)
# ---------------------------------------------------------

_I = re.IGNORECASE

_PRIVACY_POLICY_RE = re.compile(
    r"\b(?:privacy\s+(?:policy|notice|statement)|data\s+(?:policy|protection\s+policy))\b", _I
)
_INCORPORATION_RE = re.compile(
    r"\b(?:incorporat\w*|by\s+reference|forms?\s+(?:an?\s+)?(?:integral\s+)?part\s+of|"
    r"agree\w*|accept\w*|subject\s+to|bound\s+by|consent\w*)\b",
    _I,
)

_LICENSE_RE = re.compile(
    r"\b(?:licen[cs]e\w*|sub-?licen[cs]\w*|royalty[\s-]free|perpetual\s+right|"
    r"irrevocable\s+right|right\s+to\s+(?:use|reproduce|modify|distribute))\b",
    _I,
)
_CONTENT_RE = re.compile(
    r"\b(?:content|photos?|photographs?|pictures?|images?|videos?|recordings?|audio|"
    r"voice|uploads?|uploaded|submissions?|submit\w*|posts?|media|files?)\b",
    _I,
)
_VISUAL_MEDIA_RE = re.compile(r"\b(?:photos?|photographs?|pictures?|images?|videos?|selfies?)\b", _I)
_AUDIO_MEDIA_RE = re.compile(r"\b(?:voice|audio|recordings?|sound|speech)\b", _I)

_CONSENT_RE = re.compile(r"\b(?:consent\w*|agree\w*|authori[sz]\w*|acknowledg\w*|permit)\b", _I)
_COLLECTION_RE = re.compile(
    r"\b(?:collect\w*|process\w*|stor(?:e|es|ed|age|ing)|use\s+of|access\w*)\b", _I
)
_DATA_RE = re.compile(r"\b(?:data|information|details)\b", _I)

_THIRD_PARTY_RE = re.compile(
    r"\b(?:third[\s-]part(?:y|ies)|advertis\w*|ad\s+networks?|"
    r"marketing\s+partners?|business\s+partners?|affiliates?|sponsors?)\b",
    _I,
)
_SELL_SHARE_RE = re.compile(r"\b(?:sell|sold|rent|share|shared|disclose|transfer)\b", _I)

_CHANGE_VERB_RE = re.compile(
    r"\b(?:modify|modif\w+|change\w*|amend\w*|update\w*|revis\w*|alter\w*|replace)\b", _I
)
_UNILATERAL_RE = re.compile(
    r"\b(?:at\s+any\s+time|(?:our|its)\s+(?:sole\s+|absolute\s+)?discretion|"
    r"without\s+(?:prior\s+|any\s+|advance\s+)?notice|from\s+time\s+to\s+time|"
    r"continued\s+use)\b",
    _I,
)


# ---------------------------------------------------------
# Plain-English links to permissions
# ---------------------------------------------------------

_PERMISSION_LINKS: dict[TermsClauseType, str] = {
    TermsClauseType.INCORPORATES_PRIVACY_POLICY: (
        "The T&C make the privacy policy part of the user contract, so every permission the app "
        "requests is governed by what that policy discloses, and any gap between policy and "
        "permissions becomes a gap in the contract the user accepted."
    ),
    TermsClauseType.CONSENT_TO_COLLECTION: (
        "Accepting the T&C is treated as blanket consent to data collection, so data exposed by "
        "any granted permission may be collected without a separate, specific opt-in."
    ),
    TermsClauseType.THIRD_PARTY_SHARING: (
        "The T&C allow data to flow to third parties or advertisers, so data obtained through the "
        "app's permissions may leave the app's control once it is collected."
    ),
    TermsClauseType.UNILATERAL_CHANGES: (
        "The provider can change the terms unilaterally, so any limit the privacy policy places on "
        "how permission-gated data is used can be withdrawn later without fresh consent."
    ),
}


def _content_license_domains(sentence: str) -> tuple[PrivacyDomain, ...]:
    domains: list[PrivacyDomain] = []
    if _VISUAL_MEDIA_RE.search(sentence):
        domains.extend([PrivacyDomain.STORAGE_FILES, PrivacyDomain.CAMERA])
    if _AUDIO_MEDIA_RE.search(sentence):
        domains.append(PrivacyDomain.MICROPHONE)
    if not domains:
        domains.append(PrivacyDomain.STORAGE_FILES)
    return tuple(domains)


def _content_license_link(domains: tuple[PrivacyDomain, ...]) -> str:
    names = ", ".join(d.value for d in domains)
    return (
        "The T&C grant the provider a licence over user content, which raises the stakes of the "
        f"permissions that capture or read that content ({names}): material obtained through "
        "them can be reused by the provider, not just processed for the user."
    )


def _detect_clause_types(sentence: str) -> list[TermsClauseType]:
    found: list[TermsClauseType] = []
    if _PRIVACY_POLICY_RE.search(sentence) and _INCORPORATION_RE.search(sentence):
        found.append(TermsClauseType.INCORPORATES_PRIVACY_POLICY)
    if _LICENSE_RE.search(sentence) and _CONTENT_RE.search(sentence):
        found.append(TermsClauseType.CONTENT_LICENSE)
    if _CONSENT_RE.search(sentence) and _COLLECTION_RE.search(sentence) and _DATA_RE.search(sentence):
        found.append(TermsClauseType.CONSENT_TO_COLLECTION)
    if _THIRD_PARTY_RE.search(sentence) or (
        _SELL_SHARE_RE.search(sentence) and _DATA_RE.search(sentence)
    ):
        found.append(TermsClauseType.THIRD_PARTY_SHARING)
    if _CHANGE_VERB_RE.search(sentence) and _UNILATERAL_RE.search(sentence):
        found.append(TermsClauseType.UNILATERAL_CHANGES)
    return found


def analyze_terms(terms_text: str) -> list[TermsClause]:
    """Scan Terms & Conditions text for clauses that connect the contract to app permissions.

    Returns:
        List of TermsClause in document order. Empty/blank input returns [].
    """
    if not terms_text or not terms_text.strip():
        return []

    clauses: list[TermsClause] = []
    for sentence, section in split_into_sentences(terms_text):
        for clause_type in _detect_clause_types(sentence):
            if clause_type is TermsClauseType.CONTENT_LICENSE:
                domains = _content_license_domains(sentence)
                link = _content_license_link(domains)
            elif clause_type is TermsClauseType.THIRD_PARTY_SHARING:
                domains = (PrivacyDomain.THIRD_PARTY_SHARING,)
                link = _PERMISSION_LINKS[clause_type]
            else:
                domains = ()
                link = _PERMISSION_LINKS[clause_type]
            clauses.append(
                TermsClause(
                    clause_type=clause_type,
                    exact_quote=sentence,
                    section_hint=section,
                    related_domains=domains,
                    permission_link=link,
                )
            )
    return clauses


def related_permissions_note(
    clauses: list[TermsClause], permission_domains: set[PrivacyDomain]
) -> list[str]:
    """Build short notes for clauses relevant to the app's requested permission domains.

    A clause is relevant when its related_domains intersect permission_domains, or when it
    has no related_domains (it applies to all permissions). Notes are deduplicated in order.
    """
    notes: list[str] = []
    seen: set[str] = set()
    for clause in clauses:
        if clause.related_domains:
            matched = [d.value for d in clause.related_domains if d in permission_domains]
            if not matched:
                continue
            note = f"{clause.clause_type.value} (affects: {', '.join(matched)}): {clause.permission_link}"
        else:
            note = f"{clause.clause_type.value} (affects all permissions): {clause.permission_link}"
        if note not in seen:
            seen.add(note)
            notes.append(note)
    return notes
