"""Unit tests for the Terms & Conditions clause analyzer."""

from __future__ import annotations

import pytest

from src.permissions.permission_db import PrivacyDomain
from src.analysis.terms_analyzer import (
    TermsClause,
    TermsClauseType,
    analyze_terms,
    related_permissions_note,
)


# ---------------------------------------------------------
# Clause detection
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "sentence, expected",
    [
        (
            "By using the app you agree to our Privacy Policy, which is incorporated into these Terms by reference.",
            TermsClauseType.INCORPORATES_PRIVACY_POLICY,
        ),
        (
            "You grant us a worldwide, royalty-free licence to use, reproduce and distribute any content you upload.",
            TermsClauseType.CONTENT_LICENSE,
        ),
        (
            "You consent to the collection and processing of your personal data as described herein.",
            TermsClauseType.CONSENT_TO_COLLECTION,
        ),
        (
            "We may share your information with third-party advertisers and marketing partners.",
            TermsClauseType.THIRD_PARTY_SHARING,
        ),
        (
            "We may modify these terms at any time without notice.",
            TermsClauseType.UNILATERAL_CHANGES,
        ),
    ],
)
def test_each_clause_type_detected(sentence: str, expected: TermsClauseType):
    clauses = analyze_terms(sentence)
    match = next(c for c in clauses if c.clause_type is expected)
    assert match.exact_quote == sentence
    assert match.permission_link


def test_content_license_photos_maps_to_storage_and_camera():
    text = "You grant us a non-exclusive, royalty-free license to the photos you upload to the service."
    clause = next(c for c in analyze_terms(text) if c.clause_type is TermsClauseType.CONTENT_LICENSE)
    assert set(clause.related_domains) == {PrivacyDomain.STORAGE_FILES, PrivacyDomain.CAMERA}


def test_content_license_voice_recordings_maps_to_microphone():
    text = "You grant us a perpetual licence to use any voice recordings you submit through the app."
    clause = next(c for c in analyze_terms(text) if c.clause_type is TermsClauseType.CONTENT_LICENSE)
    assert clause.related_domains == (PrivacyDomain.MICROPHONE,)


def test_content_license_defaults_to_storage():
    text = "You grant us a royalty-free licence to any content you post on the platform."
    clause = next(c for c in analyze_terms(text) if c.clause_type is TermsClauseType.CONTENT_LICENSE)
    assert clause.related_domains == (PrivacyDomain.STORAGE_FILES,)


def test_third_party_domain_and_all_applicable_clauses():
    text = (
        "We may share your information with third-party advertisers. "
        "We may modify these terms at any time without notice."
    )
    clauses = {c.clause_type: c for c in analyze_terms(text)}
    assert clauses[TermsClauseType.THIRD_PARTY_SHARING].related_domains == (
        PrivacyDomain.THIRD_PARTY_SHARING,
    )
    assert clauses[TermsClauseType.UNILATERAL_CHANGES].related_domains == ()


def test_unrelated_sentence_yields_nothing():
    assert analyze_terms("These terms are governed by the laws of India.") == []


@pytest.mark.parametrize("text", ["", "   \n  "])
def test_empty_text_returns_empty_list(text: str):
    assert analyze_terms(text) == []


def test_section_hint_tracked():
    text = "CONTENT RIGHTS\nYou grant us a royalty-free licence to the photos you upload."
    clause = analyze_terms(text)[0]
    assert clause.section_hint == "CONTENT RIGHTS"


# ---------------------------------------------------------
# related_permissions_note
# ---------------------------------------------------------

def test_related_permissions_note_filters_by_domain_and_dedupes():
    text = (
        "You grant us a royalty-free licence to the voice recordings you submit. "
        "We may share your information with third-party advertisers. "
        "We may modify these terms at any time without notice. "
        "We may change these terms from time to time at our sole discretion."
    )
    clauses = analyze_terms(text)

    # Only the all-applicable unilateral-change clauses survive; the two dedupe to one note.
    notes = related_permissions_note(clauses, {PrivacyDomain.LOCATION})
    assert len(notes) == 1
    assert TermsClauseType.UNILATERAL_CHANGES.value in notes[0]

    notes = related_permissions_note(
        clauses, {PrivacyDomain.MICROPHONE, PrivacyDomain.THIRD_PARTY_SHARING}
    )
    assert len(notes) == 3
    assert any(TermsClauseType.CONTENT_LICENSE.value in n for n in notes)
    assert any(TermsClauseType.THIRD_PARTY_SHARING.value in n for n in notes)
    assert len(notes) == len(set(notes))


def test_related_permissions_note_empty_clauses():
    assert related_permissions_note([], {PrivacyDomain.CAMERA}) == []


def test_terms_clause_is_frozen():
    clause = TermsClause(
        clause_type=TermsClauseType.UNILATERAL_CHANGES,
        exact_quote="x",
        section_hint="General Policy",
        related_domains=(),
        permission_link="y",
    )
    with pytest.raises(Exception):
        clause.exact_quote = "z"  # type: ignore[misc]
