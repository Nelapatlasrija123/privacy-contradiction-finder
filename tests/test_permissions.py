"""Unit tests for Android Permission Knowledge Base and capability mapper."""

from __future__ import annotations

import pytest

from src.permissions.permission_db import (
    PrivacyDomain,
    ProtectionLevel,
    PermissionInfo,
    PERMISSION_KNOWLEDGE_BASE,
    normalize_permission_name,
    get_permission_info,
    explain_evidence_source,
)


def test_normalize_permission_name():
    assert normalize_permission_name("android.permission.CAMERA") == "CAMERA"
    assert normalize_permission_name("  access_fine_location  ") == "ACCESS_FINE_LOCATION"
    assert normalize_permission_name("android.permission.READ_CONTACTS") == "READ_CONTACTS"
    assert normalize_permission_name("com.example.CUSTOM_TRACKER") == "CUSTOM_TRACKER"
    assert normalize_permission_name("") == ""
    assert normalize_permission_name(None) == ""


def test_known_permissions_in_knowledge_base():
    required_keys = [
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
        "CAMERA",
        "RECORD_AUDIO",
        "READ_CONTACTS",
        "READ_PHONE_STATE",
        "READ_MEDIA_IMAGES",
        "BODY_SENSORS",
        "BLUETOOTH_CONNECT",
        "ACCESS_NETWORK_STATE",
    ]
    for key in required_keys:
        assert key in PERMISSION_KNOWLEDGE_BASE
        info = PERMISSION_KNOWLEDGE_BASE[key]
        assert isinstance(info, PermissionInfo)
        assert info.what_it_allows
        assert info.what_it_does_not_prove
        assert info.inherent_privacy_risk in ("High", "Medium", "Low")


def test_permission_capabilities_and_limitations():
    loc_info = get_permission_info("android.permission.ACCESS_FINE_LOCATION")
    assert loc_info.domain == PrivacyDomain.LOCATION
    assert loc_info.protection_level == ProtectionLevel.DANGEROUS
    assert "GPS" in loc_info.what_it_allows
    assert "not prove" in loc_info.what_it_does_not_prove.lower()

    audio_info = get_permission_info("RECORD_AUDIO")
    assert audio_info.domain == PrivacyDomain.MICROPHONE
    assert audio_info.inherent_privacy_risk == "High"
    assert "microphone" in audio_info.what_it_allows.lower()
    assert "eavesdropping" in audio_info.what_it_does_not_prove.lower()


def test_unrecognized_custom_permission_fallback():
    custom = get_permission_info("com.random.VENDOR_SPECIFIC_PERM")
    assert custom.name == "VENDOR_SPECIFIC_PERM"
    assert custom.domain == PrivacyDomain.SYSTEM_OTHER
    assert custom.inherent_privacy_risk == "Low"
    assert "Custom or platform-specific" in custom.short_description


def test_explain_evidence_source():
    manifest_eval = explain_evidence_source("Decompiled AndroidManifest.xml (Static Analysis)")
    assert "Static AndroidManifest.xml" in manifest_eval["source_type"]
    assert "High" in manifest_eval["evidentiary_weight"]
    assert "can ask for" in manifest_eval["caveat"].lower()

    runtime_eval = explain_evidence_source("Observed Runtime Request (Dynamic Analysis)")
    assert "Very High" in runtime_eval["evidentiary_weight"]
    assert "network traffic" in runtime_eval["caveat"].lower()

    manual_eval = explain_evidence_source("User Manual Entry")
    assert "Unverified" in manual_eval["evidentiary_weight"]
