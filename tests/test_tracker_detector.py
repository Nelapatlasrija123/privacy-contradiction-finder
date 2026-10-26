"""Unit tests for the third-party SDK (tracker) detector."""

from __future__ import annotations

from src.analysis.tracker_detector import (
    TRACKER_SIGNATURES,
    DetectedTracker,
    TrackerCategory,
    detect_trackers,
    parse_sdk_input,
)


# ---------------------------------------------------------
# Parsing
# ---------------------------------------------------------

def test_parse_newlines_and_commas():
    raw = "com.appsflyer\ncom.mixpanel.android, io.sentry\n"
    assert parse_sdk_input(raw) == ["com.appsflyer", "com.mixpanel.android", "io.sentry"]


def test_parse_gradle_coordinates_to_group():
    raw = "com.facebook.android:facebook-android-sdk:16.0.0\ncom.appsflyer:af-android-sdk:6.12.1"
    assert parse_sdk_input(raw) == ["com.facebook.android", "com.appsflyer"]


def test_parse_skips_comments_blanks_and_dupes():
    raw = "# trackers from Exodus\n\n   \ncom.appsflyer\ncom.appsflyer\n  # another comment\ncom.onesignal"
    assert parse_sdk_input(raw) == ["com.appsflyer", "com.onesignal"]


def test_parse_empty_input():
    assert parse_sdk_input("") == []
    assert parse_sdk_input("  \n # only comment\n") == []


# ---------------------------------------------------------
# Detection
# ---------------------------------------------------------

def test_detect_firebase_admob_appsflyer():
    entries = [
        "com.google.firebase.analytics.FirebaseAnalytics",
        "com.google.android.gms.ads.AdView",
        "com.appsflyer.AppsFlyerLib",
    ]
    results = detect_trackers(entries)
    assert [r.name for r in results] == ["Google Firebase Analytics", "Google AdMob", "AppsFlyer"]
    assert results[1].category == TrackerCategory.ADVERTISING
    assert results[2].category == TrackerCategory.ATTRIBUTION
    assert results[0].matched_package == entries[0]
    assert all(isinstance(r, DetectedTracker) for r in results)


def test_no_false_match_across_dotted_boundary():
    assert detect_trackers(["com.facebookx.foo", "com.appsflyerclone"]) == []


def test_case_insensitive_match():
    results = detect_trackers(["COM.AppsFlyer.SDK"])
    assert len(results) == 1 and results[0].name == "AppsFlyer"


def test_empty_entries():
    assert detect_trackers([]) == []


def test_one_result_per_tracker():
    results = detect_trackers(["com.appsflyer.a", "com.appsflyer.b", "com.appsflyer"])
    assert len(results) == 1
    assert results[0].matched_package == "com.appsflyer.a"


def test_specific_facebook_signature_wins():
    results = detect_trackers(["com.facebook.ads.AdView", "com.facebook.login.LoginManager"])
    assert [r.name for r in results] == ["Facebook Audience Network (Ads)", "Facebook Login / SDK"]


def test_end_to_end_gradle_firebase_artifacts():
    raw = "com.google.firebase:firebase-crashlytics-ktx:18.6.0\ncom.google.android.gms:play-services-ads:22.6.0"
    names = [r.name for r in detect_trackers(parse_sdk_input(raw))]
    assert names == ["Google Firebase Crashlytics", "Google AdMob"]


def test_signature_catalogue_is_sane():
    assert len(TRACKER_SIGNATURES) >= 20
    assert len({s.name for s in TRACKER_SIGNATURES}) == len(TRACKER_SIGNATURES)
