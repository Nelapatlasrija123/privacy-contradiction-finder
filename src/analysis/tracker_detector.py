"""Third-party SDK (tracker) detection from a user-supplied package list.

A privacy policy may stay silent about third-party sharing, but the SDKs
bundled inside the APK are hard evidence that data flows to outside companies.
This module matches package / class names (e.g. pasted from an Exodus Privacy
report, a jadx package tree, or a Gradle dependency list) against a catalogue
of well-known tracker signatures. Operates 100% locally and offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class TrackerCategory(str, Enum):
    ADVERTISING = "Advertising"
    ANALYTICS = "Analytics"
    ATTRIBUTION = "Attribution / Marketing"
    CRASH_REPORTING = "Crash Reporting"
    SOCIAL = "Social / Identification"


@dataclass(frozen=True)
class TrackerSignature:
    name: str
    company: str
    category: TrackerCategory
    package_prefixes: tuple[str, ...]
    data_typically_shared: str


@dataclass(frozen=True)
class DetectedTracker:
    name: str
    company: str
    category: TrackerCategory
    matched_package: str  # the user input entry that matched
    data_typically_shared: str


# Order matters: more specific signatures must come before generic ones that
# share a prefix (e.g. Facebook Ads before the generic Facebook SDK).
TRACKER_SIGNATURES: list[TrackerSignature] = [
    # --- Google ---
    TrackerSignature(
        name="Google AdMob",
        company="Google",
        category=TrackerCategory.ADVERTISING,
        package_prefixes=("com.google.android.gms.ads", "com.google.ads"),
        data_typically_shared="Advertising ID, device info, IP address and approximate location for ad targeting.",
    ),
    TrackerSignature(
        name="Google Analytics",
        company="Google",
        category=TrackerCategory.ANALYTICS,
        package_prefixes=("com.google.android.gms.analytics",),
        data_typically_shared="App usage events, screen views, device info and identifiers.",
    ),
    TrackerSignature(
        name="Google Firebase Analytics",
        company="Google",
        category=TrackerCategory.ANALYTICS,
        package_prefixes=("com.google.firebase.analytics", "com.google.android.gms.measurement"),
        data_typically_shared="App usage events, app-instance ID, Advertising ID and device info.",
    ),
    TrackerSignature(
        name="Google Firebase Crashlytics",
        company="Google",
        category=TrackerCategory.CRASH_REPORTING,
        package_prefixes=("com.google.firebase.crashlytics", "com.crashlytics"),
        data_typically_shared="Crash stack traces, device model, OS version and an installation identifier.",
    ),
    # --- Meta / Facebook (specific first, generic last) ---
    TrackerSignature(
        name="Facebook Audience Network (Ads)",
        company="Meta",
        category=TrackerCategory.ADVERTISING,
        package_prefixes=("com.facebook.ads",),
        data_typically_shared="Advertising ID, device info and ad interaction data for targeted ads.",
    ),
    TrackerSignature(
        name="Facebook Analytics (App Events)",
        company="Meta",
        category=TrackerCategory.ANALYTICS,
        package_prefixes=("com.facebook.appevents",),
        data_typically_shared="In-app events, purchases, Advertising ID and device info sent to Meta.",
    ),
    TrackerSignature(
        name="Facebook Login / SDK",
        company="Meta",
        category=TrackerCategory.SOCIAL,
        package_prefixes=("com.facebook",),
        data_typically_shared="Facebook account identity, profile data and app usage events.",
    ),
    # --- Attribution / marketing ---
    TrackerSignature(
        name="AppsFlyer",
        company="AppsFlyer",
        category=TrackerCategory.ATTRIBUTION,
        package_prefixes=("com.appsflyer",),
        data_typically_shared="Install source, Advertising ID, device info and in-app events for campaign attribution.",
    ),
    TrackerSignature(
        name="Adjust",
        company="Adjust",
        category=TrackerCategory.ATTRIBUTION,
        package_prefixes=("com.adjust.sdk",),
        data_typically_shared="Install source, Advertising ID, device info and in-app events for campaign attribution.",
    ),
    TrackerSignature(
        name="Branch",
        company="Branch Metrics",
        category=TrackerCategory.ATTRIBUTION,
        package_prefixes=("io.branch",),
        data_typically_shared="Deep-link clicks, install source, device identifiers and IP address.",
    ),
    TrackerSignature(
        name="CleverTap",
        company="CleverTap",
        category=TrackerCategory.ATTRIBUTION,
        package_prefixes=("com.clevertap",),
        data_typically_shared="User profile, in-app events, device info and location for marketing campaigns.",
    ),
    TrackerSignature(
        name="MoEngage",
        company="MoEngage",
        category=TrackerCategory.ATTRIBUTION,
        package_prefixes=("com.moengage",),
        data_typically_shared="User attributes, in-app events and device identifiers for marketing engagement.",
    ),
    TrackerSignature(
        name="OneSignal",
        company="OneSignal",
        category=TrackerCategory.ATTRIBUTION,
        package_prefixes=("com.onesignal",),
        data_typically_shared="Push token, device info, session data and optionally location for messaging.",
    ),
    # --- Advertising networks ---
    TrackerSignature(
        name="Unity Ads",
        company="Unity Technologies",
        category=TrackerCategory.ADVERTISING,
        package_prefixes=("com.unity3d.ads", "com.unity3d.services"),
        data_typically_shared="Advertising ID, device info and ad engagement data.",
    ),
    TrackerSignature(
        name="AppLovin",
        company="AppLovin",
        category=TrackerCategory.ADVERTISING,
        package_prefixes=("com.applovin",),
        data_typically_shared="Advertising ID, device info, IP address and ad engagement data.",
    ),
    TrackerSignature(
        name="ironSource",
        company="Unity Technologies (ironSource)",
        category=TrackerCategory.ADVERTISING,
        package_prefixes=("com.ironsource",),
        data_typically_shared="Advertising ID, device info and ad engagement data for ad mediation.",
    ),
    TrackerSignature(
        name="Chartboost",
        company="Chartboost",
        category=TrackerCategory.ADVERTISING,
        package_prefixes=("com.chartboost",),
        data_typically_shared="Advertising ID, device info and ad engagement data.",
    ),
    TrackerSignature(
        name="InMobi",
        company="InMobi",
        category=TrackerCategory.ADVERTISING,
        package_prefixes=("com.inmobi",),
        data_typically_shared="Advertising ID, device info, location and ad engagement data.",
    ),
    # --- Analytics ---
    TrackerSignature(
        name="Mixpanel",
        company="Mixpanel",
        category=TrackerCategory.ANALYTICS,
        package_prefixes=("com.mixpanel",),
        data_typically_shared="In-app events, user properties and device info.",
    ),
    TrackerSignature(
        name="Amplitude",
        company="Amplitude",
        category=TrackerCategory.ANALYTICS,
        package_prefixes=("com.amplitude",),
        data_typically_shared="In-app events, user properties and device identifiers.",
    ),
    TrackerSignature(
        name="Flurry",
        company="Yahoo",
        category=TrackerCategory.ANALYTICS,
        package_prefixes=("com.flurry",),
        data_typically_shared="Session data, in-app events, device info and Advertising ID.",
    ),
    TrackerSignature(
        name="Segment",
        company="Twilio Segment",
        category=TrackerCategory.ANALYTICS,
        package_prefixes=("com.segment.analytics",),
        data_typically_shared="In-app events and user traits, forwarded to further downstream tools.",
    ),
    # --- Crash reporting ---
    TrackerSignature(
        name="Sentry",
        company="Sentry",
        category=TrackerCategory.CRASH_REPORTING,
        package_prefixes=("io.sentry",),
        data_typically_shared="Error reports, stack traces, device info and breadcrumbs of user actions.",
    ),
]


_GRADLE_KEYWORDS = re.compile(
    r"^(implementation|api|compile|compileonly|runtimeonly|kapt|annotationprocessor)\b\s*",
    re.IGNORECASE,
)
_GOOGLE_ARTIFACT_PREFIXES: dict[str, str] = {
    "com.google.firebase": "firebase-",
    "com.google.android.gms": "play-services-",
}


def _normalize_entry(entry: str) -> str:
    """Clean one entry: strip Gradle keywords/quotes, slashes to dots, gradle coords to group."""
    entry = _GRADLE_KEYWORDS.sub("", entry.strip())
    entry = entry.strip("()'\" \t;")
    entry = entry.replace("/", ".").rstrip(".*").strip()
    if ":" in entry:
        parts = entry.split(":")
        group = parts[0].strip()
        artifact = parts[1].strip().lower() if len(parts) > 1 else ""
        # Google groups are too broad; refine using the artifact name,
        # e.g. com.google.firebase:firebase-analytics -> com.google.firebase.analytics
        prefix = _GOOGLE_ARTIFACT_PREFIXES.get(group.lower())
        if prefix and artifact.startswith(prefix):
            suffix = artifact[len(prefix):]
            if suffix.endswith("-ktx"):
                suffix = suffix[: -len("-ktx")]
            if suffix:
                return f"{group}.{suffix.replace('-', '.')}"
        return group
    return entry


def parse_sdk_input(raw: str) -> list[str]:
    """Split raw SDK text into clean, de-duplicated package entries (input order kept)."""
    entries: list[str] = []
    seen: set[str] = set()
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for piece in line.split(","):
            entry = _normalize_entry(piece)
            if not entry or entry.startswith("#"):
                continue
            key = entry.lower()
            if key not in seen:
                seen.add(key)
                entries.append(entry)
    return entries


def _matches_prefix(entry: str, prefix: str) -> bool:
    """Case-insensitive prefix match on a dotted boundary."""
    entry, prefix = entry.lower(), prefix.lower()
    return entry == prefix or entry.startswith(prefix + ".")


def _find_signature(entry: str) -> TrackerSignature | None:
    """Return the first (most specific) signature matching an entry."""
    for signature in TRACKER_SIGNATURES:
        if any(_matches_prefix(entry, p) for p in signature.package_prefixes):
            return signature
    return None


def detect_trackers(sdk_entries: list[str]) -> list[DetectedTracker]:
    """Detect known trackers; one result per tracker, ordered by first matching entry."""
    results: list[DetectedTracker] = []
    found: set[str] = set()
    for entry in sdk_entries:
        signature = _find_signature(entry)
        if signature is None or signature.name in found:
            continue
        found.add(signature.name)
        results.append(
            DetectedTracker(
                name=signature.name,
                company=signature.company,
                category=signature.category,
                matched_package=entry,
                data_typically_shared=signature.data_typically_shared,
            )
        )
    return results
