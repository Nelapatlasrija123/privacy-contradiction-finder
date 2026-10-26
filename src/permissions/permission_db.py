"""Android Permission Knowledge Base and Capability Mapping.

Defines exact Android OS technical capabilities, protection levels, and critical
limitations for permissions across all primary privacy domains.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PrivacyDomain(str, Enum):
    LOCATION = "Location"
    CAMERA = "Camera"
    MICROPHONE = "Microphone & Audio"
    CONTACTS = "Contacts & Address Book"
    STORAGE_FILES = "Photos, Files & Storage"
    PHONE_TELEPHONY = "Phone State & Telephony"
    BIOMETRICS_SENSORS = "Biometrics & Body Sensors"
    CONNECTIVITY_NETWORK = "Network & Connectivity"
    SYSTEM_OTHER = "System & Other"


class ProtectionLevel(str, Enum):
    DANGEROUS = "Dangerous (Runtime Consent Required)"
    NORMAL = "Normal (Install-Time Auto Grant)"
    SIGNATURE = "Signature (Restricted to Developer Key)"
    SPECIAL = "Special App Access"


@dataclass(frozen=True)
class PermissionInfo:
    name: str
    domain: PrivacyDomain
    protection_level: ProtectionLevel
    short_description: str
    what_it_allows: str
    what_it_does_not_prove: str
    inherent_privacy_risk: str  # "High", "Medium", "Low"

    @property
    def full_name(self) -> str:
        if self.name.startswith("android.permission."):
            return self.name
        return f"android.permission.{self.name}"


# Comprehensive knowledge base of sensitive Android permissions
PERMISSION_KNOWLEDGE_BASE: dict[str, PermissionInfo] = {
    # ---------------- LOCATION DOMAIN ----------------
    "ACCESS_FINE_LOCATION": PermissionInfo(
        name="ACCESS_FINE_LOCATION",
        domain=PrivacyDomain.LOCATION,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Precise GPS coordinates access",
        what_it_allows=(
            "Allows the app to access high-accuracy geographic position using Global Positioning "
            "System (GPS), Wi-Fi BSSID scanning, and cellular cell tower triangulation. "
            "Can determine user position down to meters."
        ),
        what_it_does_not_prove=(
            "Does not prove that the app continuously tracks location or transmits coordinates "
            "to any external server. The app could query location once for a local calculation "
            "(e.g., sunrise time or local weather cache) without saving or exporting it."
        ),
        inherent_privacy_risk="High",
    ),
    "ACCESS_COARSE_LOCATION": PermissionInfo(
        name="ACCESS_COARSE_LOCATION",
        domain=PrivacyDomain.LOCATION,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Approximate cell/Wi-Fi location access",
        what_it_allows=(
            "Allows the app to determine approximate location using cell towers and Wi-Fi networks. "
            "Accuracy is typically within an area of a few city blocks (approx. 2 square kilometers)."
        ),
        what_it_does_not_prove=(
            "Does not prove continuous tracking or remote transmission. Often requested by ad SDKs "
            "or regional content providers strictly for localization."
        ),
        inherent_privacy_risk="Medium",
    ),
    "ACCESS_BACKGROUND_LOCATION": PermissionInfo(
        name="ACCESS_BACKGROUND_LOCATION",
        domain=PrivacyDomain.LOCATION,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Persistent location access while app is not in focus",
        what_it_allows=(
            "Allows the app to receive geographic location updates periodically even when the app is "
            "minimized or the phone screen is locked (Android 10+)."
        ),
        what_it_does_not_prove=(
            "Does not prove the app is collecting secret logs or selling location history. "
            "May be required for genuine continuous services like ride tracking, running logs, or geofencing."
        ),
        inherent_privacy_risk="High",
    ),

    # ---------------- CAMERA DOMAIN ----------------
    "CAMERA": PermissionInfo(
        name="CAMERA",
        domain=PrivacyDomain.CAMERA,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Device camera hardware access",
        what_it_allows=(
            "Allows the application to activate the camera sensor, capture photographs, and stream "
            "video frames into application memory."
        ),
        what_it_does_not_prove=(
            "Does not prove the app is secretly photographing the user or saving images to disk. "
            "Many utility apps (e.g. flashlights, QR scanners, barcode readers) use the camera API "
            "strictly for optical scanning or controlling the physical LED without storing images."
        ),
        inherent_privacy_risk="High",
    ),

    # ---------------- MICROPHONE / AUDIO DOMAIN ----------------
    "RECORD_AUDIO": PermissionInfo(
        name="RECORD_AUDIO",
        domain=PrivacyDomain.MICROPHONE,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Microphone recording and audio capture",
        what_it_allows=(
            "Allows the application to capture raw audio streams from the device microphone at any time "
            "while running."
        ),
        what_it_does_not_prove=(
            "Does not prove the app is eavesdropping, storing ambient conversations, or uploading audio. "
            "Could be used strictly for on-device voice recognition, audio visualization, or decibel measurement."
        ),
        inherent_privacy_risk="High",
    ),

    # ---------------- CONTACTS & IDENTITY DOMAIN ----------------
    "READ_CONTACTS": PermissionInfo(
        name="READ_CONTACTS",
        domain=PrivacyDomain.CONTACTS,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Read address book and contacts",
        what_it_allows=(
            "Allows the application to read the entire user contact database stored on the device, "
            "including names, phone numbers, email addresses, and relationship notes."
        ),
        what_it_does_not_prove=(
            "Does not prove the contacts list is harvested or uploaded to cloud servers. "
            "Apps may read contacts to allow in-app invite sharing initiated by user choice."
        ),
        inherent_privacy_risk="High",
    ),
    "WRITE_CONTACTS": PermissionInfo(
        name="WRITE_CONTACTS",
        domain=PrivacyDomain.CONTACTS,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Modify or add contacts",
        what_it_allows="Allows the app to modify, add, or delete entries in the user address book.",
        what_it_does_not_prove="Does not prove unauthorized contact alteration or silent syncing.",
        inherent_privacy_risk="Medium",
    ),
    "GET_ACCOUNTS": PermissionInfo(
        name="GET_ACCOUNTS",
        domain=PrivacyDomain.CONTACTS,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Query list of registered accounts on device",
        what_it_allows=(
            "Allows access to the list of account authenticators (Google, WhatsApp, email) "
            "registered in the device Account Manager."
        ),
        what_it_does_not_prove="Does not prove that passwords or private emails are accessible.",
        inherent_privacy_risk="Medium",
    ),

    # ---------------- STORAGE & MEDIA DOMAIN ----------------
    "READ_MEDIA_IMAGES": PermissionInfo(
        name="READ_MEDIA_IMAGES",
        domain=PrivacyDomain.STORAGE_FILES,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Access user image gallery (Android 13+)",
        what_it_allows=(
            "Allows reading shared image files and photos across the device filesystem, "
            "including embedded EXIF metadata (camera model, GPS coordinates of photos)."
        ),
        what_it_does_not_prove=(
            "Does not prove photos are exfiltrated. Often requested to let users select a profile picture."
        ),
        inherent_privacy_risk="High",
    ),
    "READ_MEDIA_VIDEO": PermissionInfo(
        name="READ_MEDIA_VIDEO",
        domain=PrivacyDomain.STORAGE_FILES,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Access user video gallery (Android 13+)",
        what_it_allows="Allows reading video files on the device filesystem.",
        what_it_does_not_prove="Does not prove videos are transferred or indexed remotely.",
        inherent_privacy_risk="High",
    ),
    "READ_MEDIA_AUDIO": PermissionInfo(
        name="READ_MEDIA_AUDIO",
        domain=PrivacyDomain.STORAGE_FILES,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Access user music and audio files (Android 13+)",
        what_it_allows="Allows reading audio and music files stored on the device.",
        what_it_does_not_prove="Does not prove music libraries are catalogued or sold.",
        inherent_privacy_risk="Medium",
    ),
    "READ_EXTERNAL_STORAGE": PermissionInfo(
        name="READ_EXTERNAL_STORAGE",
        domain=PrivacyDomain.STORAGE_FILES,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Legacy broad external storage read",
        what_it_allows=(
            "Legacy permission (Android 12 and below): grants broad read access to all shared "
            "files on the SD card/external storage volume."
        ),
        what_it_does_not_prove="Does not prove the app scans documents or downloads files without user knowledge.",
        inherent_privacy_risk="High",
    ),
    "WRITE_EXTERNAL_STORAGE": PermissionInfo(
        name="WRITE_EXTERNAL_STORAGE",
        domain=PrivacyDomain.STORAGE_FILES,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Legacy broad external storage write",
        what_it_allows="Legacy permission: allows writing and deleting files in shared external storage.",
        what_it_does_not_prove="Does not prove unauthorized data overwriting.",
        inherent_privacy_risk="Medium",
    ),

    # ---------------- PHONE STATE & TELEPHONY DOMAIN ----------------
    "READ_PHONE_STATE": PermissionInfo(
        name="READ_PHONE_STATE",
        domain=PrivacyDomain.PHONE_TELEPHONY,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Device phone state and cellular network info",
        what_it_allows=(
            "Allows read-only access to phone state, including current cellular network status, "
            "ongoing call status, and on older Android versions, hardware IDs like IMEI and IMSI."
        ),
        what_it_does_not_prove=(
            "Does not prove call snooping or IMEI theft. Frequently used by media players and games "
            "to mute audio when an incoming phone call arrives."
        ),
        inherent_privacy_risk="High",
    ),
    "READ_CALL_LOG": PermissionInfo(
        name="READ_CALL_LOG",
        domain=PrivacyDomain.PHONE_TELEPHONY,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Read call history log",
        what_it_allows="Allows reading incoming, outgoing, and missed call history with timestamps.",
        what_it_does_not_prove="Does not prove call recording or remote logging.",
        inherent_privacy_risk="High",
    ),

    # ---------------- SENSORS & BIOMETRICS DOMAIN ----------------
    "BODY_SENSORS": PermissionInfo(
        name="BODY_SENSORS",
        domain=PrivacyDomain.BIOMETRICS_SENSORS,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Access heart rate and biometric sensors",
        what_it_allows="Allows the app to read data from sensors measuring heart rate, body temperature, etc.",
        what_it_does_not_prove="Does not prove health telemetry is transmitted without user awareness.",
        inherent_privacy_risk="High",
    ),
    "ACTIVITY_RECOGNITION": PermissionInfo(
        name="ACTIVITY_RECOGNITION",
        domain=PrivacyDomain.BIOMETRICS_SENSORS,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Recognize physical movement (walking, running, driving)",
        what_it_allows="Allows detecting physical activities like step counting and transport modes.",
        what_it_does_not_prove="Does not prove real-time tracking.",
        inherent_privacy_risk="Medium",
    ),

    # ---------------- CONNECTIVITY & NETWORK DOMAIN ----------------
    "BLUETOOTH_CONNECT": PermissionInfo(
        name="BLUETOOTH_CONNECT",
        domain=PrivacyDomain.CONNECTIVITY_NETWORK,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Communicate with paired Bluetooth accessories (Android 12+)",
        what_it_allows="Allows communicating with paired Bluetooth devices (smartwatches, headphones).",
        what_it_does_not_prove="Does not prove device scanning or location derivation.",
        inherent_privacy_risk="Medium",
    ),
    "BLUETOOTH_SCAN": PermissionInfo(
        name="BLUETOOTH_SCAN",
        domain=PrivacyDomain.CONNECTIVITY_NETWORK,
        protection_level=ProtectionLevel.DANGEROUS,
        short_description="Discover nearby Bluetooth devices and beacons",
        what_it_allows="Allows scanning for nearby Bluetooth beacons, which can be used to infer physical location.",
        what_it_does_not_prove="Does not prove beacon fingerprinting or commercial tracking.",
        inherent_privacy_risk="High",
    ),
    "ACCESS_NETWORK_STATE": PermissionInfo(
        name="ACCESS_NETWORK_STATE",
        domain=PrivacyDomain.CONNECTIVITY_NETWORK,
        protection_level=ProtectionLevel.NORMAL,
        short_description="View Wi-Fi/cellular connection status",
        what_it_allows="Allows checking whether an active Wi-Fi or mobile data connection is available.",
        what_it_does_not_prove="Does not allow inspecting network packet data or web traffic.",
        inherent_privacy_risk="Low",
    ),
}


def normalize_permission_name(perm_name: str) -> str:
    """Normalize permission string by stripping package prefixes, whitespace, and formatting as uppercase.

    Examples:
        'android.permission.CAMERA' -> 'CAMERA'
        '  access_fine_location  ' -> 'ACCESS_FINE_LOCATION'
        'com.example.CUSTOM_PERM' -> 'CUSTOM_PERM'
    """
    if not perm_name or not isinstance(perm_name, str):
        return ""

    cleaned = perm_name.strip()
    if cleaned.startswith("android.permission."):
        cleaned = cleaned.replace("android.permission.", "")
    elif "." in cleaned:
        # Take the suffix after the last dot if proprietary package
        cleaned = cleaned.split(".")[-1]

    return cleaned.upper()


def get_permission_info(perm_name: str) -> PermissionInfo:
    """Retrieve PermissionInfo from knowledge base, or synthesize a structured entry for custom permissions.

    Args:
        perm_name: Name of the permission (normalized or raw).

    Returns:
        A complete PermissionInfo instance.
    """
    normalized = normalize_permission_name(perm_name)
    if normalized in PERMISSION_KNOWLEDGE_BASE:
        return PERMISSION_KNOWLEDGE_BASE[normalized]

    # Synthesize entry for unrecognized / third-party / custom permissions
    return PermissionInfo(
        name=normalized or "UNKNOWN_PERMISSION",
        domain=PrivacyDomain.SYSTEM_OTHER,
        protection_level=ProtectionLevel.NORMAL,
        short_description="Custom or platform-specific permission",
        what_it_allows="Platform or vendor-specific capability not in standard Android dangerous permissions.",
        what_it_does_not_prove="Does not establish privacy invasion or data transmission.",
        inherent_privacy_risk="Low",
    )


def explain_evidence_source(evidence_source: str) -> dict[str, str]:
    """Provide scientific evidentiary context and limitations based on the origin of permission evidence.

    Args:
        evidence_source: The selected source label.

    Returns:
        Dictionary with description, evidentiary weight, and audit considerations.
    """
    source_lower = evidence_source.lower()

    if "manifest" in source_lower:
        return {
            "source_type": "Static AndroidManifest.xml Analysis",
            "evidentiary_weight": "High (Declared Technical Capability)",
            "meaning": "The application binary explicitly requested these permissions from the operating system.",
            "caveat": (
                "Declared permissions in a manifest establish what the app can ask for. "
                "It does not prove the permission is ever invoked at runtime or that the user granted it."
            ),
        }
    elif "play store" in source_lower or "listing" in source_lower:
        return {
            "source_type": "Google Play Store Data Safety Declaration",
            "evidentiary_weight": "Medium (Developer Self-Reported)",
            "meaning": "Permissions and data collection claims reported by the developer to Google Play.",
            "caveat": (
                "Self-reported Play Store declarations may occasionally lag behind actual binary updates "
                "or summarize permissions at a high level."
            ),
        }
    elif "runtime" in source_lower or "dynamic" in source_lower:
        return {
            "source_type": "Dynamic Runtime Request Observation",
            "evidentiary_weight": "Very High (Demonstrated Execution)",
            "meaning": "The app was observed prompting the user or invoking the privileged API at runtime.",
            "caveat": (
                "Proves the code path was reached, but still does not confirm data was transmitted off-device "
                "unless network traffic inspection (PCAP) is also performed."
            ),
        }
    else:
        return {
            "source_type": "User Manual Input",
            "evidentiary_weight": "Unverified (Subject to Entry Error)",
            "meaning": "Permission list supplied manually for evaluation.",
            "caveat": (
                "Manual entries must be confirmed against an authentic APK manifest or Play Store listing "
                "before forming final audit conclusions."
            ),
        }
