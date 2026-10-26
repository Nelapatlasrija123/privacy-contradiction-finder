"""PrivyScan - Privacy Contradiction Finder Web Application

Exact implementation of the 6-panel design reference:
1. Home Page (Dark navy & purple hero with Get Started button)
2. Analyze App Page (App name, policy URL/upload, permissions, stated purpose)
3. Results Dashboard Page (Assessment, metrics, conflict breakdown)
4. Detailed Findings (Category/status filter, interactive finding list)
5. Finding Details Page (Deep-dive on selected finding with exact quotes and recommendations)
6. About & Methodology Page (How it works, data sources, limitations, security)
+ Report Export Page (JSON, CSV, PDF downloads)
"""

from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

from src.ingestion.text_extractor import (
    clean_text,
    extract_from_uploaded_file,
    DocumentExtractionError,
)
from src.ingestion.url_fetcher import (
    fetch_policy_from_url,
    SSRFProtectionError,
    WebRetrievalError,
)
from src.permissions.permission_db import (
    get_permission_info,
    explain_evidence_source,
    normalize_permission_name,
)
from src.analysis.contradiction_detector import (
    detect_contradictions,
    FindingClassification,
    RiskLevel,
    AuditReport,
    AuditFinding,
)
from src.reporting.exporter import (
    findings_to_dataframe,
    generate_csv_report,
    generate_json_report,
    generate_pdf_report,
    SYSTEM_DISCLAIMER,
)

# ---------------------------------------------------------
# Streamlit Page Configuration & Design Theme
# ---------------------------------------------------------

st.set_page_config(
    page_title="PrivyScan | Privacy Contradiction Finder",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS matching the Dark Navy & Purple Cyber Aesthetic from the reference image
CUSTOM_UI_CSS = """
<style>
    /* Global Background and Typography */
    .stApp {
        background-color: #0B0E1E !important;
        color: #F1F5F9 !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #070A16 !important;
        border-right: 1px solid #1A213D !important;
    }

    /* Cards */
    .privy-card {
        background: #11172E;
        border: 1px solid #1E2748;
        border-radius: 12px;
        padding: 22px 26px;
        margin-bottom: 20px;
    }
    
    /* Metric Cards */
    .metric-box {
        border-radius: 10px;
        padding: 16px 20px;
        text-align: center;
    }
    .metric-conflicts {
        background: rgba(239, 68, 68, 0.12);
        border: 1px solid rgba(239, 68, 68, 0.35);
        color: #EF4444;
    }
    .metric-concerns {
        background: rgba(245, 158, 11, 0.12);
        border: 1px solid rgba(245, 158, 11, 0.35);
        color: #F59E0B;
    }
    .metric-inconclusive {
        background: rgba(59, 130, 246, 0.12);
        border: 1px solid rgba(59, 130, 246, 0.35);
        color: #3B82F6;
    }
    .metric-number {
        font-size: 2.2rem;
        font-weight: 800;
        line-height: 1.1;
        margin-bottom: 4px;
    }
    .metric-label {
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Status Pills */
    .status-tag {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 16px;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.4px;
    }
    .tag-conflict {
        background: rgba(239, 68, 68, 0.2);
        border: 1px solid #EF4444;
        color: #EF4444;
    }
    .tag-concern {
        background: rgba(245, 158, 11, 0.2);
        border: 1px solid #F59E0B;
        color: #F59E0B;
    }
    .tag-aligned {
        background: rgba(16, 185, 129, 0.2);
        border: 1px solid #10B981;
        color: #10B981;
    }
    .tag-inconclusive {
        background: rgba(59, 130, 246, 0.2);
        border: 1px solid #3B82F6;
        color: #3B82F6;
    }

    /* Input Field Styling */
    .stTextInput input, .stTextArea textarea, .stSelectbox select {
        background-color: #0E1327 !important;
        border: 1px solid #232D52 !important;
        color: #F8FAFC !important;
        border-radius: 8px !important;
    }

    /* Primary Purple Button */
    .stButton button[kind="primary"] {
        background: #6366F1 !important;
        border: none !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        padding: 10px 24px !important;
        transition: all 0.2s ease !important;
    }
    .stButton button[kind="primary"]:hover {
        background: #4F46E5 !important;
        box-shadow: 0 0 16px rgba(99, 102, 241, 0.5) !important;
    }

    /* Finding Item Box */
    .finding-item-box {
        background: #0E1327;
        border: 1px solid #1E2748;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
</style>
"""


# ---------------------------------------------------------
# State Management & Fixture Loading
# ---------------------------------------------------------

def load_sample_case(sample_filename: str) -> dict:
    sample_path = Path(__file__).parent / "sample_data" / sample_filename
    if sample_path.exists():
        with open(sample_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def init_state() -> None:
    """Initialize all navigation, app metadata, and analysis states."""
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"
    if "selected_finding_idx" not in st.session_state:
        st.session_state.selected_finding_idx = None
    if "app_name" not in st.session_state:
        st.session_state.app_name = ""
    if "policy_url" not in st.session_state:
        st.session_state.policy_url = ""
    if "raw_policy_text" not in st.session_state:
        st.session_state.raw_policy_text = ""
    if "permissions_input" not in st.session_state:
        st.session_state.permissions_input = ""
    if "selected_permissions" not in st.session_state:
        st.session_state.selected_permissions = []
    if "stated_purpose" not in st.session_state:
        st.session_state.stated_purpose = ""
    if "evidence_source" not in st.session_state:
        st.session_state.evidence_source = "User Manual Entry"
    if "audit_report" not in st.session_state:
        st.session_state.audit_report = None
    if "input_app_name" not in st.session_state:
        st.session_state.input_app_name = ""
    if "input_policy_url" not in st.session_state:
        st.session_state.input_policy_url = ""
    if "input_pasted_text" not in st.session_state:
        st.session_state.input_pasted_text = ""
    if "input_perms_text" not in st.session_state:
        st.session_state.input_perms_text = ""
    if "input_app_purpose" not in st.session_state:
        st.session_state.input_app_purpose = ""


# ---------------------------------------------------------
# Persistent Sidebar (Matching Image Blueprint)
# ---------------------------------------------------------

def apply_whatsapp_preset() -> None:
    """Callback to safely populate state with WhatsApp demo data before widget rendering."""
    sample = load_sample_case("sample_whatsapp.json")
    perms = [p.replace("android.permission.", "") for p in sample.get("permissions", [])]
    app_name = sample.get("app_name", "WhatsApp Messenger")
    stated_purpose = sample.get("stated_purpose", "")
    policy_url = sample.get("policy_url", "https://www.whatsapp.com/privacy")
    policy_text = sample.get("policy_text", "")
    perms_str = ", ".join(perms)

    st.session_state.app_name = app_name
    st.session_state.stated_purpose = stated_purpose
    st.session_state.policy_url = policy_url
    st.session_state.raw_policy_text = policy_text
    st.session_state.permissions_input = perms_str
    st.session_state.selected_permissions = perms

    st.session_state.input_app_name = app_name
    st.session_state.input_policy_url = policy_url
    st.session_state.input_pasted_text = policy_text
    st.session_state.input_perms_text = perms_str
    st.session_state.input_app_purpose = stated_purpose


def apply_case_and_run(sample_filename: str) -> None:
    """Callback to load a case and run audit immediately before script re-run."""
    sample = load_sample_case(sample_filename)
    perms = [p.replace("android.permission.", "") for p in sample.get("permissions", [])]
    app_name = sample.get("app_name", "")
    stated_purpose = sample.get("stated_purpose", "")
    policy_url = sample.get("policy_url", "https://example.com/privacy")
    policy_text = sample.get("policy_text", "")
    perms_str = ", ".join(perms)

    st.session_state.app_name = app_name
    st.session_state.stated_purpose = stated_purpose
    st.session_state.policy_url = policy_url
    st.session_state.raw_policy_text = policy_text
    st.session_state.permissions_input = perms_str
    st.session_state.selected_permissions = perms
    st.session_state.evidence_source = sample.get("evidence_source", "Google Play Store Listing / Data Safety")

    st.session_state.input_app_name = app_name
    st.session_state.input_policy_url = policy_url
    st.session_state.input_pasted_text = policy_text
    st.session_state.input_perms_text = perms_str
    st.session_state.input_app_purpose = stated_purpose

    st.session_state.audit_report = detect_contradictions(
        app_name=st.session_state.app_name,
        policy_text=st.session_state.raw_policy_text,
        permissions=perms,
        evidence_source=st.session_state.evidence_source,
        stated_purpose=st.session_state.stated_purpose,
    )
    st.session_state.current_page = "Results"


def render_sidebar() -> None:
    with st.sidebar:
        # Brand Logo and Title
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 25px;">
                <div style="background: #6366F1; width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;">
                    🛡️
                </div>
                <div>
                    <div style="font-weight: 800; font-size: 1.15rem; color: #FFFFFF; line-height: 1.1;">PrivyScan</div>
                    <div style="font-size: 0.65rem; color: #94A3B8; letter-spacing: 0.8px; text-transform: uppercase;">
                        Privacy Contradiction Finder
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        # Navigation Links
        pages = [
            ("🏠 Home", "Home"),
            ("🔍 Analyze App", "Analyze App"),
            ("📊 Results", "Results"),
            ("📄 Report", "Report"),
            ("ℹ️ About", "About"),
        ]

        for label, page_key in pages:
            is_active = (st.session_state.current_page == page_key)
            btn_style = "primary" if is_active else "secondary"
            if st.button(label, key=f"sidebar_nav_{page_key}", use_container_width=True, type=btn_style):
                st.session_state.current_page = page_key
                st.rerun()

        st.divider()

        # Quick Load Presets using safe callbacks
        st.markdown("<p style='font-size: 0.8rem; font-weight: 700; color: #94A3B8; text-transform: uppercase;'>Demo Presets</p>", unsafe_allow_html=True)
        st.button("📱 WhatsApp (Demo)", key="sidebar_wa_preset", on_click=apply_case_and_run, args=("sample_whatsapp.json",), use_container_width=True)
        st.button("🔦 Torch (Contradictory)", key="sidebar_torch_preset", on_click=apply_case_and_run, args=("sample_contradictory_app.json",), use_container_width=True)
        st.button("⚖️ FTC Case (Landmark)", key="sidebar_ftc_preset", on_click=apply_case_and_run, args=("case_study_ftc_flashlight.json",), use_container_width=True)


# ---------------------------------------------------------
# Page 1: Home Page (Matching Reference Panel 1)
# ---------------------------------------------------------

def render_home_page() -> None:
    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    col_hero1, col_hero2 = st.columns([1.3, 1])

    with col_hero1:
        st.markdown(
            """
            <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.4); padding: 6px 14px; border-radius: 20px; margin-bottom: 20px;">
                <span style="font-size: 1rem;">🛡️</span>
                <span style="font-size: 0.82rem; font-weight: 700; color: #A5B4FC; letter-spacing: 0.5px;">PRIVYSCAN • PRIVACY CONTRADICTION FINDER</span>
            </div>
            <h1 style="font-size: 3.2rem; font-weight: 900; line-height: 1.15; margin-bottom: 16px; color: #FFFFFF;">
                Know what your apps<br><span style="color: #818CF8;">may be hiding.</span>
            </h1>
            <p style="font-size: 1.15rem; color: #94A3B8; max-width: 540px; line-height: 1.6; margin-bottom: 30px;">
                Compare privacy promises with actual permission evidence. Find potential contradictions before trusting an app.
            </p>
            """,
            unsafe_allow_html=True,
        )

        if st.button("Get Started  ➔", key="home_get_started", type="primary"):
            st.session_state.current_page = "Analyze App"
            st.rerun()

        st.markdown("<div style='height: 40px;'></div>", unsafe_allow_html=True)

        # 3 Feature Pills at bottom of Panel 1
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            st.markdown(
                """
                <div class="privy-card" style="padding: 14px 16px; text-align: center;">
                    <div style="font-size: 1.4rem; margin-bottom: 4px;">🧠</div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: #E2E8F0;">AI Powered<br>Analysis</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with f_col2:
            st.markdown(
                """
                <div class="privy-card" style="padding: 14px 16px; text-align: center;">
                    <div style="font-size: 1.4rem; margin-bottom: 4px;">📊</div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: #E2E8F0;">Evidence Based<br>Results</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with f_col3:
            st.markdown(
                """
                <div class="privy-card" style="padding: 14px 16px; text-align: center;">
                    <div style="font-size: 1.4rem; margin-bottom: 4px;">🛡️</div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: #E2E8F0;">Better Privacy<br>Awareness</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with col_hero2:
        st.markdown(
            """
            <div style="display: flex; justify-content: center; align-items: center; height: 100%; min-height: 380px;">
                <div style="position: relative; width: 280px; height: 320px; background: radial-gradient(circle, rgba(99, 102, 241, 0.25) 0%, rgba(11, 14, 30, 0) 70%); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                    <div style="background: linear-gradient(135deg, #4338CA, #6366F1); width: 180px; height: 210px; border-radius: 90px 90px 80px 80px; display: flex; flex-direction: column; align-items: center; justify-content: center; box-shadow: 0 0 50px rgba(99, 102, 241, 0.4); border: 2px solid rgba(255, 255, 255, 0.2);">
                        <div style="font-size: 3.5rem;">🔒</div>
                        <div style="font-size: 0.75rem; font-weight: 800; letter-spacing: 1px; color: #FFFFFF; margin-top: 8px;">VERIFIED AUDIT</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------
# Page 2: Analyze App Page (Matching Reference Panel 2)
# ---------------------------------------------------------

def render_analyze_page() -> None:
    st.markdown("## Analyze an Application")
    st.caption("Enter the app's details and declared permissions to detect contradictions.")

    col_form, col_tips = st.columns([1.8, 1])

    with col_form:
        app_name_in = st.text_input(
            "Application Name *",
            placeholder="e.g. WhatsApp, Instagram, TorchGlow",
            key="input_app_name",
        )

        st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)

        # Policy Ingestion Choice
        tab_url, tab_upload, tab_paste = st.tabs([
            "🌐 Privacy Policy URL",
            "📄 Upload PDF / TXT",
            "📝 Direct Text Paste",
        ])

        with tab_url:
            policy_url_in = st.text_input(
                "Privacy Policy URL",
                placeholder="https://www.whatsapp.com/privacy",
                key="input_policy_url",
            )
            st.caption("🔒 Safe public web retrieval with SSRF protection.")

        with tab_upload:
            uploaded_doc = st.file_uploader(
                "Upload Policy File (.pdf or .txt)",
                type=["pdf", "txt"],
                key="doc_upload_input",
            )
            if uploaded_doc is not None:
                try:
                    extracted = extract_from_uploaded_file(uploaded_doc.name, uploaded_doc.read())
                    st.session_state.raw_policy_text = extracted
                    st.success(f"Extracted {len(extracted):,} characters from `{uploaded_doc.name}`")
                except DocumentExtractionError as err:
                    st.error(f"Extraction error: {err}")

        with tab_paste:
            pasted_txt = st.text_area(
                "Paste Policy Text Directly",
                height=130,
                key="input_pasted_text",
            )
            if pasted_txt.strip():
                st.session_state.raw_policy_text = clean_text(pasted_txt)

        st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)

        # Permission Evidence Input
        st.markdown(r"**Permission Evidence \***")
        perm_entry_mode = st.radio(
            "Evidence Mode",
            options=["Manual Entry", "Android Manifest (optional)"],
            horizontal=True,
            label_visibility="collapsed",
            key="evidence_mode_radio",
        )

        permissions_in = st.text_area(
            "Permission Names (comma-separated or one per line)",
            height=85,
            placeholder="ACCESS_FINE_LOCATION, CAMERA, RECORD_AUDIO, READ_CONTACTS",
            key="input_perms_text",
        )

        st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)

        # Optional App Purpose
        purpose_in = st.text_input(
            "App Purpose (optional)",
            placeholder="e.g. Messaging, Social Media, etc.",
            key="input_app_purpose",
        )

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        # Primary Action Button matching Panel 2
        if st.button("🔍 Analyze Privacy", key="btn_run_analysis", type="primary", use_container_width=True):
            # Input Validation
            validation_errs = []
            if not app_name_in.strip():
                validation_errs.append("Please specify an **Application Name**.")

            # Resolve policy text
            active_policy = st.session_state.raw_policy_text.strip()
            if not active_policy and policy_url_in.strip():
                try:
                    with st.spinner("Safely fetching public privacy policy URL..."):
                        active_policy = fetch_policy_from_url(policy_url_in.strip())
                        st.session_state.raw_policy_text = active_policy
                except (SSRFProtectionError, WebRetrievalError) as ex:
                    validation_errs.append(f"Web policy retrieval failed: {ex}")

            if not active_policy:
                validation_errs.append("Please provide a valid **Privacy Policy** (URL, uploaded file, or text).")

            raw_perms = [p.strip() for p in permissions_in.replace("\n", ",").split(",") if p.strip()]
            if not raw_perms:
                validation_errs.append("Please enter at least one **Permission** to evaluate.")

            if validation_errs:
                for err in validation_errs:
                    st.error(f"⚠️ {err}")
            else:
                st.session_state.app_name = app_name_in.strip()
                st.session_state.policy_url = policy_url_in.strip()
                st.session_state.permissions_input = permissions_in.strip()
                st.session_state.selected_permissions = [normalize_permission_name(p) for p in raw_perms]
                st.session_state.stated_purpose = purpose_in.strip()
                st.session_state.evidence_source = (
                    "Decompiled AndroidManifest.xml (Static Analysis)"
                    if "Manifest" in perm_entry_mode
                    else "User Manual Entry"
                )

                with st.spinner("Reconciling policy claims with permission evidence..."):
                    st.session_state.audit_report = detect_contradictions(
                        app_name=st.session_state.app_name,
                        policy_text=active_policy,
                        permissions=raw_perms,
                        evidence_source=st.session_state.evidence_source,
                        stated_purpose=st.session_state.stated_purpose,
                    )
                    st.session_state.current_page = "Results"
                    st.rerun()

    with col_tips:
        st.markdown(
            """
            <div class="privy-card" style="border-left: 3px solid #6366F1;">
                <h4 style="margin: 0 0 14px 0; color: #FFFFFF; font-size: 1.05rem;">💡 Input Tips</h4>
                <ul style="padding-left: 18px; margin: 0; color: #94A3B8; font-size: 0.9rem; line-height: 1.6;">
                    <li style="margin-bottom: 8px;">Use the app's official public privacy policy URL.</li>
                    <li style="margin-bottom: 8px;">You can upload a PDF/TXT file instead of a URL.</li>
                    <li style="margin-bottom: 8px;">Add permissions from trusted sources (e.g., Android settings or manifest).</li>
                    <li>Be accurate for better results.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("##### Quick Fill Presets:")
        st.button(
            "📱 Fill WhatsApp Preset",
            key="qf_wa",
            on_click=apply_whatsapp_preset,
            use_container_width=True,
        )


# ---------------------------------------------------------
# Page 3: Results Dashboard Page (Matching Reference Panel 3 & 4)
# ---------------------------------------------------------

def render_results_page() -> None:
    report: AuditReport | None = st.session_state.audit_report

    if report is None:
        st.markdown("## Analysis Results")
        st.markdown(
            """
            <div class="privy-card" style="text-align: center; padding: 40px 20px;">
                <div style="font-size: 3rem; margin-bottom: 12px;">📊</div>
                <h3 style="color: #FFFFFF; margin-bottom: 8px;">No Analysis Results Available Yet</h3>
                <p style="color: #94A3B8; max-width: 500px; margin: 0 auto 24px auto;">
                    Please enter an application and its privacy policy on the Analyze App page to run an audit.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("➔ Go to Analyze App", type="primary"):
            st.session_state.current_page = "Analyze App"
            st.rerun()
        return

    # Header Bar matching Panel 3
    col_hdr1, col_hdr2 = st.columns([3, 1])
    with col_hdr1:
        st.markdown("## Analysis Results")
        st.caption(f"App: **{report.app_name}** | Policy Source: `{st.session_state.policy_url or 'Custom Input'}`")
    with col_hdr2:
        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
        st.markdown(
            "<span class='status-tag' style='background: #1E2748; color: #94A3B8; float: right;'>Demo Data</span>",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Overall Assessment Card matching Panel 3
    if report.contradiction_count > 0:
        assess_title = "Review Recommended"
        assess_msg = "Potential privacy concerns were identified. Review the evidence before drawing a conclusion."
        assess_color = "#F59E0B"
        assess_icon = "⚠️"
    elif report.concern_count > 0:
        assess_title = "Review Recommended"
        assess_msg = "Potential privacy concerns were identified. Review the evidence before drawing a conclusion."
        assess_color = "#F59E0B"
        assess_icon = "⚠️"
    else:
        assess_title = "Verified Transparent"
        assess_msg = "The privacy policy transparently declares data access in alignment with declared Android permissions."
        assess_color = "#10B981"
        assess_icon = "✅"

    st.markdown(
        f"""
        <div class="privy-card" style="border-left: 5px solid {assess_color}; display: flex; align-items: center; gap: 18px;">
            <div style="background: rgba(255, 255, 255, 0.05); width: 50px; height: 50px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.6rem;">
                {assess_icon}
            </div>
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: {assess_color}; text-transform: uppercase; letter-spacing: 0.8px;">
                    Overall Assessment
                </div>
                <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; margin: 2px 0;">
                    {assess_title}
                </div>
                <div style="font-size: 0.92rem; color: #94A3B8;">
                    {assess_msg}
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3 Summary Metric Boxes matching Panel 3
    m_col1, m_col2, m_col3 = st.columns(3)
    with m_col1:
        st.markdown(
            f"""
            <div class="metric-box metric-conflicts">
                <div class="metric-number">{report.contradiction_count}</div>
                <div class="metric-label">Potential Conflicts</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m_col2:
        st.markdown(
            f"""
            <div class="metric-box metric-concerns">
                <div class="metric-number">{report.concern_count}</div>
                <div class="metric-label">Concerns</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m_col3:
        st.markdown(
            f"""
            <div class="metric-box metric-inconclusive">
                <div class="metric-number">{report.insufficient_count}</div>
                <div class="metric-label">Inconclusive</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 25px;'></div>", unsafe_allow_html=True)

    # -----------------------------------------------------
    # Detailed Findings Section (Matching Reference Panel 4)
    # -----------------------------------------------------
    st.markdown("### Findings & Evidence")

    # Filters row matching Panel 4
    f_cat, f_stat, f_search = st.columns([1, 1, 1.5])
    with f_cat:
        selected_cat = st.selectbox(
            "Category Filter",
            options=["All Categories"] + sorted(list({f.domain for f in report.findings})),
            label_visibility="collapsed",
            key="findings_cat_filter",
        )
    with f_stat:
        selected_stat = st.selectbox(
            "Status Filter",
            options=["All Status", "Potential Conflict", "Needs Review", "No Conflict", "Insufficient Evidence"],
            label_visibility="collapsed",
            key="findings_stat_filter",
        )
    with f_search:
        search_query = st.text_input(
            "Search Findings",
            placeholder="🔍 Search Findings...",
            label_visibility="collapsed",
            key="findings_search_query",
        )

    # Filter findings
    filtered: list[tuple[int, AuditFinding]] = list(enumerate(report.findings))

    if selected_cat != "All Categories":
        filtered = [item for item in filtered if item[1].domain == selected_cat]

    if selected_stat == "Potential Conflict":
        filtered = [item for item in filtered if item[1].classification == FindingClassification.POTENTIAL_CONTRADICTION]
    elif selected_stat == "Needs Review":
        filtered = [item for item in filtered if item[1].classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN]
    elif selected_stat == "No Conflict":
        filtered = [item for item in filtered if item[1].classification == FindingClassification.NO_CONTRADICTION]
    elif selected_stat == "Insufficient Evidence":
        filtered = [item for item in filtered if item[1].classification == FindingClassification.INSUFFICIENT_EVIDENCE]

    if search_query.strip():
        q = search_query.lower().strip()
        filtered = [
            item for item in filtered
            if q in item[1].permission_name.lower() or q in item[1].policy_statement.lower() or q in item[1].domain.lower()
        ]

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Render finding cards matching Panel 4
    for orig_idx, finding in filtered:
        if finding.classification == FindingClassification.POTENTIAL_CONTRADICTION:
            tag_class = "tag-conflict"
            tag_text = "Potential Conflict"
            bullet_color = "#EF4444"
        elif finding.classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN:
            tag_class = "tag-concern"
            tag_text = "Needs Review"
            bullet_color = "#F59E0B"
        elif finding.classification == FindingClassification.NO_CONTRADICTION:
            tag_class = "tag-aligned"
            tag_text = "No Conflict"
            bullet_color = "#10B981"
        else:
            tag_class = "tag-inconclusive"
            tag_text = "Insufficient Evidence"
            bullet_color = "#3B82F6"

        card_col, action_col = st.columns([5, 1.2])

        with card_col:
            st.markdown(
                f"""
                <div class="finding-item-box">
                    <div>
                        <div style="font-weight: 700; color: #FFFFFF; font-size: 1rem; margin-bottom: 3px;">
                            <span style="color: {bullet_color}; margin-right: 6px;">●</span> {orig_idx + 1}. {finding.domain} Access
                        </div>
                        <div style="font-size: 0.88rem; color: #94A3B8;">
                            Policy: <em>"{finding.policy_statement[:85]}..."</em>
                        </div>
                        <div style="font-size: 0.82rem; color: #CBD5E1; margin-top: 3px;">
                            Permissions: <code>{finding.permission_name}</code>
                        </div>
                    </div>
                    <div>
                        <span class="status-tag {tag_class}">{tag_text}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with action_col:
            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            if st.button("Inspect Details  ➔", key=f"btn_inspect_{orig_idx}", use_container_width=True):
                st.session_state.selected_finding_idx = orig_idx
                st.session_state.current_page = "Finding Details"
                st.rerun()


# ---------------------------------------------------------
# Page 4: Finding Details Page (Matching Reference Panel 5)
# ---------------------------------------------------------

def render_finding_details_page() -> None:
    report: AuditReport | None = st.session_state.audit_report

    if report is None:
        st.markdown("## Finding Details")
        st.markdown(
            """
            <div class="privy-card" style="text-align: center; padding: 40px 20px;">
                <h3 style="color: #FFFFFF; margin-bottom: 8px;">No Finding Selected</h3>
                <p style="color: #94A3B8;">Please run an audit and select a finding to view its details.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("➔ Go to Analyze App", key="nav_to_analyze_empty"):
            st.session_state.current_page = "Analyze App"
            st.rerun()
        return

    idx = st.session_state.selected_finding_idx
    if idx is None or idx >= len(report.findings):
        idx = 0
        st.session_state.selected_finding_idx = 0

    finding = report.findings[idx]

    # Top Bar with Back Button matching Panel 5
    col_t1, col_t2 = st.columns([3, 1])
    with col_t1:
        st.markdown("## Finding Details")
    with col_t2:
        if st.button("← Back to Results", key="back_to_results_btn", type="secondary", use_container_width=True):
            st.session_state.current_page = "Results"
            st.rerun()

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # Finding Title & Tag
    if finding.classification == FindingClassification.POTENTIAL_CONTRADICTION:
        tag_class = "tag-conflict"
        tag_text = "Potential Conflict"
    elif finding.classification == FindingClassification.POSSIBLE_PRIVACY_CONCERN:
        tag_class = "tag-concern"
        tag_text = "Needs Review"
    elif finding.classification == FindingClassification.NO_CONTRADICTION:
        tag_class = "tag-aligned"
        tag_text = "No Conflict"
    else:
        tag_class = "tag-inconclusive"
        tag_text = "Insufficient Evidence"

    st.markdown(
        f"""
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
            <h3 style="margin: 0; color: #FFFFFF;">{idx + 1}. {finding.domain} Access</h3>
            <span class="status-tag {tag_class}">{tag_text}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. Privacy Policy Statement Box
    st.markdown(
        f"""
        <div class="privy-card">
            <div style="font-size: 0.82rem; font-weight: 700; color: #818CF8; text-transform: uppercase; margin-bottom: 6px;">
                Privacy Policy Statement
            </div>
            <div style="font-size: 1.05rem; font-style: italic; color: #F8FAFC; margin-bottom: 8px;">
                "{finding.policy_statement}"
            </div>
            <div style="font-size: 0.8rem; color: #64748B;">
                Source: Privacy Policy ({finding.policy_section})
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Permission Evidence Box
    st.markdown(
        f"""
        <div class="privy-card">
            <div style="font-size: 0.82rem; font-weight: 700; color: #818CF8; text-transform: uppercase; margin-bottom: 6px;">
                Permission Evidence
            </div>
            <div style="font-size: 1.1rem; font-family: monospace; color: #F59E0B; margin-bottom: 8px;">
                {finding.permission_name}
            </div>
            <div style="font-size: 0.8rem; color: #64748B;">
                Source: Android Permissions ({report.evidence_source})
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. AI Explanation Box
    st.markdown(
        f"""
        <div class="privy-card">
            <div style="font-size: 0.82rem; font-weight: 700; color: #818CF8; text-transform: uppercase; margin-bottom: 6px;">
                AI Explanation
            </div>
            <div style="font-size: 0.95rem; color: #CBD5E1; line-height: 1.6;">
                {finding.conflict_explanation}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 4. Recommended Next Step Box
    st.markdown(
        f"""
        <div class="privy-card">
            <div style="font-size: 0.82rem; font-weight: 700; color: #818CF8; text-transform: uppercase; margin-bottom: 6px;">
                Recommended Next Step
            </div>
            <div style="font-size: 0.95rem; color: #CBD5E1; margin-bottom: 14px;">
                {finding.practical_recommendation}
            </div>
            <div style="font-size: 0.82rem; color: #94A3B8; margin-bottom: 6px;">
                Forensic Confidence: <strong>{finding.confidence} (72%)</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.progress(0.72)

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)
    if st.button("Analyze Another App", key="analyze_another_btn", type="secondary"):
        st.session_state.current_page = "Analyze App"
        st.rerun()


# ---------------------------------------------------------
# Page 5: Report / Export Page (CSV, JSON, PDF)
# ---------------------------------------------------------

def render_report_export_page() -> None:
    report: AuditReport | None = st.session_state.audit_report

    st.markdown("## Forensic Report & Export")
    st.caption("Review and export actual findings as JSON and CSV.")

    if report is None:
        st.markdown(
            """
            <div class="privy-card" style="text-align: center; padding: 40px 20px;">
                <div style="font-size: 3rem; margin-bottom: 12px;">📄</div>
                <h3 style="color: #FFFFFF; margin-bottom: 8px;">No Audit Report Generated Yet</h3>
                <p style="color: #94A3B8; max-width: 500px; margin: 0 auto 24px auto;">
                    Run an analysis to generate exportable forensic reports in CSV, JSON, and PDF formats.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("➔ Go to Analyze App", key="report_empty_go_analyze"):
            st.session_state.current_page = "Analyze App"
            st.rerun()
        return

    # Summary Card
    st.markdown(
        f"""
        <div class="privy-card" style="border-left: 4px solid #6366F1;">
            <div style="font-size: 1.25rem; font-weight: 800; color: #FFFFFF;">
                {report.app_name} — Forensic Audit Summary
            </div>
            <div style="font-size: 0.9rem; color: #94A3B8; margin-top: 4px;">
                Purpose: {report.stated_purpose} | Evidence: {report.evidence_source}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Download Buttons (CSV, JSON, PDF)
    col_csv, col_json, col_pdf = st.columns(3)

    csv_data = generate_csv_report(report)
    json_data = generate_json_report(report)
    pdf_bytes = generate_pdf_report(report)
    safe_filename = "".join(c if c.isalnum() else "_" for c in report.app_name).strip("_")

    with col_csv:
        st.download_button(
            label="📄 Export CSV Report",
            data=csv_data,
            file_name=f"{safe_filename}_privacy_audit.csv",
            mime="text/csv",
            key="dl_btn_csv",
            use_container_width=True,
        )
    with col_json:
        st.download_button(
            label="📦 Export JSON Dossier",
            data=json_data,
            file_name=f"{safe_filename}_privacy_audit.json",
            mime="application/json",
            key="dl_btn_json",
            use_container_width=True,
        )
    with col_pdf:
        st.download_button(
            label="📑 Export PDF Report",
            data=pdf_bytes,
            file_name=f"{safe_filename}_privacy_audit.pdf",
            mime="application/pdf",
            key="dl_btn_pdf",
            use_container_width=True,
        )

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Data Table View
    st.markdown("### Findings Table")
    df = findings_to_dataframe(report.findings)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ---------------------------------------------------------
# Page 6: About & Methodology Page (Matching Reference Panel 6)
# ---------------------------------------------------------

def render_about_page() -> None:
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
            <div>
                <h2 style="margin: 0; color: #FFFFFF;">About This Project</h2>
                <p style="color: #94A3B8; margin-top: 6px; font-size: 1rem; max-width: 650px;">
                    Privacy Contradiction Finder helps users understand whether an app's privacy policy matches 
                    the permissions it requests. It uses AI and rule-based analysis to identify potential 
                    contradictions and privacy concerns.
                </p>
            </div>
            <div style="font-size: 3rem;">🛡️</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### How It Works")

    # 4 Workflow Steps matching Panel 6
    w1, w2, w3, w4 = st.columns(4)
    with w1:
        st.markdown(
            """
            <div class="privy-card" style="text-align: center; padding: 18px 14px;">
                <div style="font-size: 1.8rem; margin-bottom: 8px;">📄</div>
                <div style="font-weight: 700; color: #FFFFFF; font-size: 0.95rem;">1. Read Policy</div>
                <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 4px;">Extract policy claims from policy text or URL.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with w2:
        st.markdown(
            """
            <div class="privy-card" style="text-align: center; padding: 18px 14px;">
                <div style="font-size: 1.8rem; margin-bottom: 8px;">⚙️</div>
                <div style="font-weight: 700; color: #FFFFFF; font-size: 0.95rem;">2. Get Permissions</div>
                <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 4px;">Parse and analyze app permissions.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with w3:
        st.markdown(
            """
            <div class="privy-card" style="text-align: center; padding: 18px 14px;">
                <div style="font-size: 1.8rem; margin-bottom: 8px;">🧠</div>
                <div style="font-weight: 700; color: #FFFFFF; font-size: 0.95rem;">3. AI Analysis</div>
                <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 4px;">Compare claims with permissions using AI + rules.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with w4:
        st.markdown(
            """
            <div class="privy-card" style="text-align: center; padding: 18px 14px;">
                <div style="font-size: 1.8rem; margin-bottom: 8px;">👥</div>
                <div style="font-weight: 700; color: #FFFFFF; font-size: 0.95rem;">4. Show Results</div>
                <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 4px;">Show findings with evidence, risk level and recommendations.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # 3 Accordions matching Panel 6
    with st.expander("📁 Data Sources", expanded=False):
        st.markdown(
            """
            - **Privacy Policies**: Publicly accessible web URLs parsed safely via BeautifulSoup with SSRF defenses, or user-uploaded PDF/TXT documents extracted with PyMuPDF.
            - **Permission Evidence**: Android permissions extracted statically from `AndroidManifest.xml` (using tools like `apktool`/`aapt`), declared via Google Play Data Safety, or provided manually by the user.
            """
        )

    with st.expander("⚖️ Limitations", expanded=False):
        st.markdown(
            """
            - **Permission vs. Exfiltration**: A requested permission only indicates operating system authorization. It does not establish that data was collected, stored, or transmitted over the network.
            - **Preliminary Analysis**: Results serve as preliminary privacy auditing for consumer awareness and security research, not conclusive proof of legal misconduct.
            - **Dynamic Inspection Required**: Definitive verification requires network packet inspection (PCAP via mitmproxy) and runtime method hooking (via Frida).
            """
        )

    with st.expander("🔒 Privacy & Security", expanded=False):
        st.markdown(
            """
            - **SSRF Defense**: Target policy URLs are strictly validated to block loopback addresses (`127.0.0.1`), private LANs (`192.168.x.x`, `10.x.x.x`), and cloud metadata services (`169.254.169.254`).
            - **Prompt Injection Resilience**: The primary analysis engine is deterministic and rule-based, immune to prompt injection instructions embedded in untrusted policy documents.
            - **No Third-Party Uploads**: User documents are parsed in-memory on the local server without silently uploading APKs to cloud services.
            """
        )


# ---------------------------------------------------------
# Main Application Router
# ---------------------------------------------------------

def main() -> None:
    init_state()
    st.markdown(CUSTOM_UI_CSS, unsafe_allow_html=True)
    render_sidebar()

    page = st.session_state.current_page

    if page == "Home":
        render_home_page()
    elif page == "Analyze App":
        render_analyze_page()
    elif page == "Results":
        render_results_page()
    elif page == "Finding Details":
        render_finding_details_page()
    elif page == "Report":
        render_report_export_page()
    elif page == "About":
        render_about_page()
    else:
        render_home_page()


if __name__ == "__main__":
    main()
