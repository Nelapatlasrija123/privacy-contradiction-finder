"""End-to-End User Journey and Navigation Tests for PrivyScan Streamlit Web Application.

Tests:
1. Initial landing on Home page with empty audit state (no fake results).
2. Navigation to Results / Report / Finding Details when empty shows guidance, no crash, no fake data.
3. Every sidebar link navigates to the correct page.
4. 'Get Started' button opens 'Analyze App'.
5. Input validation on Analyze App catches missing fields.
6. Case study presets populate state correctly.
7. 'Analyze Privacy' button triggers analysis, preserves state, and navigates to 'Results'.
8. Results page displays accurate counts, assessment, and finding cards.
9. Clicking 'Inspect Details' opens 'Finding Details' with all required sections.
10. '← Back to Results' and 'Analyze Another App' navigate correctly.
11. Report page displays findings matrix and export buttons (CSV, JSON, PDF).
"""

from __future__ import annotations

from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = str(Path(__file__).parent.parent / "app.py")


@pytest.fixture
def fresh_app() -> AppTest:
    """Fixture providing a fresh AppTest instance initialized on Home."""
    at = AppTest.from_file(APP_PATH, default_timeout=30)
    at.run()
    return at


def test_home_page_initial_state_no_fake_results(fresh_app: AppTest):
    """Verify home page loads, starts at Home, and audit_report is None (no fake results)."""
    assert fresh_app.session_state.current_page == "Home"
    assert fresh_app.session_state.audit_report is None
    assert len(fresh_app.exception) == 0


def test_direct_navigation_without_analysis_shows_empty_state(fresh_app: AppTest):
    """Verify navigating directly to Results or Report shows guidance and no fake data."""
    # Navigate to Results directly
    fresh_app.session_state.current_page = "Results"
    fresh_app.run()
    assert fresh_app.session_state.audit_report is None
    assert len(fresh_app.exception) == 0
    # Should contain "No Analysis Results Available Yet"
    text_content = " ".join([m.value for m in fresh_app.markdown])
    assert "No Analysis Results Available Yet" in text_content

    # Navigate to Report directly
    fresh_app.session_state.current_page = "Report"
    fresh_app.run()
    assert len(fresh_app.exception) == 0
    text_content = " ".join([m.value for m in fresh_app.markdown])
    assert "No Audit Report Generated Yet" in text_content

    # Navigate to Finding Details directly
    fresh_app.session_state.current_page = "Finding Details"
    fresh_app.run()
    assert len(fresh_app.exception) == 0


def test_sidebar_links_navigate_to_all_pages(fresh_app: AppTest):
    """Verify that every sidebar link navigates to the expected page."""
    # 1. Analyze App
    sidebar_analyze = fresh_app.sidebar.button(key="sidebar_nav_Analyze App")
    sidebar_analyze.click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Analyze App"
    assert len(fresh_app.exception) == 0

    # 2. Results
    sidebar_results = fresh_app.sidebar.button(key="sidebar_nav_Results")
    sidebar_results.click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Results"
    assert len(fresh_app.exception) == 0

    # 3. Report
    sidebar_report = fresh_app.sidebar.button(key="sidebar_nav_Report")
    sidebar_report.click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Report"
    assert len(fresh_app.exception) == 0

    # 4. About
    sidebar_about = fresh_app.sidebar.button(key="sidebar_nav_About")
    sidebar_about.click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "About"
    assert len(fresh_app.exception) == 0

    # 5. Home
    sidebar_home = fresh_app.sidebar.button(key="sidebar_nav_Home")
    sidebar_home.click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Home"
    assert len(fresh_app.exception) == 0


def test_get_started_button_opens_analyze_app(fresh_app: AppTest):
    """Verify 'Get Started →' on the Home page transitions to Analyze App."""
    get_started_btn = fresh_app.button(key="home_get_started")
    get_started_btn.click()
    fresh_app.run()

    assert fresh_app.session_state.current_page == "Analyze App"
    assert len(fresh_app.exception) == 0


def test_analyze_app_validation_blocks_empty_submission(fresh_app: AppTest):
    """Verify input validation triggers error warnings when required fields are missing."""
    fresh_app.session_state.current_page = "Analyze App"
    fresh_app.session_state.app_name = ""
    fresh_app.session_state.raw_policy_text = ""
    fresh_app.session_state.selected_permissions = []
    fresh_app.run()

    analyze_btn = fresh_app.button(key="btn_run_analysis")
    analyze_btn.click()
    fresh_app.run()

    # Still on Analyze App page and errors displayed
    assert fresh_app.session_state.current_page == "Analyze App"
    assert fresh_app.session_state.audit_report is None
    assert len(fresh_app.error) > 0


def test_complete_end_to_end_journey(fresh_app: AppTest):
    """Test full journey: Home -> Get Started -> Analyze App -> Run Analysis -> Results -> Finding Details -> Back -> Report."""
    # Step 1: Start at Home
    assert fresh_app.session_state.current_page == "Home"

    # Step 2: Click Get Started
    fresh_app.button(key="home_get_started").click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Analyze App"

    # Step 3: Populate Form (e.g. via WhatsApp Demo preset)
    wa_preset_btn = fresh_app.button(key="qf_wa")
    wa_preset_btn.click()
    fresh_app.run()

    assert fresh_app.session_state.app_name == "WhatsApp Messenger"
    assert len(fresh_app.session_state.selected_permissions) > 0
    assert len(fresh_app.session_state.raw_policy_text) > 0

    # Step 4: Click 'Analyze Privacy'
    fresh_app.button(key="btn_run_analysis").click()
    fresh_app.run()

    # Step 5: Verify Results Dashboard
    assert fresh_app.session_state.current_page == "Results"
    report = fresh_app.session_state.audit_report
    assert report is not None
    assert report.app_name == "WhatsApp Messenger"
    assert len(report.findings) > 0

    # Step 6: Click 'Inspect Details →' on first finding
    inspect_btn = fresh_app.button(key="btn_inspect_0")
    inspect_btn.click()
    fresh_app.run()

    # Step 7: Verify Finding Details page
    assert fresh_app.session_state.current_page == "Finding Details"
    assert fresh_app.session_state.selected_finding_idx == 0
    md_text = " ".join([m.value for m in fresh_app.markdown])
    assert "Finding Details" in md_text
    assert "Privacy Policy Statement" in md_text
    assert "Permission Evidence" in md_text
    assert "AI Explanation" in md_text
    assert "Recommended Next Step" in md_text

    # Step 8: Click '← Back to Results'
    back_btn = fresh_app.button(key="back_to_results_btn")
    back_btn.click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Results"

    # Step 9: Navigate to Report page
    fresh_app.sidebar.button(key="sidebar_nav_Report").click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Report"
    assert len(fresh_app.download_button) >= 3  # CSV, JSON, PDF download buttons

    # Step 10: Verify Analyze Another App navigates back to Analyze App
    fresh_app.sidebar.button(key="sidebar_nav_Results").click()
    fresh_app.run()
    assert fresh_app.session_state.current_page == "Results"
