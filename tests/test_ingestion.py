"""Unit tests for document extraction, PDF parsing, and SSRF-safe URL fetching."""

from __future__ import annotations

import io
import pytest
import pymupdf

from src.ingestion.text_extractor import (
    clean_text,
    extract_from_txt,
    extract_from_pdf,
    extract_from_uploaded_file,
    DocumentExtractionError,
)
from src.ingestion.url_fetcher import (
    is_ip_publicly_routable,
    validate_url_safety,
    extract_policy_from_html,
    SSRFProtectionError,
    WebRetrievalError,
)


# ---------------------------------------------------------
# Test Text Cleaning and Normalization
# ---------------------------------------------------------

def test_clean_text_normalizes_whitespace():
    raw = "  Hello   world!  \r\n\r\n\r\nThis   is   a   test.  \n"
    result = clean_text(raw)
    assert result == "Hello   world!\n\nThis   is   a   test."


def test_clean_text_filters_control_characters():
    raw = "Privacy\x00\x07 Policy\x1b Statement"
    result = clean_text(raw)
    assert result == "Privacy Policy Statement"


def test_clean_text_empty_input():
    assert clean_text("") == ""
    assert clean_text("   \n\t  ") == ""


# ---------------------------------------------------------
# Test TXT Extraction
# ---------------------------------------------------------

def test_extract_from_txt_success():
    sample = "We do not collect or sell your personal information.\nAll data is processed locally."
    content_bytes = sample.encode("utf-8")
    extracted = extract_from_txt(content_bytes)
    assert "We do not collect or sell" in extracted


def test_extract_from_txt_empty_raises_error():
    with pytest.raises(DocumentExtractionError, match="empty"):
        extract_from_txt(b"")


def test_extract_from_txt_whitespace_only_raises_error():
    with pytest.raises(DocumentExtractionError, match="empty"):
        extract_from_txt(b"   \r\n\t  ")


# ---------------------------------------------------------
# Test PDF Extraction with PyMuPDF
# ---------------------------------------------------------

def create_in_memory_pdf(page_texts: list[str]) -> bytes:
    """Helper to generate an in-memory PDF document using PyMuPDF."""
    doc = pymupdf.open()
    for text in page_texts:
        page = doc.new_page()
        page.insert_text((50, 50), text)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def test_extract_from_pdf_single_page():
    pdf_bytes = create_in_memory_pdf(["Privacy Statement: We collect location data."])
    extracted = extract_from_pdf(pdf_bytes)
    assert "Privacy Statement: We collect location data." in extracted


def test_extract_from_pdf_multi_page():
    pdf_bytes = create_in_memory_pdf([
        "Page 1: Overview of our services.",
        "Page 2: We request camera access to take profile photos.",
    ])
    extracted = extract_from_pdf(pdf_bytes)
    assert "Page 1: Overview" in extracted
    assert "Page 2: We request camera access" in extracted


def test_extract_from_pdf_empty_bytes_raises_error():
    with pytest.raises(DocumentExtractionError, match="empty"):
        extract_from_pdf(b"")


def test_extract_from_uploaded_file_dispatcher():
    txt_bytes = b"Sample text policy content."
    assert "Sample text policy" in extract_from_uploaded_file("policy.txt", txt_bytes)

    pdf_bytes = create_in_memory_pdf(["PDF policy sample."])
    assert "PDF policy sample" in extract_from_uploaded_file("policy.pdf", pdf_bytes)

    with pytest.raises(DocumentExtractionError, match="Unsupported file type"):
        extract_from_uploaded_file("policy.docx", b"word doc content")


# ---------------------------------------------------------
# Test SSRF Protection & IP Routing
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "ip_address,expected_routable",
    [
        ("127.0.0.1", False),           # IPv4 Loopback
        ("127.0.1.1", False),           # Subnet loopback
        ("::1", False),                 # IPv6 Loopback
        ("10.0.0.1", False),            # RFC 1918 Private class A
        ("172.16.0.1", False),          # RFC 1918 Private class B
        ("192.168.1.1", False),         # RFC 1918 Private class C
        ("169.254.169.254", False),     # Link-local / Cloud Metadata
        ("0.0.0.0", False),             # Unspecified
        ("224.0.0.1", False),           # Multicast
        ("8.8.8.8", True),              # Public DNS (Google)
        ("1.1.1.1", True),              # Public DNS (Cloudflare)
        ("93.184.216.34", True),        # Public IP (example.com)
    ],
)
def test_is_ip_publicly_routable(ip_address: str, expected_routable: bool):
    assert is_ip_publicly_routable(ip_address) == expected_routable


def test_validate_url_safety_blocks_file_scheme():
    with pytest.raises(SSRFProtectionError, match="Unsupported URL scheme"):
        validate_url_safety("file:///etc/passwd")


def test_validate_url_safety_blocks_ftp_scheme():
    with pytest.raises(SSRFProtectionError, match="Unsupported URL scheme"):
        validate_url_safety("ftp://ftp.example.com/policy.txt")


def test_validate_url_safety_blocks_localhost_string():
    with pytest.raises(SSRFProtectionError, match="blocked for security"):
        validate_url_safety("http://localhost:8501")


def test_validate_url_safety_blocks_loopback_ip():
    with pytest.raises(SSRFProtectionError, match="private/internal IP"):
        validate_url_safety("http://127.0.0.1:8000/internal-admin")


def test_validate_url_safety_blocks_cloud_metadata():
    with pytest.raises(SSRFProtectionError, match="private/internal IP"):
        validate_url_safety("http://169.254.169.254/latest/meta-data")


def test_validate_url_safety_blocks_private_lan():
    with pytest.raises(SSRFProtectionError, match="private/internal IP"):
        validate_url_safety("http://192.168.1.1/router-settings")


# ---------------------------------------------------------
# Test HTML Policy Extraction
# ---------------------------------------------------------

def test_extract_policy_from_html_strips_scripts_and_nav():
    sample_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Test Privacy</title><script>alert('bad');</script></head>
    <body>
        <nav><a href="/home">Home</a> | <a href="/login">Login</a></nav>
        <header><h1>Site Header</h1></header>
        <main>
            <h2>Privacy Policy</h2>
            <p>We do not collect precise GPS location data.</p>
            <p>Audio is only recorded when you press the microphone button.</p>
        </main>
        <footer>Copyright 2026 Example Corp</footer>
    </body>
    </html>
    """
    extracted = extract_policy_from_html(sample_html)
    assert "alert('bad')" not in extracted
    assert "Site Header" not in extracted
    assert "Copyright 2026" not in extracted
    assert "We do not collect precise GPS location data." in extracted
    assert "Audio is only recorded" in extracted
