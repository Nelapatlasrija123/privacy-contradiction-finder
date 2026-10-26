"""Text extraction and sanitization utilities for Privacy Contradiction Finder.

Handles plain text and PDF document parsing with clean whitespace normalization
and input validation.
"""

from __future__ import annotations

import unicodedata
import pymupdf


class DocumentExtractionError(Exception):
    """Raised when document extraction fails due to formatting, encryption, or corruption."""
    pass


def clean_text(raw_text: str) -> str:
    """Normalize unicode, strip control characters, and collapse excessive whitespace.

    Args:
        raw_text: Raw string extracted from document or web page.

    Returns:
        Sanitized, readable plain text.
    """
    if not raw_text:
        return ""

    # Normalize unicode to NFC (canonical decomposition followed by canonical composition)
    normalized = unicodedata.normalize("NFKC", raw_text)

    # Filter out control characters except standard whitespace (newline, tab, carriage return)
    cleaned_chars = []
    for ch in normalized:
        if ch in ("\n", "\t", "\r") or not unicodedata.category(ch).startswith("C"):
            cleaned_chars.append(ch)
    cleaned = "".join(cleaned_chars)

    # Standardize line breaks
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")

    # Collapse horizontal whitespace runs while preserving paragraph breaks
    lines = [line.strip() for line in cleaned.split("\n")]
    result_lines: list[str] = []
    prev_blank = False

    for line in lines:
        if line:
            result_lines.append(line)
            prev_blank = False
        elif not prev_blank:
            # Allow at most one consecutive blank line to separate paragraphs
            result_lines.append("")
            prev_blank = True

    return "\n".join(result_lines).strip()


def extract_from_txt(content_bytes: bytes) -> str:
    """Extract and decode text from TXT file bytes with multi-encoding fallback.

    Args:
        content_bytes: Raw bytes of the uploaded TXT file.

    Returns:
        Sanitized string content.

    Raises:
        DocumentExtractionError: If file is empty or cannot be decoded.
    """
    if not content_bytes or len(content_bytes.strip()) == 0:
        raise DocumentExtractionError("The provided TXT file is empty.")

    # Try common encodings
    for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            decoded = content_bytes.decode(encoding)
            cleaned = clean_text(decoded)
            if cleaned:
                return cleaned
        except (UnicodeDecodeError, LookupError):
            continue

    # Fallback with replacement of invalid characters
    fallback_decoded = content_bytes.decode("utf-8", errors="replace")
    return clean_text(fallback_decoded)


def extract_from_pdf(pdf_bytes: bytes) -> str:
    """Extract text from a PDF byte stream using PyMuPDF.

    Args:
        pdf_bytes: Raw bytes of the uploaded PDF file.

    Returns:
        Sanitized combined text of all document pages.

    Raises:
        DocumentExtractionError: If PDF is encrypted, corrupted, or contains no readable text.
    """
    if not pdf_bytes or len(pdf_bytes) == 0:
        raise DocumentExtractionError("The provided PDF file is empty.")

    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception as exc:
        raise DocumentExtractionError(f"Failed to open PDF document: {exc}") from exc

    try:
        if doc.is_encrypted:
            raise DocumentExtractionError(
                "The PDF document is password-protected or encrypted. Please provide an unencrypted copy."
            )

        if doc.page_count == 0:
            raise DocumentExtractionError("The PDF document contains no pages.")

        page_texts: list[str] = []
        for page_num in range(doc.page_count):
            page = doc.load_page(page_num)
            text = page.get_text("text")
            if text and text.strip():
                page_texts.append(text.strip())

        if not page_texts:
            raise DocumentExtractionError(
                "The PDF contains no extractable text. It may consist entirely of scanned images."
            )

        combined_text = "\n\n".join(page_texts)
        return clean_text(combined_text)

    finally:
        doc.close()


def extract_from_uploaded_file(file_name: str, file_bytes: bytes) -> str:
    """Dispatcher function to extract text based on file extension.

    Args:
        file_name: Name of the uploaded file.
        file_bytes: Raw bytes of the uploaded file.

    Returns:
        Sanitized plain text extracted from the document.

    Raises:
        DocumentExtractionError: For unsupported formats or extraction failures.
    """
    lower_name = file_name.lower().strip()
    if lower_name.endswith(".txt"):
        return extract_from_txt(file_bytes)
    elif lower_name.endswith(".pdf"):
        return extract_from_pdf(file_bytes)
    else:
        raise DocumentExtractionError(
            f"Unsupported file type for '{file_name}'. Only .txt and .pdf files are supported."
        )
