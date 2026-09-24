from __future__ import annotations

import json

try:
    import pymupdf as fitz
except ImportError:
    import fitz

import pytest

from visible_text_watermark import VisibleTextWatermark
from watermarking_method import InvalidKeyError


WATERMARK_TEXT = "CONFIDENTIAL - Test_Group"

TEST_KEY = (
    "0123456789abcdef"
    "0123456789abcdef"
    "0123456789abcdef"
    "0123456789abcdef"
)

WRONG_KEY = (
    "ffffffffffffffff"
    "ffffffffffffffff"
    "ffffffffffffffff"
    "ffffffffffffffff"
)


@pytest.fixture()
def method() -> VisibleTextWatermark:
    return VisibleTextWatermark()


@pytest.fixture()
def source_pdf() -> bytes:
    """Create a valid two-page PDF in memory."""
    document = fitz.open()

    first_page = document.new_page()
    first_page.insert_text(
        (72, 72),
        "Visible watermark test - page 1",
    )

    second_page = document.new_page()
    second_page.insert_text(
        (72, 72),
        "Visible watermark test - page 2",
    )

    pdf_bytes = document.tobytes()
    document.close()

    return pdf_bytes


def test_roundtrip_recovers_exact_text(
    method: VisibleTextWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=WATERMARK_TEXT,
        key=TEST_KEY,
        position="tiled",
    )

    assert watermarked.startswith(b"%PDF-")
    assert watermarked != source_pdf

    recovered = method.read_secret(
        watermarked,
        TEST_KEY,
    )

    assert recovered == WATERMARK_TEXT


def test_visible_text_is_added_to_every_page(
    method: VisibleTextWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=WATERMARK_TEXT,
        key=TEST_KEY,
        position="tiled",
    )

    document = fitz.open(
        stream=watermarked,
        filetype="pdf",
    )

    try:
        assert document.page_count == 2

        for page in document:
            extracted_text = page.get_text("text")
            assert WATERMARK_TEXT in extracted_text
    finally:
        document.close()


def test_correct_key_succeeds_and_wrong_key_is_rejected(
    method: VisibleTextWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=WATERMARK_TEXT,
        key=TEST_KEY,
        position="tiled",
    )

    assert (
        method.read_secret(watermarked, TEST_KEY)
        == WATERMARK_TEXT
    )

    with pytest.raises(InvalidKeyError):
        method.read_secret(
            watermarked,
            WRONG_KEY,
        )


def test_authenticated_metadata_tampering_is_rejected(
    method: VisibleTextWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=WATERMARK_TEXT,
        key=TEST_KEY,
        position="tiled",
    )

    document = fitz.open(
        stream=watermarked,
        filetype="pdf",
    )

    try:
        metadata = document.metadata or {}
        keywords = metadata.get("keywords", "")

        match = method._PAYLOAD_RE.search(keywords)
        assert match is not None

        original_encoded = match.group(1)
        envelope = method._decode_payload(original_encoded)

        # Keep valid JSON/Base64 but invalidate the HMAC.
        envelope["mac"] = "0" * 64

        tampered_serialized = json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        tampered_encoded = method._urlsafe_encode(
            tampered_serialized
        )

        allowed_fields = (
            "title",
            "author",
            "subject",
            "keywords",
            "creator",
            "producer",
            "creationDate",
            "modDate",
            "trapped",
        )

        clean_metadata = {
            name: metadata.get(name, "") or ""
            for name in allowed_fields
        }

        clean_metadata["keywords"] = keywords.replace(
            original_encoded,
            tampered_encoded,
            1,
        )

        document.set_metadata(clean_metadata)

        tampered_pdf = document.tobytes(
            garbage=4,
            clean=True,
            deflate=True,
        )
    finally:
        document.close()

    with pytest.raises(InvalidKeyError):
        method.read_secret(
            tampered_pdf,
            TEST_KEY,
        )


@pytest.mark.parametrize(
    ("secret", "key"),
    [
        ("", TEST_KEY),
        ("   ", TEST_KEY),
        (WATERMARK_TEXT, ""),
    ],
)
def test_empty_text_or_key_is_rejected(
    method: VisibleTextWatermark,
    source_pdf: bytes,
    secret: str,
    key: str,
) -> None:
    with pytest.raises(ValueError):
        method.add_watermark(
            source_pdf,
            secret=secret,
            key=key,
            position="tiled",
        )


def test_long_watermark_text_is_rejected(
    method: VisibleTextWatermark,
    source_pdf: bytes,
) -> None:
    with pytest.raises(ValueError):
        method.add_watermark(
            source_pdf,
            secret="A" * 65,
            key=TEST_KEY,
            position="tiled",
        )


def test_invalid_position_is_rejected(
    method: VisibleTextWatermark,
    source_pdf: bytes,
) -> None:
    with pytest.raises(ValueError):
        method.add_watermark(
            source_pdf,
            secret=WATERMARK_TEXT,
            key=TEST_KEY,
            position="footer",
        )


def test_different_keys_produce_different_authenticated_files(
    method: VisibleTextWatermark,
    source_pdf: bytes,
) -> None:
    first = method.add_watermark(
        source_pdf,
        secret=WATERMARK_TEXT,
        key=TEST_KEY,
        position="tiled",
    )

    second = method.add_watermark(
        source_pdf,
        secret=WATERMARK_TEXT,
        key=WRONG_KEY,
        position="tiled",
    )

    assert first != second
    assert method.read_secret(first, TEST_KEY) == WATERMARK_TEXT
    assert method.read_secret(second, WRONG_KEY) == WATERMARK_TEXT