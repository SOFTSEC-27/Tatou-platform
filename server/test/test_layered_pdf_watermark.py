from __future__ import annotations

try:
    import pymupdf as fitz
except ImportError:
    import fitz

import pytest

from layered_pdf_watermark import LayeredPDFWatermark
from watermarking_method import InvalidKeyError


RECIPIENT = "Group_Test"

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
def method() -> LayeredPDFWatermark:
    return LayeredPDFWatermark()


@pytest.fixture()
def source_pdf() -> bytes:
    """Create a valid two-page PDF entirely in memory."""
    document = fitz.open()

    first_page = document.new_page()
    first_page.insert_text(
        (72, 72),
        "Tatou layered watermark unit test - page 1",
    )

    second_page = document.new_page()
    second_page.insert_text(
        (72, 72),
        "Tatou layered watermark unit test - page 2",
    )

    pdf_bytes = document.tobytes()
    document.close()

    return pdf_bytes


def test_roundtrip_recovers_exact_recipient(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=RECIPIENT,
        key=TEST_KEY,
        position="footer",
    )

    assert watermarked.startswith(b"%PDF-")
    assert watermarked != source_pdf
    assert method.read_secret(watermarked, TEST_KEY) == RECIPIENT


def test_output_is_valid_pdf_and_label_is_on_every_page(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=RECIPIENT,
        key=TEST_KEY,
        position="footer",
    )

    document = fitz.open(stream=watermarked, filetype="pdf")

    try:
        assert document.page_count == 2

        for page in document:
            page_text = page.get_text()
            assert RECIPIENT in page_text
    finally:
        document.close()


def test_wrong_key_is_rejected(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=RECIPIENT,
        key=TEST_KEY,
        position="footer",
    )

    with pytest.raises(InvalidKeyError):
        method.read_secret(watermarked, WRONG_KEY)


def test_watermark_survives_eof_cleanup(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=RECIPIENT,
        key=TEST_KEY,
        position="footer",
    )

    eof_position = watermarked.rfind(b"%%EOF")
    assert eof_position >= 0

    cleaned = (
        watermarked[: eof_position + len(b"%%EOF")]
        + b"\n"
    )

    assert method.read_secret(cleaned, TEST_KEY) == RECIPIENT


def test_watermark_survives_metadata_removal(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=RECIPIENT,
        key=TEST_KEY,
        position="footer",
    )

    document = fitz.open(stream=watermarked, filetype="pdf")

    try:
        document.set_metadata({})
        cleaned = document.tobytes(
            garbage=4,
            clean=True,
            deflate=True,
        )
    finally:
        document.close()

    assert method.read_secret(cleaned, TEST_KEY) == RECIPIENT


def test_authenticated_payload_tampering_is_rejected(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=RECIPIENT,
        key=TEST_KEY,
        position="footer",
    )

    document = fitz.open(stream=watermarked, filetype="pdf")

    try:
        searchable_values = [
            value
            for value in document.metadata.values()
            if isinstance(value, str) and value
        ]

        searchable_values.extend(
            page.get_text()
            for page in document
        )
    finally:
        document.close()

    candidates: list[str] = []

    for value in searchable_values:
        candidates.extend(method._find_payloads(value))

    valid_payload: str | None = None

    for candidate in candidates:
        try:
            recovered = method._decode_payload(
                candidate,
                TEST_KEY,
            )
        except Exception:
            continue

        if recovered == RECIPIENT:
            valid_payload = candidate
            break

    assert valid_payload is not None

    position = len(valid_payload) // 2
    original_character = valid_payload[position]
    replacement = "A" if original_character != "A" else "B"

    tampered_payload = (
        valid_payload[:position]
        + replacement
        + valid_payload[position + 1 :]
    )

    assert tampered_payload != valid_payload

    with pytest.raises(Exception):
        method._decode_payload(
            tampered_payload,
            TEST_KEY,
        )


@pytest.mark.parametrize(
    ("secret", "key"),
    [
        ("", TEST_KEY),
        (RECIPIENT, ""),
    ],
)
def test_empty_secret_or_key_is_rejected(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
    secret: str,
    key: str,
) -> None:
    with pytest.raises(ValueError):
        method.add_watermark(
            source_pdf,
            secret=secret,
            key=key,
            position="footer",
        )


def test_empty_read_key_is_rejected(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    watermarked = method.add_watermark(
        source_pdf,
        secret=RECIPIENT,
        key=TEST_KEY,
        position="footer",
    )

    with pytest.raises(ValueError):
        method.read_secret(watermarked, "")


def test_invalid_position_is_rejected(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    with pytest.raises(ValueError):
        method.add_watermark(
            source_pdf,
            secret=RECIPIENT,
            key=TEST_KEY,
            position="diagonal",
        )


def test_different_recipients_produce_different_files(
    method: LayeredPDFWatermark,
    source_pdf: bytes,
) -> None:
    group_07_pdf = method.add_watermark(
        source_pdf,
        secret="Group_07",
        key=TEST_KEY,
        position="footer",
    )

    group_08_pdf = method.add_watermark(
        source_pdf,
        secret="Group_08",
        key=TEST_KEY,
        position="footer",
    )

    assert group_07_pdf != group_08_pdf
    assert method.read_secret(group_07_pdf, TEST_KEY) == "Group_07"
    assert method.read_secret(group_08_pdf, TEST_KEY) == "Group_08"