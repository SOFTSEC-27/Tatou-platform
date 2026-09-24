"""Visible tiled text watermark with authenticated metadata."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from typing import Final

try:
    import pymupdf as fitz
except ImportError:
    import fitz

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class VisibleTextWatermark(WatermarkingMethod):
    """Apply repeated visible text and authenticated PDF metadata."""

    name: Final[str] = "visible-text-watermark"

    _MARKER: Final[str] = "TATOU-VTW1:"
    _CONTEXT: Final[bytes] = b"tatou-visible-text-watermark-v1\x00"

    _PAYLOAD_RE: Final[re.Pattern[str]] = re.compile(
        r"TATOU-VTW1:([A-Za-z0-9_-]+={0,2})"
    )

    @staticmethod
    def get_usage() -> str:
        return (
            "Repeated visible text watermark across every PDF page. "
            "The key authenticates the embedded metadata record. "
            "Position may be empty or tiled."
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        if position not in (None, "", "tiled"):
            return False

        try:
            data = load_pdf_bytes(pdf)

            with fitz.open(stream=data, filetype="pdf") as document:
                return document.page_count > 0
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        text = self._clean_watermark_text(secret)

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        if position not in (None, "", "tiled"):
            raise ValueError("Position must be empty or tiled")

        data = load_pdf_bytes(pdf)
        marker = self._build_marker(text, key)

        try:
            document = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError("Unable to open PDF") from exc

        try:
            if document.page_count < 1:
                raise WatermarkingError("PDF contains no pages")

            # Preserve the existing standard metadata fields.
            metadata = document.metadata or {}

            clean_metadata = {
                name: metadata.get(name, "") or ""
                for name in (
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
            }

            existing_keywords = clean_metadata.get("keywords", "")

            clean_metadata["keywords"] = (
                f"{existing_keywords}\n{marker}".strip()
            )

            clean_metadata["subject"] = (
                f"{clean_metadata.get('subject', '')}\n"
                "Tatou visible text watermark"
            ).strip()

            document.set_metadata(clean_metadata)

            # Use a built-in CJK font when non-ASCII characters are present.
            font_name = (
                "china-s"
                if any(ord(character) > 127 for character in text)
                else "helv"
            )

            for page in document:
                self._apply_tiled_text(
                    page=page,
                    text=text,
                    font_name=font_name,
                )

            output = document.tobytes(
                garbage=4,
                deflate=True,
                clean=True,
            )

        except WatermarkingError:
            raise
        except Exception as exc:
            raise WatermarkingError(
                "Unable to apply visible text watermark"
            ) from exc
        finally:
            document.close()

        if not output.startswith(b"%PDF-"):
            raise WatermarkingError(
                "Watermarking produced an invalid PDF"
            )

        return output

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
    ) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)

        try:
            document = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError("Unable to open PDF") from exc

        candidates: list[str] = []

        try:
            metadata = document.metadata or {}

            for value in metadata.values():
                if isinstance(value, str):
                    candidates.extend(
                        self._PAYLOAD_RE.findall(value)
                    )
        finally:
            document.close()

        if not candidates:
            raise SecretNotFoundError(
                "No visible text watermark record was found"
            )

        invalid_key_seen = False

        for encoded_payload in dict.fromkeys(candidates):
            try:
                envelope = self._decode_payload(encoded_payload)

                if envelope.get("v") != 1:
                    continue

                text = envelope.get("text")
                nonce = envelope.get("nonce")
                supplied_mac = envelope.get("mac")

                if not all(
                    isinstance(value, str) and value
                    for value in (text, nonce, supplied_mac)
                ):
                    continue

                payload = {
                    "nonce": nonce,
                    "text": text,
                    "v": 1,
                }

                expected_mac = self._calculate_mac(
                    payload=payload,
                    key=key,
                )

                if not hmac.compare_digest(
                    supplied_mac,
                    expected_mac,
                ):
                    invalid_key_seen = True
                    continue

                return text

            except (ValueError, TypeError, json.JSONDecodeError):
                continue

        if invalid_key_seen:
            raise InvalidKeyError(
                "The provided key could not verify the watermark"
            )

        raise SecretNotFoundError(
            "No valid visible text watermark record was found"
        )

    @staticmethod
    def _clean_watermark_text(secret: str) -> str:
        if not isinstance(secret, str):
            raise ValueError("Watermark text must be a string")

        # Remove newlines and collapse repeated whitespace.
        cleaned = " ".join(secret.split())

        if not cleaned:
            raise ValueError(
                "Watermark text must not be empty"
            )

        if len(cleaned) > 64:
            raise ValueError(
                "Watermark text must not exceed 64 characters"
            )

        if any(not character.isprintable() for character in cleaned):
            raise ValueError(
                "Watermark text contains invalid characters"
            )

        return cleaned

    @staticmethod
    def _apply_tiled_text(
        page: fitz.Page,
        text: str,
        font_name: str,
    ) -> None:
        page_width = int(page.rect.width)
        page_height = int(page.rect.height)

        horizontal_spacing = 220
        vertical_spacing = 125
        font_size = 18
        angle = 30

        row_number = 0

        for y in range(-40, page_height + 120, vertical_spacing):
            # Offset alternate rows to create a tiled pattern.
            row_offset = -110 if row_number % 2 else 0

            for x in range(
                -160 + row_offset,
                page_width + 220,
                horizontal_spacing,
            ):
                anchor = fitz.Point(x, y)

                page.insert_text(
                    anchor,
                    text,
                    fontsize=font_size,
                    fontname=font_name,
                    color=(0.35, 0.35, 0.35),
                    fill_opacity=0.20,
                    morph=(anchor, fitz.Matrix(angle)),
                    overlay=True,
                )

            row_number += 1

    def _build_marker(
        self,
        text: str,
        key: str,
    ) -> str:
        nonce = self._urlsafe_encode(os.urandom(16))

        payload = {
            "nonce": nonce,
            "text": text,
            "v": 1,
        }

        envelope = {
            **payload,
            "mac": self._calculate_mac(
                payload=payload,
                key=key,
            ),
        }

        serialized = json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return self._MARKER + self._urlsafe_encode(serialized)

    def _calculate_mac(
        self,
        payload: dict[str, object],
        key: str,
    ) -> str:
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + serialized,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _decode_payload(encoded_payload: str) -> dict[str, object]:
        padding = "=" * (-len(encoded_payload) % 4)

        decoded = base64.urlsafe_b64decode(
            encoded_payload + padding
        )

        value = json.loads(decoded.decode("utf-8"))

        if not isinstance(value, dict):
            raise ValueError("Invalid watermark payload")

        return value

    @staticmethod
    def _urlsafe_encode(value: bytes) -> str:
        return (
            base64.urlsafe_b64encode(value)
            .decode("ascii")
            .rstrip("=")
        )


__all__ = ["VisibleTextWatermark"]