"""Layered PDF watermark using visible text and authenticated metadata."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
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


class LayeredPDFWatermark(WatermarkingMethod):
    """Embed an authenticated recipient marker in several PDF layers."""

    name: Final[str] = "layered-identity-v1"

    _MARKER: Final[str] = "TATOU-WM1:"
    _CONTEXT: Final[bytes] = b"tatou-layered-identity-v1\x00"
    _PAYLOAD_RE: Final[re.Pattern[str]] = re.compile(
        r"TATOU-WM1:([A-Za-z0-9_-]+={0,2})"
    )

    @staticmethod
    def get_usage() -> str:
        return (
            "Authenticated recipient watermark stored in PDF metadata and "
            "page content, with a visible trace label on every page. "
            "Position may be center, header, or footer."
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        if position not in (None, "center", "header", "footer"):
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
        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        placement = position or "center"
        if placement not in ("center", "header", "footer"):
            raise ValueError("Position must be center, header, or footer")

        data = load_pdf_bytes(pdf)
        payload, trace_id = self._build_payload(secret, key)
        marker = self._MARKER + payload

        display_secret = self._safe_display_text(secret)
        visible_label = (
            f"CONFIDENTIAL - Recipient: {display_secret} "
            f"- Trace: {trace_id}"
        )

        try:
            document = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError("Unable to open PDF") from exc

        try:
            if document.page_count < 1:
                raise WatermarkingError("PDF contains no pages")

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
                f"Tatou trace {trace_id}"
            ).strip()

            document.set_metadata(clean_metadata)

            for page in document:
                visible_rect = self._visible_rect(page.rect, placement)

                result = page.insert_textbox(
                    visible_rect,
                    visible_label,
                    fontsize=16,
                    fontname="helv",
                    color=(0.45, 0.45, 0.45),
                    fill_opacity=0.22,
                    align=fitz.TEXT_ALIGN_CENTER,
                    overlay=True,
                )

                if result < 0:
                    page.insert_text(
                        (36, max(36, visible_rect.y1)),
                        visible_label[:100],
                        fontsize=9,
                        fontname="helv",
                        color=(0.45, 0.45, 0.45),
                        fill_opacity=0.22,
                        overlay=True,
                    )

                hidden_rect = fitz.Rect(
                    2,
                    max(2, page.rect.height - 10),
                    max(3, page.rect.width - 2),
                    max(3, page.rect.height - 2),
                )

                page.insert_textbox(
                    hidden_rect,
                    marker,
                    fontsize=0.5,
                    fontname="cour",
                    color=(0.98, 0.98, 0.98),
                    fill_opacity=0.03,
                    overlay=True,
                )

            output = document.tobytes(
                garbage=4,
                deflate=True,
                clean=True,
            )
        except WatermarkingError:
            raise
        except Exception as exc:
            raise WatermarkingError("Unable to embed PDF watermark") from exc
        finally:
            document.close()

        if not output.startswith(b"%PDF-"):
            raise WatermarkingError("Watermarking produced an invalid PDF")

        return output

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)

        try:
            document = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError("Unable to open PDF") from exc

        candidates: list[str] = []
        invalid_key_seen = False

        try:
            metadata = document.metadata or {}

            for value in metadata.values():
                if isinstance(value, str):
                    candidates.extend(self._find_payloads(value))

            for page in document:
                page_text = page.get_text("text")
                candidates.extend(self._find_payloads(page_text))
        finally:
            document.close()

        for candidate in dict.fromkeys(candidates):
            try:
                return self._decode_payload(candidate, key)
            except InvalidKeyError:
                invalid_key_seen = True
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue

        if invalid_key_seen:
            raise InvalidKeyError(
                "The watermark exists, but the supplied key is incorrect"
            )

        raise SecretNotFoundError(
            "No valid layered identity watermark was found"
        )

    def _build_payload(self, secret: str, key: str) -> tuple[str, str]:
        secret_bytes = secret.encode("utf-8")

        mac = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + secret_bytes,
            hashlib.sha256,
        ).hexdigest()

        payload = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
            "mac": mac,
        }

        encoded = base64.urlsafe_b64encode(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).decode("ascii")

        return encoded, mac[:16]

    def _decode_payload(self, encoded: str, key: str) -> str:
        raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))

        if payload.get("v") != 1:
            raise ValueError("Unsupported watermark version")

        if payload.get("alg") != "HMAC-SHA256":
            raise ValueError("Unsupported watermark algorithm")

        secret_bytes = base64.b64decode(
            str(payload["secret"]).encode("ascii"),
            validate=True,
        )

        supplied_mac = str(payload["mac"])
        expected_mac = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + secret_bytes,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(supplied_mac, expected_mac):
            raise InvalidKeyError("Watermark authentication failed")

        return secret_bytes.decode("utf-8")

    def _find_payloads(self, value: str) -> list[str]:
        return [
            match.group(1)
            for match in self._PAYLOAD_RE.finditer(value)
        ]

    @staticmethod
    def _safe_display_text(secret: str) -> str:
        cleaned = "".join(
            character if character.isprintable() else "?"
            for character in secret
        )
        return cleaned[:64]

    @staticmethod
    def _visible_rect(
        page_rect: fitz.Rect,
        position: str,
    ) -> fitz.Rect:
        margin = 36
        height = 52

        if position == "header":
            top = margin
        elif position == "footer":
            top = max(margin, page_rect.height - margin - height)
        else:
            top = max(margin, (page_rect.height - height) / 2)

        return fitz.Rect(
            margin,
            top,
            max(margin + 1, page_rect.width - margin),
            top + height,
        )


__all__ = ["LayeredPDFWatermark"]