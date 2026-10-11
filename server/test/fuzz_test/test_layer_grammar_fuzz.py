import pytest
from watermarking_method import InvalidKeyError
import pymupdf as fitz
from hypothesis import given, settings, strategies as st
from layered_pdf_watermark import LayeredPDFWatermark


recipients = st.text(
    alphabet="0123456789",
    min_size=1,
    max_size=3,
).map(lambda digits: f"Group_{digits}")

labels = st.text(
    alphabet='abcABC012å中"\\\n',
    min_size=1,
    max_size=96,
)

layered_secrets = st.one_of(
    recipients,
    st.tuples(recipients, labels).map(
        lambda parts: ":".join(parts)
    ),
)

layered_keys = st.text(
    alphabet="abcdef0123456789",
    min_size=1,
    max_size=32,
)


@settings(max_examples=100, deadline=None)
@given(
    secret=layered_secrets,
    key=layered_keys,
    position=st.sampled_from(["center", "header", "footer"]),
)
def test_layered_grammar_roundtrip(secret, key, position):
    with fitz.open() as document:
        document.new_page()
        original_pdf = document.tobytes()

    method = LayeredPDFWatermark()

    watermarked_pdf = method.add_watermark(
        pdf=original_pdf,
        secret=secret,
        key=key,
        position=position,
    )

    with fitz.open(stream=watermarked_pdf, filetype="pdf") as document:
        assert document.page_count == 1

    extracted_secret = method.read_secret(
        pdf=watermarked_pdf,
        key=key,
    )

    assert extracted_secret == secret
    with pytest.raises(InvalidKeyError):
        method.read_secret(
            pdf=watermarked_pdf,
            key=key + "x",
        )