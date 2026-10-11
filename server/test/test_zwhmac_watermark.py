import pytest
import fitz

from src.watermarking_zw_HMAC_method import ZwHMACWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError

# Professionella testvärden istället för hårdkodade strängar i testerna 
TEST_SECRET = "CLASSIFIED_PAYLOAD_001"
TEST_KEY = "secure_hmac_key_2026"
WRONG_KEY = "malicious_actor_key"

@pytest.fixture
def empty_pdf_bytes():
    """Generates a temporary, blank PDF in memory for testing."""

    doc = fitz.open()
    doc.new_page()
    return doc.tobytes()

@pytest.fixture
def wm_tool():
    """Initializes the watermark class."""

    return ZwHMACWatermark()

def test_is_applicable(wm_tool, empty_pdf_bytes):
    assert wm_tool.is_watermark_applicable(empty_pdf_bytes) is True
    assert wm_tool.is_watermark_applicable(b"this is not a valid pdf file") is False

def test_add_and_read_success(wm_tool, empty_pdf_bytes):
    watermarked_pdf = wm_tool.add_watermark(empty_pdf_bytes, TEST_SECRET, TEST_KEY)
    extracted_secret = wm_tool.read_secret(watermarked_pdf, TEST_KEY)
    
    assert extracted_secret == TEST_SECRET

def test_read_wrong_key(wm_tool, empty_pdf_bytes):
    watermarked_pdf = wm_tool.add_watermark(empty_pdf_bytes, TEST_SECRET, TEST_KEY)
    
    # FIX: added ^ and $ to force exakt matchning from error message
    with pytest.raises(InvalidKeyError, match="^Wrong key or manipulated watermarking$"):
        wm_tool.read_secret(watermarked_pdf, WRONG_KEY)
    
    with pytest.raises(InvalidKeyError, match="Wrong key or manipulated watermarking"):
        wm_tool.read_secret(watermarked_pdf, WRONG_KEY)

def test_read_no_watermark(wm_tool, empty_pdf_bytes):
    with pytest.raises(SecretNotFoundError, match="^No watermark found$"): #Same Fix from test_read_wrong_key
        wm_tool.read_secret(empty_pdf_bytes, TEST_KEY)

def test_deterministic_and_unique(wm_tool, empty_pdf_bytes):
    # Generates files with two different secrets
    pdf1 = wm_tool.add_watermark(empty_pdf_bytes, TEST_SECRET, TEST_KEY)
    pdf3 = wm_tool.add_watermark(empty_pdf_bytes, "DIFFERENT_PAYLOAD_002", TEST_KEY)
    
    # Verifies the files are different with different secrets
    assert pdf1 != pdf3

def test_survives_metadata_removal(wm_tool, empty_pdf_bytes):
    watermarked = wm_tool.add_watermark(empty_pdf_bytes, TEST_SECRET, TEST_KEY)
    
    # Simulate a user/attacker scrubbing the PDF metadata
    doc = fitz.open(stream=watermarked, filetype="pdf")
    doc.set_metadata({})
    cleaned_bytes = doc.tobytes(garbage=4, clean=True, deflate=True)
    doc.close()
    
    assert wm_tool.read_secret(cleaned_bytes, TEST_KEY) == TEST_SECRET

def test_tampering_is_rejected(wm_tool, empty_pdf_bytes):
    watermarked = wm_tool.add_watermark(empty_pdf_bytes, TEST_SECRET, TEST_KEY)
    
    # Simulate an attacker flipping a single bit (replacing a '~' with '^')
    tampered = watermarked.replace(b"~", b"^", 1) 
    
    # The HMAC or UTF-8 decoding should immediately fail
    with pytest.raises((InvalidKeyError, WatermarkingError)):
        wm_tool.read_secret(tampered, TEST_KEY)