import pymupdf

from GeometricWatermark import GeometricWatermark
import pytest

from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError

SECRET = "TESTING-1"
KEY = "MYKEY1"

def test_secret(): 
    with pymupdf.open() as document: 
        document.new_page()
        original = document.tobytes()

    w = GeometricWatermark()
    watermarked = w.add_watermark(original,SECRET,KEY,)

    recovered = w.read_secret(watermarked,KEY)

    assert recovered == SECRET


def test_wrong_key(): 
    with pymupdf.open() as document: 
        document.new_page()
        originalDoc = document.tobytes()

        w = GeometricWatermark()
        watermarked = w.add_watermark(originalDoc,SECRET,KEY)

        with pytest.raises(InvalidKeyError):
            w.read_secret(watermarked, "wrong")


def test_missing_watermark(): 
    with pymupdf.open() as doc: 
        doc.new_page()
        originalDoc = doc.tobytes()

        w = GeometricWatermark()

        with pytest.raises(SecretNotFoundError):
            w.read_secret(originalDoc,KEY)


def test_deterministic_output(): 
    #same input should give same pdf bytes
    with pymupdf.open() as doc: 
        doc.new_page()
        originalDoc = doc.tobytes()

        w = GeometricWatermark()

        firstOutput = w.add_watermark(originalDoc, SECRET, KEY)
        secondOutput = w.add_watermark(originalDoc, SECRET, KEY)

        assert firstOutput == secondOutput

def test_repeat_position(): 
    with pymupdf.open() as doc: 
        doc.new_page()
        orginalDoc = doc.tobytes()

    w = GeometricWatermark()
    watermarked = w.add_watermark(orginalDoc, SECRET, KEY, "repeat")

    with pymupdf.open(stream=watermarked, filetype="pdf") as doc:
        page = doc[0]
        count = 0

        for drawing in page.get_drawings():
            bits = w.drawingRectangleToBits(drawing)
            payload = w.convertsBitsToByte(bits)
            recovered = w.readPayload(w.IDENTIFIER_WATERMARK,KEY,payload)

            assert recovered == SECRET
            count +=1
        assert count == 3
