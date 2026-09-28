"""
Bruno watermarking method.
"""

import fitz #PyMuPDF, as recommended in watermarking_method.py
import hashlib
import hmac

from watermarking_method import(
    PdfSource,
    WatermarkingError,
    SecretNotFoundError,
    InvalidKeyError,
    load_pdf_bytes,
    WatermarkingMethod,
)

class ZwHMACWatermark(WatermarkingMethod):
    """
    A watermarking method that embeds a secret and an HMAC-SHA256 signature into a PDF document.

    Uses explicit start/end anchors (ZW_START/ZW_END) to isolate payload data and prevent collisions in the document.
    Maps binary data to ~ and ^.
    Uses render_mode=3 to make embedded text invisible for human reader.
    """
    name = "zw_hmac"

    def _generate_hmac(self, text:str, key:str) -> str:

        """
        Generates HMAC-SHA256 signature from text and key. Returns the signature as a hexadec string.
        """
        key_bytes = key.encode("utf-8")
        text_bytes = text.encode("utf-8")

        hmac_obj = hmac.new(key_bytes, text_bytes, hashlib.sha256)

        return hmac_obj.hexdigest()

    @staticmethod
    def get_usage() -> str:

        desc = "Embeds a hidden watermark using isolated text anchors and symbols (~ ^) at a fixed position." \
        "Uses HMAC-SHA256 with the provided key to ensure integrity and authenticity. " \
        "The exact same key must be provided during extraction."
        return desc

    def is_watermark_applicable(self, pdf:PdfSource, position:str | None=None) -> bool:
            
        """
        Verifies that the input is a valid PDF with at least 1 page.
        Normalizes the data and the tests if it can be opened using fitz
        """

        try:
            pdf_check = load_pdf_bytes(pdf) 
            document = fitz.open(stream=pdf_check, filetype="pdf") 
            if len (document)>=1:
                return True
            else:
                return False

        except Exception:
            return False

    def add_watermark(self, pdf:PdfSource, secret:str, key:str, position:str | None=None) -> bytes:

        """
        Embeds the secret into the first page of the PDF using zero-width characters and HMAC.
        Returns the modified PDF document as raw bytes.
        """

        pdf_bytes = load_pdf_bytes(pdf)

        document = fitz.open(stream=pdf_bytes, filetype="pdf")

        page = document[0]

        #Generates a cryptographic signature and combines payload
        signature = self._generate_hmac(text=secret, key=key)
        combined_text =f"{secret}|{signature}"

        #Convert text payload to a binary stream
        text_bytes = combined_text.encode("utf-8")

        #Wrap binary data with anchors using custom symbol mapping
        invis_text = "[ZW_START]"
        for byte in text_bytes:
            binary_string = f"{byte:08b}"

            for bit in binary_string:
                if bit == '0':
                    invis_text +="~"
                else:
                    invis_text += "^"
        invis_text += "[ZW_END]"

        #Inserts the watermark and makes it "invisible" with render_mode=3
        page.insert_text(fitz.Point(72,72), invis_text, fontsize=1, render_mode=3)

        new_pdf_bytes = document.tobytes()

        return new_pdf_bytes
        

    def read_secret(self, pdf:PdfSource, key:str) -> str:

        """
        Recovers and verifies the hiden secret from the PDF.

        Raises errors if:
        Anchor or watermark data is missing,
        byte decoding fails or data format is corrupt and
        HMAC verification fails due to wrong key or tamper.
        """
        pdf_bytes = load_pdf_bytes(pdf)
        document = fitz.open(stream=pdf_bytes, filetype="pdf")
        page = document[0]

        #Extracts page text and locates the anchors
        text_on_page = page.get_text()
        start_idx = text_on_page.find("[ZW_START]")
        end_idx = text_on_page.find("[ZW_END]")
        if start_idx == -1 or end_idx == -1:
            raise SecretNotFoundError("No watermark found")
        payload = text_on_page[start_idx + 10 : end_idx]

        binary_string = ""
        for char in payload:
            if char == "~":
                binary_string += "0"
            elif char == "^":
                binary_string += "1"
        if not binary_string:
            raise SecretNotFoundError("No watermark found")

        #Reconstructs bytes and decode to UTF-8 string
        byte_array = bytearray()
        for i in range(0, len(binary_string), 8):
            byte_chunk = binary_string[i:i+8]

            if len(byte_chunk) == 8:
                byte_array.append(int(byte_chunk, 2))

        try:
            extracted_text = byte_array.decode("utf-8")
        except Exception:
            raise WatermarkingError("Decoding not possible")

        parts = extracted_text.split("|")
        if len(parts) != 2:
            raise WatermarkingError("Data corrupt or wrong format")

        secret = parts[0]
        extracted_signature = parts[1]

        #Verify integrity using HMAC and the provided key
        calculated_signature = self._generate_hmac(text=secret, key=key)
        if calculated_signature != extracted_signature:
            raise InvalidKeyError("Wrong key or manipulated watermarking")

        return secret
