import os
from typing import Final

import hashlib
import hmac

import pymupdf 


from watermarking_method import (
    WatermarkingMethod, 
    WatermarkingError, 
    SecretNotFoundError,
    PdfSource,
    InvalidKeyError,
    load_pdf_bytes
) 


"""

 Geometric Watermark puts the secret and HMAC-SHA256 authentication code 
 as invisible vector rectangles in the PDF.
 Using HMAC-SHA256 ensures integrity and authentication of the payload. The secret is encoded, not encrypted. 
 The watermark can be placed at the top or bottom of each page, 
 or repeated three times per page to provide redundancy.
 
 by ankw6718
"""
class GeometricWatermark(WatermarkingMethod): 
    name: Final[str] = "geometric-watermark"

    GRID_MAX_COLUMNS: Final[int] = 50
    GRID_SPACING: Final[int] = 3
    RECTANGLE_HEIGHT: Final[float] = 0.8
    RECTANLGE_NARROW_WIDTH: Final[float] = 0.8
    RECTANGLE_WIDE_WIDTH: Final[float] = 1.6
    LAYER_NAME: Final[str] = "ankw"
    IDENTIFIER_WATERMARK: Final[bytes] = b"ankw2026"

    def isBlank(self, someString : str) -> bool:
         """
            This allows to check if string is None, or empty or blank. 
            So if it is blank it will return True, otherwise False. 
         """ 
         return not bool(someString and someString.strip())

    def convertStrToBytes(self, secret:str) -> bytes:
         """
            This function allows to convert the secret of type str into bytes. 
            It also verifies that it is a STRING and it is not blank. 
            So there must be some characters. It rejects whitespace only secrets.

            Returns 
            --------
            bytes 
                secret message
         """

         if not isinstance(secret, str):
              raise ValueError("Secret must be a string")

         if self.isBlank(secret): 
              raise ValueError("Secret must not be empty.") 

         return secret.encode("utf-8")


    def convertByteToBits(self, secretByte: bytes) -> str: 
         bits =""
         for byte in secretByte:
              bits+=f"{byte:08b}"

         return bits


    def convertsBitsToStr(self, secretBits:str) -> str:
         if len(secretBits) % 8 != 0: 
              raise ValueError("The bit sequence must contain complete bytes")

         
         
         for bit in secretBits: 
              if bit not in "01": 
                   raise ValueError("The bit sequence must contain only 0 and 1")

         messageBytes  = bytearray()
         for x in range(0, len(secretBits), 8): 
              getInt = int(secretBits[x:x+8], 2)
              messageBytes.append(getInt)

         return messageBytes.decode("utf-8")
    
    def convertsBitsToByte(self, bits:str) -> bytes:
         if len(bits) % 8 != 0: 
              raise ValueError("The bit sequence must contain complete bytes")

         
         
         for bit in bits: 
              if bit not in "01": 
                   raise ValueError("The bit sequence must contain only 0 and 1")

         messageBytes  = bytearray()
         for x in range(0, len(bits), 8): 
              getInt = int(bits[x:x+8], 2)
              messageBytes.append(getInt)

         return bytes(messageBytes)

    

    def computeHMACSHA256(self, key:str, secret:bytes) -> bytes: 
         """
            This method allows to create the HMAC using the key + secret message. 
            It returns a 32 byte hash

         """
         if not isinstance(key, str): 
              raise ValueError("Key must be a string")
         if self.isBlank(key):
              raise ValueError("Key must not be blank")

         keyBytes = key.encode('utf-8')

         return hmac.new(keyBytes,secret,hashlib.sha256).digest()


    def buildPayload(self, key:str, secret:str) -> bytes:
         """
            Creates the HMAC digest. 

         """
         secretBytes = self.convertStrToBytes(secret)

         if len(secretBytes) > 65535: 
              raise ValueError("Secret exceeds the two byte length capacity. It should be less.")

         
         lengthBytes = len(secretBytes).to_bytes(2, byteorder="big")

         message = self.IDENTIFIER_WATERMARK + lengthBytes + secretBytes
         hmacCompute = self.computeHMACSHA256(key, message)

         return message + hmacCompute

    def verifyHMAC(self, key:str, embeddedHMAC:bytes, messageToVerify:bytes) -> bool:
         calculatedHMAC = self.computeHMACSHA256(key,messageToVerify)
         return hmac.compare_digest(embeddedHMAC,calculatedHMAC)




    def readPayload(self, identifier:bytes, key:str, payload:bytes) -> str:
         headerLen = len(identifier) + 2 
         hmacLen = hashlib.sha256().digest_size 

         if len(payload) < headerLen + hmacLen: 
              raise SecretNotFoundError("Watermark payload is incomplete")
         elif not payload.startswith(identifier): 
              raise SecretNotFoundError("Watermark identifier not found")
         
         secretLen = int.from_bytes(payload[len(identifier):headerLen], byteorder="big")

         secretEndPos = headerLen + secretLen


         extractSecret = payload[headerLen:secretEndPos]
         extractHMAC=payload[secretEndPos:]
         messageToVerify = payload[:secretEndPos]

         if not self.verifyHMAC(key, extractHMAC, messageToVerify):
              raise InvalidKeyError("Incorrect Key or modified watermark")

         try: 
              return extractSecret.decode("utf-8")
         except UnicodeDecodeError as exc: 
              raise WatermarkingError("Secret is not valid UTF-8") from exc



    def drawingBitToRectangle(self, page:pymupdf.Page,bits:str,startX:float,startY:float, layerId:int)->None:

         drawing = page.new_shape() 
        
         for i, bit in enumerate(bits): 
              row = i // self.GRID_MAX_COLUMNS
              column = i % self.GRID_MAX_COLUMNS 

              x = startX + column * self.GRID_SPACING
              y = startY + row * self.GRID_SPACING

              if bit == "0": 
                   width = self.RECTANLGE_NARROW_WIDTH
              else : 
                   width= self.RECTANGLE_WIDE_WIDTH


              rectangle = pymupdf.Rect(x,y,x+width,y+self.RECTANGLE_HEIGHT)
              drawing.draw_rect(rectangle)

         drawing.finish(color=None,fill=(0.65,0.65,0.65),fill_opacity=0.0, closePath=False, oc=layerId)
         drawing.commit(overlay=False)

              
         

    def calculcateGridDimension(self, bitsLen:int, gridType:str) -> float:
         
         rows = (bitsLen + self.GRID_MAX_COLUMNS -1) // self.GRID_MAX_COLUMNS

         if gridType == "height": 
              return (rows - 1) * self.GRID_SPACING + self.RECTANGLE_HEIGHT
         elif gridType == "width": 
              return (self.GRID_MAX_COLUMNS-1) * self.GRID_SPACING + self.RECTANGLE_WIDE_WIDTH
         else: 
              raise ValueError("There's an error, it is either height or width to calculate.")

    def drawingRectangleToBits(self, drawing:dict) -> str:
         bits = ""

         for item in drawing["items"]:
              if item[0] =="re": 
                   rectangle = item[1]
                   width = round(rectangle.width, 2)
                   height = round(rectangle.height,2)

                   if height == self.RECTANGLE_HEIGHT:
                        if width == self.RECTANLGE_NARROW_WIDTH:
                             bits+="0"
                        elif width == self.RECTANGLE_WIDE_WIDTH: 
                             bits+="1"
                        else: 
                             return ""
         return bits


         
    @staticmethod
    def get_usage() -> str:
        return (
            "Geometric watermark: a small grid of rectangles that encodes the secret. "
            "The key generates and verifies an HMAC ensuring integrity. "
            "Position: 'repeat' (default), 'top', or 'bottom'. "
        )

    def add_watermark(self, pdf: PdfSource, secret:str, key:str, position :str | None = None) -> bytes:
         """Return a new PDF with an embedded watermark."""

         pdfBytes = load_pdf_bytes(pdf)
         payload = self.buildPayload(key,secret)
         bits = self.convertByteToBits(payload) #this is to obtain the number of rectangles 0:narrow 1:wide

         if position is not None and not isinstance(position, str):
              raise ValueError("Position must be either 'repeat', or 'top', or 'bottom'")

         if self.isBlank(position): 
              #we set the default value repeat: top, middle, bottom
              position="repeat"
         elif position.lower() not in ("repeat", "top","bottom"):
              raise ValueError("Position must be either 'repeat', 'top', or 'bottom'")

         with pymupdf.open(stream=pdfBytes, filetype="pdf") as pdfDoc: 
              if pdfDoc.needs_pass:
                   raise WatermarkingError("Password protect PDF is not supported")

              if pdfDoc.page_count == 0: 
                   raise WatermarkingError("PDF doesn't contain pages")

              layerId = pdfDoc.add_ocg(self.LAYER_NAME)

              for page in pdfDoc:

                   startXpos = 30 
                   margin = 30 
                   pageHeight = page.cropbox.height
                   pageWidth = page.cropbox.width
                   topStartYPos = startXpos 
                   gridHeight = self.calculcateGridDimension(len(bits), "height")
                   gridWidth = self.calculcateGridDimension(len(bits), "width")
                   bottomStartYPos = pageHeight - margin - gridHeight

                   if(startXpos + gridWidth + margin > pageWidth or topStartYPos + gridHeight + margin > pageHeight):
                        raise WatermarkingError("The watermark doesn't fit on this page")
                        

                   if position.lower() == "top": 
                        self.drawingBitToRectangle(page, bits,startXpos, topStartYPos, layerId)
                   elif position.lower() == "bottom": 
                        self.drawingBitToRectangle(page,bits,startXpos, bottomStartYPos, layerId)
                   elif position.lower() == "repeat":
                        i = 0
                        stepY = (bottomStartYPos - topStartYPos) / 2

                        if stepY<gridHeight: 
                             raise WatermarkingError("Repeated watermark grids would overlap.")
                        
                        while i< 3:
                             startYPosRepetion = topStartYPos + i * stepY
                             self.drawingBitToRectangle(page,bits,startXpos,startYPosRepetion, layerId) 
                             i+=1
                   else: 
                        raise ValueError("error")
              return pdfDoc.tobytes(deflate=True, no_new_id=True)

                            



    def is_watermark_applicable(self, pdf:PdfSource, position: str | None = None) -> bool:
         """Return whether the method is applicable on this specific method"""
         if position is not None and not isinstance(position, str):
              return False

         if self.isBlank(position):
              position = "repeat"

         if position.lower() not in ("repeat", "top", "bottom"):
              return False

         try: 
              pdfBytes = load_pdf_bytes(pdf)

              with pymupdf.open(stream=pdfBytes, filetype="pdf") as pdfDoc: 
                   if pdfDoc.needs_pass or pdfDoc.page_count == 0: 
                        return False
              return True
         except Exception:
              return False 
              

         

    def read_secret(self, pdf: PdfSource, key:str) -> str:
         """Extract and return the embedded secret from ``pdf``."""

         if not isinstance(key,str) or self.isBlank(key):
              raise ValueError("Key can't be something empty")

         pdfByte = load_pdf_bytes(pdf)
         authenticationFailed = False
         with pymupdf.open(stream=pdfByte, filetype="pdf") as pdfDoc: 
              if pdfDoc.needs_pass: 
                   raise WatermarkingError("Password protected not supported")

              for page in pdfDoc: 
                   for drawing in page.get_drawings(): 
                         bits = self.drawingRectangleToBits(drawing)                       
                         try:
                              payload = self.convertsBitsToByte(bits) 
                              return self.readPayload(self.IDENTIFIER_WATERMARK,key,payload)
                         except InvalidKeyError:
                              authenticationFailed = True
                         except ValueError :
                              continue
                         except WatermarkingError:
                              continue                             
              if authenticationFailed:
                   raise InvalidKeyError("Incorrect key") 
              raise SecretNotFoundError("No valid geometric watermark found")
                   
                                 
                             




__all__ = ["GeometricWatermark"]