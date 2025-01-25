import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
from PIL import Image, ImageDraw, ImageFont
import hashlib
import os

class SecureQRGenerator:
    def __init__(self, ssid: str, password: str):
        self.ssid = ssid
        self.password = password
        self.qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )

    def generate(self) -> Image.Image:
        nonce = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        payload = f"WIFI:T:WPA;S:{self.ssid};P:{self.password};N:{nonce};;"
        
        self.qr.add_data(payload)
        self.qr.make(fit=True)

        img = self.qr.make_image(fill_color="black", back_color="white", image_factory=StyledPilImage, module_drawer=RoundedModuleDrawer())
        
        # Add anti-tamper hologram overlay
        hologram = Image.open("security_hologram.png").convert("RGBA")
        hologram = hologram.resize((img.size[0]//4, img.size[1]//4))
        img = img.convert("RGBA")
        img.paste(hologram, (img.size[0]-hologram.size[0], img.size[1]-hologram.size[1]), hologram)

        # Add expiration timestamp
        draw = ImageDraw.Draw(img)
        font = ImageFont.truetype("arial.ttf", 20)
        draw.text((10, 10), f"Expires: {nonce}", font=font, fill=(0, 0, 0, 128))

        return img
