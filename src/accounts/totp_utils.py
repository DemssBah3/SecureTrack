import pyotp
import qrcode
from io import BytesIO
import base64

def generate_secret():
    """Generate TOTP secret"""
    return pyotp.random_base32()

def generate_qr_code(email, secret):
    """Generate QR code for TOTP"""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name='SecureTrack')
    
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make()
    
    img = qr.make_image()
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return base64.b64encode(buf.getvalue()).decode()

def verify_totp(secret, code):
    """Verify TOTP code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_backup_codes(count=10):
    """Generate backup codes"""
    import secrets
    return [secrets.token_hex(4) for _ in range(count)]
