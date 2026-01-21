import pyotp
import qrcode
from io import BytesIO
import base64
import secrets
import string


def generate_totp_secret():
    """Générer un secret TOTP base32"""
    return pyotp.random_base32()


def get_totp_uri(secret, email):
    """Obtenir l'URI TOTP pour QR code"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=email,
        issuer_name='SecureTrack'
    )


def generate_qr_code(totp_uri):
    """Générer un QR code en base64"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{qr_code_base64}"


def verify_totp(secret, code):
    """Vérifier un code TOTP"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    except:
        return False


def generate_backup_codes(count=10):
    """Générer des codes de secours format: ABC1-ABC2-ABC3"""
    codes = []
    for _ in range(count):
        code = '-'.join([
            ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            for _ in range(3)
        ])
        codes.append(code)
    return codes


def verify_backup_code(code, stored_codes):
    """Vérifier si un code est dans les codes de secours"""
    return code in stored_codes