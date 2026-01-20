"""
TOTP utilities for SecureTrack.
Gestion des secrets TOTP, codes de secours, etc.
"""
import pyotp
import qrcode
from io import BytesIO
import base64
import secrets
import string


def generate_totp_secret():
    """
    Générer un secret TOTP aléatoire.
    
    Returns:
        str: Secret base32 (32 caractères)
    """
    return pyotp.random_base32()


def get_totp_uri(secret, user_email, issuer="SecureTrack"):
    """
    Générer l'URI TOTP pour créer un QR code.
    
    Args:
        secret: Secret TOTP base32
        user_email: Email de l'utilisateur
        issuer: Nom de l'app
    
    Returns:
        str: URI TOTP (otpauth://...)
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=user_email,
        issuer_name=issuer
    )


def generate_qr_code(totp_uri):
    """
    Générer un QR code en base64.
    
    Args:
        totp_uri: URI TOTP
    
    Returns:
        str: QR code en base64 (PNG)
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    # Générer image PNG
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convertir en base64
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{qr_base64}"


def verify_totp(secret, token):
    """
    Vérifier un code TOTP.
    
    Args:
        secret: Secret TOTP base32
        token: Code TOTP (6 chiffres)
    
    Returns:
        bool: True si valide, False sinon
    """
    totp = pyotp.TOTP(secret)
    # Vérifier le token avec fenêtre de temps (±30 secondes)
    return totp.verify(token, valid_window=1)


def generate_backup_codes(count=10):
    """
    Générer des codes de secours.
    
    Format : XXXX-XXXX-XXXX (12 caractères alphanumériques)
    
    Args:
        count: Nombre de codes à générer (défaut 10)
    
    Returns:
        list: Liste de codes de secours
    """
    codes = []
    for _ in range(count):
        # Générer 12 caractères aléatoires (uppercase + digits)
        code_part1 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        code_part2 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        code_part3 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        code = f"{code_part1}-{code_part2}-{code_part3}"
        codes.append(code)
    
    return codes


def verify_backup_code(codes_str, code):
    """
    Vérifier si un backup code est valide et le marquer comme utilisé.
    
    Args:
        codes_str: String de codes séparés par | (ex: "ABC1-ABC2|DEF1-DEF2")
        code: Code à vérifier
    
    Returns:
        tuple: (is_valid: bool, remaining_codes: str, code_count: int)
    """
    if not codes_str:
        return False, codes_str, 0
    
    codes_list = codes_str.split('|')
    code_upper = code.upper().strip()
    
    if code_upper in codes_list:
        # Code trouvé, le supprimer
        codes_list.remove(code_upper)
        remaining = '|'.join(codes_list)
        return True, remaining, len(codes_list)
    
    return False, codes_str, len(codes_list)
