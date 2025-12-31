"""
zero_reveal_dpp/qr.py
QR code generation for passport root hash embedding.
"""
import json
from dataclasses import dataclass


@dataclass
class PassportQRData:
    """Data structure for QR code content."""
    merkle_root: str  # hex-encoded root hash
    signature: str  # hex-encoded signature
    issuer_did: str  # DID URL for key resolution
    passport_version: str
    schema_version: str = "1.0.0"


def generate_passport_qr(
    qr_data: PassportQRData,
    output_path: str,
    error_correction: str = 'M'
) -> None:
    """Generate QR code for passport verification.
    
    Args:
        qr_data: PassportQRData with root, signature, DID
        output_path: Path to save QR image (PNG)
        error_correction: L(7%), M(15%), Q(25%), H(30%)
            If generation fails at the requested level, the function
            falls back to L to maximize compatibility.
        
    Raises:
        ImportError: If qrcode library not installed
    """
    try:
        import qrcode
    except ImportError:
        raise ImportError("Install qrcode library: pip install qrcode[pil]")
    
    # Compact JSON for QR capacity
    payload = {
        "r": qr_data.merkle_root,
        "s": qr_data.signature,
        "i": qr_data.issuer_did,
        "v": qr_data.passport_version,
        "sv": qr_data.schema_version
    }
    
    data = json.dumps(payload, separators=(',', ':'))
    
    # Select error correction
    ec_map = {
        'L': qrcode.constants.ERROR_CORRECT_L,
        'M': qrcode.constants.ERROR_CORRECT_M,
        'Q': qrcode.constants.ERROR_CORRECT_Q,
        'H': qrcode.constants.ERROR_CORRECT_H,
    }

    error_correction = (error_correction or 'M').upper()

    def build_qr(ec_level: str):
        qr = qrcode.QRCode(
            version=None,  # Auto-detect
            error_correction=ec_map.get(ec_level, qrcode.constants.ERROR_CORRECT_M),
            box_size=10,
            border=4
        )
        qr.add_data(data)
        qr.make(fit=True)
        return qr

    try:
        qr = build_qr(error_correction)
    except Exception as exc:
        if error_correction != 'L':
            try:
                qr = build_qr('L')
            except Exception as exc2:
                raise exc2 from exc
        else:
            raise
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)


def parse_passport_qr(qr_content: str) -> PassportQRData:
    """Parse QR code content into structured data.
    
    Args:
        qr_content: Raw string from QR scanner
        
    Returns:
        PassportQRData object
    """
    payload = json.loads(qr_content)
    
    return PassportQRData(
        merkle_root=payload['r'],
        signature=payload['s'],
        issuer_did=payload['i'],
        passport_version=payload['v'],
        schema_version=payload.get('sv', '1.0.0')
    )
