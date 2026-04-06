from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64


# ===== GENERAR LLAVES RSA =====
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()


def export_private_key_pem(private_key):
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()


def export_public_key_pem(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def load_private_key_pem(pem):
    return serialization.load_pem_private_key(
        pem.encode(),
        password=None
    )

def load_rsa_private_key_pem(pem_text: str):
    return serialization.load_pem_private_key(
        pem_text.encode("utf-8"),
        password=None
    )

def load_public_key_pem(pem):
    return serialization.load_pem_public_key(
        pem.encode()
    )


# ===== FIRMAR =====
def sign_rsa(private_key, data: bytes):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


# ===== VERIFICAR =====
def verify_rsa(public_key, data: bytes, signature_b64: str):
    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False