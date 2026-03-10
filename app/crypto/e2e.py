from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_public_key(pem_str: str):
    return serialization.load_pem_public_key(
        pem_str.encode(),
        backend=default_backend()
    )


def encrypt_message(public_key_pem: str, message: str) -> str:
    public_key = load_public_key(public_key_pem)
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext.hex()
