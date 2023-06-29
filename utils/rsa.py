import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

global_keys_path = "keys"

if os.path.exists(global_keys_path) == False:
    # Create a directory to store the keys if it doesn't exist
    os.mkdir(global_keys_path)

def generate_rsa_key_pair(user: str) -> tuple[bytes, bytes]:
    global global_keys_path

    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Get the corresponding public key from the private key
    public_key = private_key.public_key()

    # Serialize the private key in PKCS#8 format without encryption
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    if os.path.exists(f'{global_keys_path}/{user}') == False:
        # Create a directory for the user's keys if it doesn't exist
        os.mkdir(f'{global_keys_path}/{user}')

    # Save the private key to a file
    with open(f'{global_keys_path}/{user}/private_key.pem', 'wb') as f:
        f.write(private_pem)

    # Serialize the public key in SubjectPublicKeyInfo (SPKI) format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the public key to a file
    with open(f'{global_keys_path}/{user}/public_key.pem', 'wb') as f:
        f.write(public_pem)

    return (private_pem, public_pem)

def read_rsa_key_pair(user: str) -> tuple[bytes, bytes]:
    global global_keys_path

    # Read the private key from the file
    with open(f"{global_keys_path}/{user}/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Read the public key from the file
    with open(f"{global_keys_path}/{user}/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Serialize the private key in PKCS#8 format without encryption
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key in SubjectPublicKeyInfo (SPKI) format
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return (private_key_bytes, public_key_bytes)

def encrypt(plain_data: bytes, public_key_bytes: bytes) -> bytes:
    # Load the public key from the provided bytes
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    # Encrypt the plain data using the public key with OAEP padding
    encrypted = base64.b64encode(public_key.encrypt(
        plain_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))

    return encrypted

def decrypt(encrypted_data: bytes, private_key_bytes: bytes) -> bytes:
    # Load the private key from the provided bytes
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

    # Decrypt the encrypted data using the private key with OAEP padding
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted
