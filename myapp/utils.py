
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(serialized_key):
    return serialization.load_pem_private_key(
        serialized_key,
        password=None,
        backend=default_backend()
    )

private_key, public_key = generate_key_pair()
# # serialized_private_key = serialize_private_key(private_key)
# # retrieved_private_key = deserialize_private_key(serialized_private_key)
