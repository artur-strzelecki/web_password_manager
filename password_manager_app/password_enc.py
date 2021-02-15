import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from decouple import config


def encrypt_password(request, password):
    salt = str(request.user.id) + str(request.user.username) + config('KEY1_PASS')
    salt_bytes = str.encode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=1000000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(str.encode(config('KEY2_PASS'))))
    f = Fernet(key)
    pass_enc = f.encrypt(str.encode(password))
    return pass_enc


def decrypt_password(request, pass_enc):
    salt = str(request.user.id) + str(request.user.username) + config('KEY1_PASS')
    salt_bytes = str.encode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=1000000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(str.encode(config('KEY2_PASS'))))
    f = Fernet(key)

    typ = type(pass_enc)
    if isinstance(pass_enc, str):
        pass_bytes = str.encode(pass_enc)
    else:
        pass_bytes = pass_enc

    password = f.decrypt(pass_bytes)
    return password.decode()
