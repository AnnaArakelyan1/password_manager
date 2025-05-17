from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

SALT = b'some_salt_here' 
ITERATIONS = 100_000
KEY_LEN = 32 

def derive_key(master_password: str) -> bytes:
    return PBKDF2(master_password, SALT, dkLen=KEY_LEN, count=ITERATIONS)

def encrypt(plaintext: str, key: bytes) -> str:
    data = plaintext.encode('utf-8')
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    raw = base64.b64decode(ciphertext_b64)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')
