import hashlib
import os
import json

AUTH_FILE = 'auth.json'

def set_master_password(password: str):
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    data = {
        'salt': salt.hex(),
        'pwdhash': pwdhash.hex()
    }
    with open(AUTH_FILE, 'w') as f:
        json.dump(data, f)

def verify_master_password(password: str) -> bool:
    try:
        with open(AUTH_FILE, 'r') as f:
            data = json.load(f)
        salt = bytes.fromhex(data['salt'])
        stored_hash = data['pwdhash']
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
        return pwdhash == stored_hash
    except FileNotFoundError:
        return False

def master_password_exists() -> bool:
    return os.path.exists(AUTH_FILE)
