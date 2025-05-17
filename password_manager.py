import storage
import encryption

class PasswordManager:
    def __init__(self, master_password: str, salt: bytes):
        self.key = encryption.derive_key(master_password.encode(), salt)

    def add_password(self, service: str, plaintext_password: str):
        encrypted = encryption.encrypt(plaintext_password, self.key)
        storage.add_password(service, encrypted)

    def get_password(self, service: str):
        encrypted = storage.get_password(service)
        if encrypted:
            return encryption.decrypt(encrypted, self.key)
        return None

    def delete_password(self, service: str):
        storage.delete_password(service)

    def list_services(self):
        return storage.get_all_services()
