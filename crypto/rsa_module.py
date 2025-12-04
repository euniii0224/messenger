# flask-messenger/crypto/rsa_module.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSACipher:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey().export_key()
        self.private_key = self.key.export_key()

    def get_public_key(self):
        return self.public_key
        
    def encrypt(self, message_str, recipient_public_key_bytes):
        try:
            recipient_key = RSA.import_key(recipient_public_key_bytes)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            encrypted = cipher_rsa.encrypt(message_str.encode('latin-1'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"RSA 암호화 오류: {e}")
            raise

    def decrypt(self, encrypted_message_b64):
        try:
            encrypted_bytes = base64.b64decode(encrypted_message_b64)
            private_key = RSA.import_key(self.private_key)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted = cipher_rsa.decrypt(encrypted_bytes)
            return decrypted.decode('latin-1')
        except Exception as e:
            print(f"RSA 복호화 오류: {e}")
            raise