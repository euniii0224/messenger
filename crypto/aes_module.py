# flask-messenger/crypto/aes_module.py
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

class AESCipher:
    def __init__(self, key_bytes=None):
        self.key = key_bytes if key_bytes is not None else os.urandom(32)
        self.backend = default_backend()
        self.IV_LEN = 12
        self.TAG_LEN = 16

    def get_key_bytes(self):
        return self.key

    def encrypt(self, plaintext, associated_data=b''):
        plaintext_bytes = plaintext.encode('utf-8')
        iv = os.urandom(self.IV_LEN) 

        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=self.backend
        ).encryptor()

        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        data_to_send = iv + encryptor.tag + ciphertext
        return base64.b64encode(data_to_send).decode('utf-8')

    def decrypt(self, enc_data, associated_data=b''):
        try:
            enc_bytes = base64.b64decode(enc_data)
        except:
            raise ValueError("Invalid Base64 format")

        if len(enc_bytes) < self.IV_LEN + self.TAG_LEN:
             raise ValueError("Encrypted data is too short or malformed")
        
        iv = enc_bytes[:self.IV_LEN]
        tag = enc_bytes[self.IV_LEN:self.IV_LEN + self.TAG_LEN]
        ciphertext = enc_bytes[self.IV_LEN + self.TAG_LEN:]
        
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=self.backend
        ).decryptor()

        decryptor.authenticate_additional_data(associated_data)

        try:
            plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext_bytes.decode('utf-8')
        except InvalidTag:
            raise InvalidTag("Authentication tag verification failed: Data tampered.")
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")