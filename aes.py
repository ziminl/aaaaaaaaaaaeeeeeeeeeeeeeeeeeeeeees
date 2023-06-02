from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def aes_encrypt(plain_text, key):
    padder = padding.PKCS7(128).padder()
    padded_plain_text = padder.update(plain_text) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_plain_text) + encryptor.finalize()
    return cipher_text

def aes_decrypt(cipher_text, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain_text = unpadder.update(padded_plain_text) + unpadder.finalize()

    return plain_text
    
key = b'abcdefghijklmnop' #key should be one of 16,24,32byte
plain_text = b'This is a secret message.'

cipher_text = aes_encrypt(plain_text, key)
print("cipher text:", cipher_text)

decrypted_text = aes_decrypt(cipher_text, key)
print("decrypted text:", decrypted_text.decode())
