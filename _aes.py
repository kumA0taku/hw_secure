from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def gen_aes_key():
    return get_random_bytes(16)

data = b'Warinthorn'
key = gen_aes_key()
print("Generated AES Key:", key.hex())

cipher = AES.new(key, AES.MODE_CFB)
cipher_text = cipher.encrypt(data)
iv = cipher.iv
print("Encrypted text:", cipher_text.hex())

decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
plain_text = decrypt_cipher.decrypt(cipher_text)
print("Decrypted text:", plain_text)