import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

__key__ = hashlib.sha256(b'16-character key').digest()


def generate_des_key():
    return get_random_bytes(8)

def encrypt(raw):
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key= __key__, mode= AES.MODE_CFB,iv= iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def decrypt(enc):
    unpad = lambda s: s[:-ord(s[-1:])]

    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(__key__, AES.MODE_CFB, iv)
    return unpad(base64.b64decode(cipher.decrypt(enc[AES.block_size:])).decode('utf8'))

def main():
    key = generate_des_key()
    print("Generated AES Key:", key.hex())
    
    while True:
        plaintext = input("Enter the plaintext to encrypt: ")
        ciphertext = encrypt(key, plaintext)
        print("Encrypted ciphertext:", ciphertext.hex())

        decrypted_text = decrypt(key, ciphertext)
        print("Decrypted text:", decrypted_text)


if __name__ == "__main__":
    main()