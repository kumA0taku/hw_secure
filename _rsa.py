""" 
install 'pycryptodome' library to use DSE by the command below
`pip install pycryptodome`
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_key_pair():
    key = RSA.generate(2048)  # 2048-bit key size is a common choice for RSA
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode()

def main():
    print("Welcome to the RSA Encryption/Decryption program!")
    private_key, public_key = generate_rsa_key_pair()
    print("Generated RSA Private Key:", private_key.decode())
    print("Generated RSA Public Key:", public_key.decode())

    plaintext = input("Enter the plaintext to encrypt: ")
    ciphertext = rsa_encrypt(public_key, plaintext)
    print("Encrypted ciphertext: ", ciphertext.hex())

    decrypted_text = rsa_decrypt(private_key, ciphertext)
    print("Decrypted text: ", decrypted_text)

if __name__ == "__main__":
    main()
