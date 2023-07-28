""" 
install 'pycryptodome' library to use DSE by the command below
`pip install pycryptodome`
"""
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def generate_des_key():
    return get_random_bytes(8)

def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), 8)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode().rstrip('\x00')

def main():
    key = generate_des_key()
    print("Generated DES Key:", key.hex())
    
    while True:
        plaintext = input("Enter the plaintext to encrypt: ")
        ciphertext = des_encrypt(key, plaintext)
        print("Encrypted ciphertext:", ciphertext.hex())

        decrypted_text = des_decrypt(key, ciphertext)
        print("Decrypted text:", decrypted_text)


if __name__ == "__main__":
    main()
