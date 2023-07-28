from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

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
    unpadded_data = unpad(decrypted_data, 8)
    return unpadded_data.decode()

def main():
    print("Welcome to the DES Encryption/Decryption program!")
    key = generate_des_key()
    print("Generated DES Key:", key.hex())

    while True:
        choice = input("Enter 'e' for encryption, 'd' for decryption, or 'q' to quit: ")
        if choice == 'e':
            plaintext = input("Enter the plaintext to encrypt: ")
            ciphertext = des_encrypt(key, plaintext)
            print("Encrypted ciphertext:", ciphertext.hex())
        elif choice == 'd':
            ciphertext = bytes.fromhex(input("Enter the ciphertext to decrypt (in hexadecimal format): "))
            decrypted_text = des_decrypt(key, ciphertext)
            print("Decrypted text:", decrypted_text)
        elif choice == 'q':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
