from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes
from sys import argv

usage = "Usage: RC4.py [encrypt|decrypt]"

def encrypt(plain_text):
    key = b'The Key of Keys'
    nonce = get_random_bytes(16)
    key = SHA.new(key+nonce).digest()
    cipher = ARC4.new(key)
    msg = cipher.encrypt(plain_text)
    return msg.hex(), key.hex()

def decrypt(cipher_text, key):
    cipher = ARC4.new(key)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text.decode()

if __name__ == "__main__":
    if 'decrypt' in argv or 'encrypt' in argv:
        pass
    else:
        print(usage)
        exit()
    if argv[1] == "encrypt":
        plain_text = input("Enter PT: ")
        plain_text = plain_text.encode()
        ct = encrypt(plain_text)
        print(f"The Cipher Text is: {ct[0]}\nThe Key used is: {ct[1]}")
    elif argv[1] == "decrypt":
        cipher_text = input("Enter the Cipher Text: ")
        cipher_text = bytes.fromhex(cipher_text)
        key = input("Enter the Key: ")
        key = bytes.fromhex(key)
        pt = decrypt(cipher_text, key)
        print(f"The decrypted text is: {pt}")
    else:
        print(usage)
        exit()
