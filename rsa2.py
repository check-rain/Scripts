from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import urllib.parse
import base64
from sys import argv

usage = "Usage: rsa.py [encrypt|decrypt]"

def encrypt(plain_text):
    new_key = RSA.generate(4096, e=65537)
    private_key = new_key.exportKey("PEM")
    with open("/Users/home/MCSI/privatekey.pem", 'w') as key_file:
        key_file.write(private_key.decode())
    public_key = new_key.publickey().exportKey("PEM")
    with open("/Users/home/MCSI/publickey.pem", 'w') as key_file:
        key_file.write(public_key.decode())
    public_key = RSA.importKey(public_key)
    rsa_object = PKCS1_v1_5.new(public_key)
    cipher_text = rsa_object.encrypt(plain_text.encode())
    cipher_text = base64.b64encode(cipher_text)
    cipher_text = cipher_text.decode()
    return cipher_text

def decrypt(cipher_text):
    cipher_text = base64.b64decode(cipher_text)
    with open("/Users/home/MCSI/privatekey.pem", 'r') as private_key:
        private_key = ''.join(private_key.readlines()).encode()
    private_key = RSA.importKey(private_key)
    rsa_object = PKCS1_v1_5.new(private_key)
    plain_text = rsa_object.decrypt(cipher_text, private_key)
    return plain_text

if __name__ == "__main__":
    if 'decrypt' in argv or 'encrypt' in argv:
        pass
    else:
        print(usage)
        exit()
    if argv[1] == "encrypt":
        plain_text = input("Enter the plain text to encrypt: ")
        cipher_text = encrypt(plain_text)
        print(f"\nCipher Text is: \n{cipher_text}")
    if argv[1] == "decrypt":
        cipher_text = input("Enter the cipher text to decrypt: ")
        plain_text = decrypt(cipher_text)
        print(f"\nPlain Text is: \n{plain_text.decode()}")
