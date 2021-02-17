from sys import argv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

usage = "Usage: crypt.py [encrypt|decrypt]"

keys = {
    'key_128' : get_random_bytes(16),
    'key_192' : get_random_bytes(24),
    'key_256' : get_random_bytes(32)
}

def encrypt(key):
    cipher = AES.new(key, AES.MODE_CBC)
    pt_in = input("Enter plaintext: ").encode()
    ct = cipher.encrypt(pad(pt_in, AES.block_size))
    iv = cipher.iv
    print(f'key = {key.hex()}')
    print(f'iv = {cipher.iv.hex()}')
    print(f'ct = {ct.hex()}')
    return ct, iv

def decrypt(ct, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_out = unpad(cipher.decrypt(ct), AES.block_size)
    print(f'The Decrypted message is: "{pt_out.decode()}"')
    return pt_out.decode()

if "decrypt" in argv or "encrypt" in argv:
    if argv[1] == "encrypt":
        key_length = input("Choose key length: ")
        try:
            key = keys[f'key_{key_length}']
        except KeyError:
            print("Please choose a 128, 192, or 256-bit encryption key.")
            exit()
        encrypt(key)
    elif argv[1] == "decrypt":
        ct = bytes.fromhex(input("Enter ciphertext as hex value: "))
        iv = bytes.fromhex(input("Enter IV as hex value: "))
        key = bytes.fromhex(input("Enter key as hex value: "))
        decrypt(ct, iv, key)
else:
    print(usage)
    exit()
