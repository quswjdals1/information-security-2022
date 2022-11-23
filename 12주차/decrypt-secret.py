from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def decode_base64(b64):
    return base64.b64decode(b64)

def read_from_base64():
    return [ decode_base64(input()), decode_base64(input()) ]

def decrypt_secret(secret, priKey):
    key = RSA.importKey(priKey)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(secret)

[secret, prikey] = read_from_base64()
result = decrypt_secret(secret, prikey).decode('ascii')

print(result)