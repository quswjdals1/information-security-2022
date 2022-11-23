from Crypto import Random
from Crypto.PublicKey import RSA
import base64

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

secret = Random.get_random_bytes(32);

rsa =RSA.generate(2048);
pubkey = rsa.public_key().exportKey();
prikey = rsa.exportKey();

print(encode_base64(secret) + '\n')

print(encode_base64(pubkey) + '\n')
print(encode_base64(prikey) + '\n')
