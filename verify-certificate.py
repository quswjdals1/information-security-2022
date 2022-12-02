from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64, json

def decode_base64(b64):
    return base64.b64decode(b64)

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

def make_cert_hash(name, pubKeyBase64):
	message = name + pubKeyBase64
	return SHA256.new(message.encode('utf-8'))

def read_as_json():
	json_str = decode_base64(input()).decode('utf-8')
	json_obj = json.loads(json_str)
	return json_obj

# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
def verify(hash, key, signature):
	key = RSA.import_key(key)
	try:
		pkcs1_15.new(key).verify(hash, signature)
		return True
	except (ValueError, TypeError):
		return False

cert = read_as_json()

hash_compare = make_cert_hash(cert['name'], cert['pubKey'])
server_pubkey = decode_base64(cert['serverPubKey'])
signature = decode_base64(cert['signature'])

cert['isValid'] =  verify(hash_compare, server_pubkey, signature)

json_str = json.dumps(cert).encode('utf-8')

print(encode_base64(json_str))