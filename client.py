#!/usr/bin/python3
import requests
import rsa
import hashlib
import base64
ADDR='http://127.0.0.1:5000/challenge'
data = base64.b64decode(requests.get(ADDR).content)
my_key = rsa.PrivateKey.load_pkcs1(open('client-priv.pem','rb').read())
server_key = rsa.PublicKey.load_pkcs1(open('server-pub.pem', 'rb').read())
nonce = rsa.decrypt(data,my_key)
digest = hashlib.sha3_512(nonce)
enc = rsa.encrypt(digest.digest(), server_key)
requests.post(ADDR, data=base64.b64encode(enc)).raise_for_status()
