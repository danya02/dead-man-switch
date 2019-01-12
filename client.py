#!/usr/bin/python3
import requests
import rsa
import hashlib
import base64
ADDR='http://deadman.danya02.ru/auth/challenge'
data = requests.get(ADDR).content
print('<', data)
ip = data.split(b':')[0]
data = base64.b64decode(data.split(b':')[1])
my_key = rsa.PrivateKey.load_pkcs1(open('client-priv.pem','rb').read())
server_key = rsa.PublicKey.load_pkcs1(open('server-pub.pem', 'rb').read())
nonce = rsa.decrypt(data,my_key)
digest = hashlib.sha3_512(nonce)
enc = rsa.encrypt(digest.digest(), server_key)
xmit=base64.b64encode(enc)
print('>',xmit)
a = requests.post(ADDR, data=xmit)
print(a, a.content)

