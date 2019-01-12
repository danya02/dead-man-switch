#!/usr/bin/python3
import requests
import rsa
import hashlib
import base64
ADDR='https://deadman.danya02.ru/auth/'
data = requests.get(ADDR+'challenge').content
print('<', data)
ip = data.split(b':')[0]
data = base64.b64decode(data.split(b':')[1])
my_key = rsa.PrivateKey.load_pkcs1(open('client-priv.pem','rb').read())
server_key = rsa.PublicKey.load_pkcs1(open('server-pub.pem', 'rb').read())
nonce = rsa.decrypt(data,my_key)
digest = hashlib.sha512(nonce)
enc = rsa.encrypt(digest.digest(), server_key)
xmit=ip+b':'+base64.b64encode(enc)
print('>',xmit)
a = requests.post(ADDR+'response', data=xmit)
print(a, a.content)

