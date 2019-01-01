#!/usr/bin/python3
from flask import Flask, request
import time
import rsa
import secrets
import base64
import hashlib
import os
app = Flask(__name__)

@app.route('/')
def hello():
    return 'This is the challenge-response server.'

# Protocol:
# ---------
# 0. All network exchanges are Base64-coded.
# 1. Client asks for challenge
# 2. Server responds with some unique string encoded with client's public key. The challenge is associated with the client's IP
# 3. Client decrypts message, takes a SHA3-512 hash of it, encrypts it using server's public key
# 4. Server decrypts message, compares it with the original challenge, and acts based on whether the response is correct

challenges = {}

def get_challenge(ip):
    if ip in challenges:
        return challenges.pop(ip)
    else:
        data = secrets.token_bytes(512)
        challenges.update({ip:data})
        return data


@app.route('/challenge',methods = ['POST', 'GET'])
def challenge():
    peer_pub_key = rsa.PublicKey.load_pkcs1(open('client-pub.pem', 'rb').read())
    my_sec_key = rsa.PrivateKey.load_pkcs1(open('server-priv.pem','rb').read())
    ip = request.remote_addr
    if request.method=='GET':
        ch=get_challenge(ip)
        return base64.b64encode(rsa.encrypt(ch,peer_pub_key))
    elif request.method=='POST':
        try:
            ch = hashlib.sha3_512(get_challenge(ip)).digest()
            resp = rsa.decrypt(base64.b64decode(request.get_data()), my_sec_key)
            if secrets.compare_digest(ch, resp):
                with open('last-login-time.txt','w') as o:
                    o.write(str(time.time()))
                os.unlink('latest-relative-time.txt')
                return 'Challenge passed!'
        except:
            print('Error while decrypting.')
        return 'Challenge failed!', 403

if __name__ == '__main__':
    app.run('127.0.0.1',5001)
