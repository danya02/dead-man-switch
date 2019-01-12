#!/usr/bin/python3
from flask import Flask, request
import time
import rsa
#import secrets
import json
import base64
import hashlib
import os
app = Flask(__name__)

PATH = '/var/dead-man-switch/deadman/'

@app.route('/')
def hello():
    return 'This is the challenge-response server.'

# Protocol:
# ---------
# 0. All network exchanges are Base64-coded.
# 1. Client asks for challenge
# 2. Server responds with the client's IP, a colon (":", ASCII 0x3A), and some unique string encoded with client's public key. The challenge is associated with the client's IP
# 3. Client decrypts message, takes a SHA3-512 hash of it, encrypts it using server's public key, sends it to server with the IP it heard from the server prepended with a colon.
# 4. If the IP transmitted is different from the one the server thinks the client has, it returns a 409 Conflict response, which it will not return in any other circumstance
# 5. Server decrypts message, compares it with the original challenge, and acts based on whether the response is correct


def get_challenge(ip):
    try:
        challenges = json.load(open('/tmp/deadman_challenges.json'))
    except:
        challenges = dict()
    if ip in challenges:
        ch = challenges.pop(ip)
        with open('/tmp/deadman_challenges.json','w') as o:
            json.dump(challenges, o)
        return base64.b64decode(bytes(challenges.pop(ip), 'utf-8'))
    else:
        data = os.urandom(512)
        challenges.update({ip:str(base64.b64encode(data), 'utf-8')})
        with open('/tmp/deadman_challenges.json','w') as o:
            json.dump(challenges, o)
        return data


@app.route('/challenge',methods = ['POST', 'GET'])
def challenge():
    peer_pub_key = rsa.PublicKey.load_pkcs1(open(PATH+'client-pub.pem', 'rb').read())
    my_sec_key = rsa.PrivateKey.load_pkcs1(open(PATH+'server-priv.pem','rb').read())
    ip = request.remote_addr
    if request.method=='GET':
        ch=get_challenge(ip)
        return bytes(ip, 'utf-8')+b':'+base64.b64encode(rsa.encrypt(ch,peer_pub_key))
    elif request.method=='POST':
        try:
            challenge = get_challenge(ip)
            ch = hashlib.sha3_512(challenge).digest()
            data = request.get_data()
            prove_ip = str(data.split(b':')[0], 'utf-8')
            if ip!=prove_ip:
                return 'IP mismatch: client thinks '+prove_ip+', but is actually from '+ip, 409
            resp = rsa.decrypt(base64.b64decode(data.split(b':')[1]), my_sec_key)
            if ch == resp:
                with open(PATH+'last-login-time.txt','w') as o:
                    o.write(str(time.time()))
                os.unlink(PATH+'latest-relative-time.txt')
                return 'Challenge passed!'
        except:
            print('Error while decrypting.')
        return 'Challenge failed!', 401

if __name__ == '__main__':
    app.run('127.0.0.1',5001)
