import requests
import gnupg
import json
import time
import socket
import uuid

gpg = gnupg.GPG()

MY_KEY = 'C7EB560F9B4744E9CC927040CC9FFFF135CA075C'
MASTER_KEY = '73F0F8B9A5468F6E02E088BC90DF11CC3211DA60'
HOST = 'http://127.0.0.1:5050'


def URL(endpoint):
    return HOST + endpoint


def compose_message(msg, use_master=False):
    msg.update({'unix_minute': int(time.time()) // 60})
    msg = json.dumps(msg)
    signature = gpg.sign(msg, keyid=MASTER_KEY if use_master else MY_KEY, detach=True)
    return json.dumps({'signature': signature.data if isinstance(signature.data, str) else str(signature.data, 'utf-8'),
                       'message': msg})


def check_in(comment=None, prevent_eviction=False):
    resp = requests.post(URL('/api/checkin'),
                         data=compose_message({'comment': comment, 'prevent_eviction': prevent_eviction}))
    print(resp, resp.text)


def add_my_key(name='Key for ' + socket.gethostname()):
    resp = requests.post(URL('/api/key'),
                         data=compose_message({'name': name, 'pubkey': str(gpg.export_keys(MY_KEY))}, use_master=True))
    print(resp, resp.text)


def distrust_my_key():
    resp = requests.delete(URL('/api/key/' + MY_KEY), data=compose_message({'random': str(uuid.uuid4())}))
    print(resp, resp.text)


def distrust_some_key(fprint):
    resp = requests.delete(URL('/api/key/' + fprint),
                           data=compose_message({'random': str(uuid.uuid4())}, use_master=True))
    print(resp, resp.text)


def lockdown(message, hard=False):
    resp = requests.delete(URL('/'),
                           data=compose_message({'random': str(uuid.uuid4()), 'text': message, 'hard': hard},
                                                use_master=True))
    print(resp, resp.text)


def run_eviction():
    resp = requests.get(URL('/api/checkin/evict'))
    print(resp, resp.text)

if __name__ == '__main__':
    add_my_key()
    check_in(comment=input('Comment: '), prevent_eviction=input('Do not evict? Y/N').lower() == 'y')
