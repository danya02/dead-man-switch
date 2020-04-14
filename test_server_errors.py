import client
import time
import requests
import json
import os
import subprocess
import pytest

gpg = client.gpg

client.HOST = 'http://127.0.0.1:5000'


# def compose_message(msg, use_master):
#    msg.update({'unix_minute': int(time.time())//60})
#    msg = json.dumps(msg)
#    signature = gpg.sign(msg, keyid=client.MASTER_KEY if use_master else MY_KEY, detach=True)
#    return json.dumps({'signature': signature.data if isinstance(signature.data, str) else str(signature.data, 'utf-8'), 'message': msg if isinstance(msg, str) else str(msg, 'utf-8')})

@pytest.fixture
def server():
    try:
        os.unlink('dead-man.db')
    except FileNotFoundError:
        pass
    proc = subprocess.Popen(['python3', 'server.py', 'test'])
    time.sleep(0.5)  # wait for server to init
    yield None
    proc.terminate()
    os.unlink('dead-man.db')


def test_add_key(server):
    msg = {'pubkey': gpg.export_keys(client.MY_KEY), 'name': 'test key', 'unix_minute': int(time.time()) // 60}
    msg = json.dumps(msg)
    signature = gpg.sign(msg, keyid=client.MASTER_KEY, detach=True)
    to_send = json.dumps(
        {'signature': signature.data if isinstance(signature.data, str) else str(signature.data, 'utf-8'),
         'message': msg})
    resp = requests.post(client.URL('/api/key'), data=to_send)
    assert resp.status_code == 201
    j = resp.json()
    assert j['fingerprint'] == client.MY_KEY


def test_message_out_of_date(server):
    test_add_key(server)
    msg = {'comment': 'Testing out-of-date token', 'prevent_eviction': True}
    msg.update({'unix_minute': int(time.time() - 1800) // 60})
    msg = json.dumps(msg)
    signature = gpg.sign(msg, keyid=client.MY_KEY, detach=True)
    to_send = json.dumps(
        {'signature': signature.data if isinstance(signature.data, str) else str(signature.data, 'utf-8'),
         'message': msg})
    resp = requests.post(client.URL('/api/checkin'), data=to_send)
    assert resp.status_code == 403
    j = resp.json()
    assert j['status'] == 'forbidden'
    assert j['reason'] == 'timestamp_wrong'


def test_outer_not_json(server):
    resp = requests.post(client.URL('/api/checkin'), data='I can\'t believe it\'s not JSON!')
    assert resp.status_code == 400
    j = resp.json()
    assert j['status'] == 'data_error'
    assert j['reason'] == 'bad_outer_json'


def test_outer_is_empty_json(server):
    resp = requests.post(client.URL('/api/checkin'), data='{}')
    assert resp.status_code == 400
    j = resp.json()
    assert j['status'] == 'data_error'
    assert j['reason'] == 'no_outer_field'
