from peewee import *
from flask import Flask, request, jsonify
import datetime
import gnupg
import functools
import uuid
import json
import time

app = Flask(__name__)
db = SqliteDatabase('dead-man.db')
gpg = gnupg.GPG(gnupghome='/home/danya')

MASTER_FINGERPRINT = 'DEADBEEF'

class MyModel(Model):
    class Meta:
        database = db

class CheckinKey(MyModel):
    pub_key = TextField()
    fingerprint = CharField()
    name = CharField()
    distrusted = BooleanField()
    trust_status_since = DateTimeField(default=datetime.datetime.now)

class Checkin(MyModel):
    uuid = UUIDField(default=uuid.uuid4)
    used_key = ForeignKeyField(CheckinKey, backref='checkins')
    date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    comment = TextField(null=True)
    can_be_evicted = BooleanField(default=True)

db.create_tables([CheckinKey, Checkin])

@app.route('/')
def hello_world():
    return 'Hello, World!'

def needs_valid_signature(or_master=False):
    def wrapper(fun):
        @functools.wraps(fun)
        def wrapped(*args, **kwargs):
            data = request.json()
            ip = request.remote_addr
            signature = data['signature']
            message = data['message']
            to_verify = '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n' +message+ '\n'+signature
            verification = gpg.verify(to_verify)
            if not verification:
                return jsonify({'status': 'forbidden', 'reason':'unregistered', 'text': 'Verification failed, first you need to register the PGP key'}), 403

            fingerprint = verification.fingerprint
            if or_master and fingerprint == MASTER_FINGERPRINT:
                key = None
            else:
                if fingerprint == MASTER_FINGERPRINT:
                    return jsonify({'status': 'forbidden', 'reason': 'master_not_allowed', 'text': 'You tried to use the master key in a context where it is not allowed.'})
                try:
                    key = CheckinKey.get(fingerprint=fingerprint)
                except CheckinKey.DoesNotExist:
                    return jsonify({'status': 'error', 'text': 'You used a key that is in GPG\'s database, but not in this service\'s. This should not have happened, you need to re-register this key.'}), 500
                if key.distrusted:
                    return jsonify({'status': 'forbidden', 'reason': 'distrusted', 'since':key.trust_status_since.isoformat(),
                        'text': 'The key you used was distrusted as of '+key.trust_status_since.isoformat()+' and so cannot be used for check-ins. Use a new key.'}), 403

            message = json.loads(message)
            if message.get('unix_minute') != int(time.time()) // 60:
                return jsonify({'status': 'forbidden', 'reason':'timestamp_wrong', 'timestamp': {'mine':int(time.time()) // 60, 'yours': message.get('unix_minute')},
                    'text': 'The timestamp provided with your message is incorrect; it should be the number of minutes elapsed since the Unix Epoch. It is currently '+str(int(time.time()) // 60)+' but you provided '+ repr(message.get('unix_minute'))}), 403

        kwargs.update({'key':key, 'message':message})
        return fun(*args, **kwargs)
    return wrapper

@app.route('/api/checkin', methods=['POST'])
@needs_valid_signature(False)
def check_in(key=None, message=None):
    new_checkin = Checkin.create(used_key=key, ip_address=request.remote_addr, comment=message.get('comment'), can_be_evicted=not message.get('prevent_eviction', False))
    return jsonify({'status':'ok', 'id':new_checkin.uuid, 'text':'Checkin successfully registered and assigned id '+new_checkin.uuid})

@app.route('/api/key/<fprint>', methods=['GET'])
def get_key(fprint):
    try:
        key = CheckinKey.get(fingerprint=fprint)
    except CheckinKey.DoesNotExist:
        return jsonify({'status':'not_found','text':'The requested key fingerprint ('+fprint+') not registered in the system.'}), 404
    return jsonify({'status':'ok', 'public_key':key.pub_key, 'fingerprint':key.fingerprint, 'name':key.name, 'distrusted':key.distrusted, 'trust_status_since': key.trust_status_since.isoformat()}), 200

@app.route('/api/key/<fprint>', methods=['DELETE'])
@needs_valid_signature(True)
def distrust_key(fprint, key=None, message=None):
    if key is None or key.fingerprint==fprint:
        key.distrusted = True
        key.trust_status_since = datetime.datetime.now()
        key.save()
        return jsonify({'status':'ok', 'text': 'This key is now distrusted.'}), 200
    else:
        return jsonify({'status':'forbidden', 'reason':'fprint_mismatch', 'text':'The message\'s key fingerprint does not match the fingerprint you requested and is not the master.'}), 200

