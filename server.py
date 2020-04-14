from peewee import *
from flask import Flask, request, jsonify, redirect, url_for, Response
import datetime
import gnupg
import functools
import uuid
import json
import time

app = Flask(__name__)
db = SqliteDatabase('dead-man.db')
gpg = gnupg.GPG(gnupghome='/home/danya/.gnupg', verbose=True, use_agent=True)

MASTER_FINGERPRINT = '73F0F8B9A5468F6E02E088BC90DF11CC3211DA60'


class MyModel(Model):
    class Meta:
        database = db


class CheckinKey(MyModel):
    pub_key = TextField()
    fingerprint = CharField(unique=True)
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


class Lockdown(MyModel):
    message = TextField()
    hard_lock = BooleanField()


db.connect()
db.create_tables([CheckinKey, Checkin, Lockdown])
db.close()


def needs_valid_signature(or_master=False):
    def wrapper(fun):
        @functools.wraps(fun)
        def wrapped(*args, **kwargs):
            try:
                data = request.get_json(force=True)
            except:
                return jsonify({'status': 'data_error', 'reason': 'bad_outer_json',
                                'text': 'The outer message was not recognized as valid JSON'}), 400
            ip = request.remote_addr
            try:
                signature = data['signature']
                message = data['message']
            except KeyError:
                return jsonify({'status': 'data_error', 'reason': 'no_outer_field',
                                'text': 'The outer message did not contain an obligatory field'}), 400

            to_verify = '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n' + message + '\n' + signature
            verification = gpg.verify(to_verify)
            if not verification:
                help(verification)
                return jsonify({'status': 'forbidden', 'reason': 'unregistered',
                                'text': 'Verification failed, first you need to register the PGP key'}), 403

            fingerprint = verification.fingerprint
            if or_master and fingerprint == MASTER_FINGERPRINT:
                key = None
            else:
                if fingerprint == MASTER_FINGERPRINT:
                    return jsonify({'status': 'forbidden', 'reason': 'master_not_allowed',
                                    'text': 'You tried to use the master key in a context where it is not allowed.'})
                try:
                    key = CheckinKey.get(fingerprint=fingerprint)
                except CheckinKey.DoesNotExist:
                    return jsonify({'status': 'error',
                                    'text': 'You used a key that is in GPG\'s database, but not in this service\'s. This should not have happened, you need to re-register this key.'}), 500
                if key.distrusted:
                    return jsonify(
                        {'status': 'forbidden', 'reason': 'distrusted', 'since': key.trust_status_since.isoformat(),
                         'text': 'The key you used was distrusted as of ' + key.trust_status_since.isoformat() + ' and so cannot be used for check-ins. Use a new key.'}), 403
            try:
                message = json.loads(message)
                if not isinstance(message, dict): raise ValueError
            except:
                return jsonify({'status': 'data_error', 'reason': 'invalid_json',
                                'text': 'The message was not a valid JSON object.'}), 422

            if message.get('unix_minute') != int(time.time()) // 60:
                return jsonify({'status': 'forbidden', 'reason': 'timestamp_wrong',
                                'timestamp': {'mine': int(time.time()) // 60, 'yours': message.get('unix_minute')},
                                'text': 'The timestamp provided with your message is incorrect; it should be the number of minutes elapsed since the Unix Epoch. It is currently ' + str(
                                    int(time.time()) // 60) + ' but you provided ' + repr(
                                    message.get('unix_minute'))}), 403

            kwargs.update({'key': key, 'message': message})
            return fun(*args, **kwargs)

        return wrapped

    return wrapper


def alters_state(human_readable=True):
    def wrapper(fun):
        @functools.wraps(fun)
        def wrapped(*args, **kwargs):
            if len(Lockdown.select()) != 0:
                return redirect(url_for('main'))
            else:
                return fun(*args, **kwargs)

        return wrapped

    return wrapper


@app.before_request
def before_request():
    db.connect()
    if len(Lockdown.select()) > 0:
        ld = list(Lockdown.select())[0]
        if ld.hard_lock:
            return '', 204


@app.after_request
def after_request(resp):
    db.close()
    return resp


@app.route('/')
def main():
    return 'Hello, World!'


@app.route('/', methods=['DELETE'])
@needs_valid_signature(True)
@alters_state(True)
def lockdown(key=True, message=None):
    if key is not None:
        return jsonify({'status': 'forbidden', 'reason': 'need_master_auth',
                        'text': 'This action requires being authed by the master key.'}), 403
    if 'text' not in message:
        return jsonify({'status': 'data_error', 'reason': 'need_text',
                        'text': 'A text message is required to initiate lockdown.'}), 422
    if 'hard' not in message:
        return jsonify({'status': 'data_error', 'reason': 'need_hard', 'text': 'Is the lockdown hard or not?'}), 422
    Lockdown.create(message=message['text'], hard_lock=message['hard'])
    return jsonify({'status': 'ok'})


@app.route('/api/checkin', methods=['POST'])
@needs_valid_signature(False)
@alters_state(False)
def check_in(key=None, message=None):
    new_checkin = Checkin.create(used_key=key, ip_address=request.remote_addr, comment=message.get('comment'),
                                 can_be_evicted=not message.get('prevent_eviction', False))

    resp = jsonify({'status': 'ok', 'id': new_checkin.uuid,
                    'text': 'Checkin successfully registered and assigned id ' + str(new_checkin.uuid)})
    resp.headers['Location'] = url_for('get_checkin', uid=str(new_checkin.uuid))
    return resp, 201


@app.route('/api/checkin/<uid>', methods=['GET'])
def get_checkin(uid):
    return 'To be implemented', 500


@app.route('/api/key/<fprint>', methods=['GET'])
def get_key(fprint):
    try:
        key = CheckinKey.get(fingerprint=fprint)
    except CheckinKey.DoesNotExist:
        return jsonify({'status': 'not_found',
                        'text': 'The requested key fingerprint (' + fprint + ') not registered in the system.'}), 404
    return jsonify({'status': 'ok', 'public_key': key.pub_key, 'fingerprint': key.fingerprint, 'name': key.name,
                    'distrusted': key.distrusted, 'trust_status_since': key.trust_status_since.isoformat()}), 200


@app.route('/api/key/<fprint>', methods=['DELETE'])
@needs_valid_signature(True)
@alters_state(False)
def distrust_key(fprint, key=None, message=None):
    if key is None or key.fingerprint == fprint:
        key.distrusted = True
        key.trust_status_since = datetime.datetime.now()
        key.save()
        return jsonify({'status': 'ok', 'text': 'This key is now distrusted.'}), 200
    else:
        return jsonify({'status': 'forbidden', 'reason': 'fprint_mismatch',
                        'text': 'The message\'s key fingerprint does not match the fingerprint you requested and is not the master.'}), 403


@app.route('/api/key', methods=['POST'])
@needs_valid_signature(True)
@alters_state(False)
def create_key(key=True, message=None):
    if key is not None:
        return jsonify({'status': 'forbidden', 'reason': 'need_master_auth',
                        'text': 'This action requires being authed by the master key.'}), 403
    try:
        pubkey = message['pubkey']
        name = message['name']
    except KeyError:
        return jsonify(
            {'status': 'data_error', 'reason': 'no_field', 'text': 'A mandatory field was omitted from the json'}), 411

    import_res = gpg.import_keys(pubkey)
    if len(import_res.fingerprints) == 0:
        return jsonify({'status': 'data_error', 'reason': 'no_fingerprint',
                        'text': 'There were no fingerprints in the provided key data.'}), 411
    elif len(import_res.fingerprints) > 1:
        return jsonify({'status': 'data_error', 'reason': 'many_fingerprints',
                        'text': 'There were multiple fingerprints in the provided key data; this is not supported, so resend them separately.'}), 413

    fprint = import_res.fingerprints[0]
    key_id = (CheckinKey.insert(name=name, pub_key=pubkey, fingerprint=fprint,
                                distrusted=False).on_conflict_replace().execute())

    resp = jsonify(
        {'status': 'ok', 'fingerprint': fprint, 'text': 'The key with the fingerprint ' + fprint + ' was registered.'})
    resp.headers['Location'] = url_for('get_key', fprint=fprint)
    return resp, 201


if __name__ == '__main__':
    import sys

    app.run('0.0.0.0', 5000, debug='test' in sys.argv)
