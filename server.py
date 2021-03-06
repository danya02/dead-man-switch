from peewee import *
from flask import Flask, request, jsonify, redirect, url_for, render_template
import datetime
import gnupg
import functools
import uuid
import json
import time
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

logger = logging.getLogger('peewee')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

app = Flask(__name__)
db = SqliteDatabase('dead-man.db')
gpg = gnupg.GPG(gnupghome='/home/danya/.gnupg', verbose=True, use_agent=True)

MASTER_FINGERPRINT = '73F0F8B9A5468F6E02E088BC90DF11CC3211DA60'
EVICTION_THRESHOLD = 1024  # how many evictable rows are allowed per key before the oldest begin being evicted


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

    def safe_ip_addr(self):
        a, b, c, d = self.ip_address.split('.')
        return f'{a}.{b}.{c}.XXX'


class Lockdown(MyModel):
    message = TextField()
    date = DateTimeField(default=datetime.datetime.now)
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
                if human_readable:
                    return redirect(url_for('main'))
                else:
                    lock = list(Lockdown.select())[0]
                    return jsonify({'status': 'emergency', 'reason': 'lockdown', 'message': lock.message,
                                    'date': lock.date.isoformat(), 'text': 'This system is under lockdown since ' + str(
                            lock.date) + '. The owner left this message: ' + lock.message}), 451
            else:
                return fun(*args, **kwargs)

        return wrapped

    return wrapper


@app.before_request
def before_request():
    db.connect()
    if len(Lockdown.select()) > 0:
        for lock in list(Lockdown.select()):
            if lock.hard_lock:
                return '', 204


@app.after_request
def after_request(resp):
    db.close()
    return resp


@app.route('/')
def main():
    try:
        lock = Lockdown.select()[0]
    except IndexError:
        lock = None
    return render_template('index.html', Checkin=Checkin, CheckinKey=CheckinKey, lock=lock)


@app.route('/key/<fprint>')
def view_key(fprint):
    try:
        key = CheckinKey.get(CheckinKey.fingerprint == fprint)
    except CheckinKey.DoesNotExist:
        return 'key not found', 404
    return render_template('key.html', Checkin=Checkin, CheckinKey=CheckinKey, key=key)


@app.route('/checkin/<uuid>')
def view_checkin(uuid):
    try:
        checkin = Checkin.get(Checkin.uuid == uuid)
    except Checkin.DoesNotExist:
        return 'checkin not found', 404
    return render_template('checkin.html', Checkin=Checkin, CheckinKey=CheckinKey, checkin=checkin)


@alters_state(human_readable=False)
@app.route('/api/checkin/evict')
def run_eviction():
    answer = {}
    for key in CheckinKey.select():
        try:
            later_than = \
                Checkin.select().where((Checkin.can_be_evicted == True) & (Checkin.used_key == key)).order_by(
                    Checkin.date)[
                    -EVICTION_THRESHOLD]
            rows = Checkin.delete().where((Checkin.date < later_than.date) & (Checkin.used_key == key)).execute()
        except IndexError:
            rows = 0
        answer[key.fingerprint] = rows
    return jsonify({'status': 'ok', 'affected_rows': answer})


@app.route('/', methods=['DELETE'])
@needs_valid_signature(or_master=True)
@alters_state(human_readable=True)
def lockdown(key=True, message=None):
    if key is not None:
        return jsonify({'status': 'forbidden', 'reason': 'need_master_auth',
                        'text': 'This action requires being authed by the master key.'}), 403
    if 'text' not in message:
        return jsonify({'status': 'data_error', 'reason': 'need_text',
                        'text': 'A text message is required to initiate lockdown.'}), 422
    if 'hard' not in message:
        return jsonify({'status': 'data_error', 'reason': 'need_hard', 'text': 'Is the lockdown hard or not?'}), 422
    Lockdown.create(message=message['text'], hard_lock=bool(message['hard']))
    return jsonify({'status': 'ok'})


@app.route('/api/checkin', methods=['POST'])
@needs_valid_signature(or_master=False)
@alters_state(human_readable=False)
def check_in(key=None, message=None):
    new_checkin = Checkin.create(used_key=key, ip_address=request.remote_addr, comment=message.get('comment'),
                                 can_be_evicted=not message.get('prevent_eviction', False))

    resp = jsonify({'status': 'ok', 'id': new_checkin.uuid,
                    'text': 'Checkin successfully registered and assigned id ' + str(new_checkin.uuid)})
    resp.headers['Location'] = url_for('get_checkin', uid=str(new_checkin.uuid))
    return resp, 201


@app.route('/api/checkin/<uid>', methods=['GET'])
def get_checkin(uid):
    try:
        checkin = Checkin.get(Checkin.uuid == uuid.UUID(uid))
    except Checkin.DoesNotExist:
        return jsonify({'status': 'not_found', 'id': uid,
                        'text': 'The requested check-in with id ' + uid + ' not found. It may never have existed or been evicted.'}), 404
    except ValueError:
        return jsonify(
            {'status': 'data_error', 'reason': 'not_uuid', 'text': 'You have requested an invalid UUID.'}), 400
    return jsonify(
        {'status': 'ok', 'ip': checkin.safe_ip_addr(), 'date': checkin.date.isoformat(), 'comment': checkin.comment,
         'evictable': checkin.can_be_evicted, 'key': checkin.used_key.fingerprint})


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
@needs_valid_signature(or_master=True)
@alters_state(human_readable=False)
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
@needs_valid_signature(or_master=True)
@alters_state(human_readable=False)
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

    app.run('0.0.0.0', 5050, debug='test' in sys.argv)
