from peewee import *
from flask import Flask
import datetime

app = Flask(__name__)
db = SqliteDatabase('dead-man.db')

class MyModel(Model):
    class Meta:
        database = db

class CheckinKey(MyModel):
    pub_key = BlobField()
    short_id = CharField()
    long_id = CharField()
    name = CharField()
    distrusted = BooleanField()
    trust_status_since = DateTimeField()

class Checkin(MyModel):
    used_key = ForeignKeyField(CheckinKey)
    date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    comment = TextField()
    can_be_evicted = BooleanField(default=True)

class Martian(MyModel):
    date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    content = BlobField()
    reason = TextField()
    associated_key = ForeignKeyField(CheckinKey, null=True)

@app.route('/')
def hello_world():
    return 'Hello, World!'
