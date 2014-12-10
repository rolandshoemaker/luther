#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

"""
.. module:: luther.models
    :platform: Unix
    :synopsis: Model definitions for luther.

.. moduleauthor:: Roland Shoemaker <rolandshoemaker@gmail.com>
"""

from luther import app, db

from passlib.apps import custom_app_context as pwd_context
import uuid


def init_db():
    with app.app_context():
        db.create_all()
        db.session.commit()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    quota = db.Column(db.Integer, default=app.config['DEFAULT_USER_QUOTA'])
    role = db.Column(db.Integer, default=1)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def is_admin(self):
        if self.role == 0:
            return True
        else:
            return False


class Subdomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    ip = db.Column(db.String)
    v6 = db.Column(db.Boolean)
    token = db.Column(db.String)
    last_updated = db.Column(
        db.DateTime,
        default=db.func.now(),
        onupdate=db.func.now()
    )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship(
        'User',
        backref=db.backref(
            'subdomains',
            cascade='all, delete-orphan',
            lazy='dynamic'
        )
    )

    def generate_domain_token(self):
        self.token = str(uuid.uuid4())

    def verify_domain_token(self, token):
        return self.token == token
