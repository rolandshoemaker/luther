import config

from flask.ext.sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import uuid

db = SQLAlchemy()

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(120), unique=True)
	password_hash = db.Column(db.String(128))
	quota = db.Column(db.Integer)
	role = db.Column(db.Integer)

	def hash_password(self, password):
		self.password_hash = pwd_context.encrypt(password)

	def verify_password(self, password):
		return pwd_context.verify(password, self.password_hash)

	def generate_auth_token(self, expiration=600):
		s = Serializer(config.secret_key, expires_in=expiration)
		return s.dumps({'id': self.id})

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(config.secret_key)
		try:
			data = s.loads(token)
		except SignatureExpired:
			return None # valid token, but expired
		except BadSignature:
			return None # invalid token
		user = User.query.get(data['id'])
		return user

class Domain(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String)
	ip = db.Column(db.String)
	v6 = db.Column(db.Boolean)
	token = db.Column(db.String)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	user = db.relationship('User', backref=db.backref('domains', lazy='dynamic'))

	def generate_domain_token(self):
		self.token = str(uuid.uuid4())
		return self.token

	def verify_domain_token(self, token):
		return self.token == token
