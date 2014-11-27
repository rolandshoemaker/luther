#!/usr/bin/python
import config
from restapi import app
from models import User, db

from getpass import getpass

db.init_app(app)

def add(email=None, password=None, role=1, quota=config.default_user_quota):
    if not email:
        email = input('Email: ')
    if User.query.filter.filter_by(email=email):
        print('Email already exists silly.')
        return 0
    if not password:
        password = getpass()
        if not password == getpass(prompt='Confirm Password: '):
            print('Passwords dont match...')
            return 0
        if password is '':
            print('Password cannot be blank.')
            return 0
    with app.app_context():
        new_user = User(email=email, role=role, quota=quota)
        new_user.hash_password(password)
        db.session.add(new_user)
        db.session.commit()
    print(email+' added!')
    return 1