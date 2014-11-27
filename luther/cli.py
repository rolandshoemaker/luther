#!/usr/bin/python
import config
from api import app, add_ddns, update_ddns, delete_ddns
from models import User, Subdomain, db

from getpass import getpass

db.init_app(app)

def add_user(email=None, password=None, role=1, quota=config.default_user_quota):
    if not email:
        email = input('Email: ')
    if User.query.filter.filter_by(email=email):
        print('Email already exists silly.')
        return False
    if not password:
        password = getpass()
        if not password == getpass(prompt='Confirm Password: '):
            print('Passwords dont match...')
            return False
        if password is '':
            print('Password cannot be blank.')
            return False
    with app.app_context():
        new_user = User(email=email, role=role, quota=quota)
        new_user.hash_password(password)
        db.session.add(new_user)
        db.session.commit()
    print(email+' added!')
    return True

def edit_user():
    pass

def delete_user():
    pass

def list_users(count=False):
    if count:
        with app.app_context():
            print(str(User.query.all().count())+' users exist.')
            return True

def add_subdomain():
    pass

def edit_subdomain():
    pass

def delete_subdomain():
    pass

def list_subdomains(count=False):
    if count:
        with app.app_context():
            print(str(Subdomain.query.all().count())+' subdomains exist.')
            return True

if __name__ == "__main__":
    import argparse
    