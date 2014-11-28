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

def edit_user(id=None, email=None, password=None):
    pass

def delete_user():
    pass

def view_user(email=None, count=False, all_users=False):
    if count:
        with app.app_context():
            print(str(User.query.all().count())+' users exist.')
            return True
    if all_users:
        with app.app_context():
            print('email\trole\tquota\tnum subdomains')
            for user in User.query.all():
                print(user.email+'\t'+user.role+'\t'+user.quota+'\t'+str(user.subdomains.count()))
            return True
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            print('email\trole\tquota\tnum subdomains')
            print(user.email+'\t'+user.role+'\t'+user.quota+'\t'+str(user.subdomains.count()))
            return True
        else:
            return False

def add_subdomain():
    pass

def edit_subdomain():
    pass

def delete_subdomain():
    pass

def regen_subdomain_token():
    pass

def view_subdomain(name=None, count=False, all_subdomains=False):
    if count:
        with app.app_context():
            print(str(Subdomain.query.all().count())+' subdomains exist.')
            return True
    if all_subdomains:
        with app.app_context():
            print('subdomain\tip\ttoken\tlast updated\tuser')
            for sub in Subdomain.query.all():
                print(sub.name+'\t'+sub.ip+'\t'+sub.token+'\t'+str(sub.last_updated)+'\t'+sub.user.name)
            return True
    if name:
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            print('subdomain\tip\ttoken\tlast updated\tuser')
            print(sub.name+'\t'+sub.ip+'\t'+sub.token+'\t'+str(sub.last_updated)+'\t'+sub.user.name)
            return True
        else:
            return False


if __name__ == "__main__":
    import argparse
