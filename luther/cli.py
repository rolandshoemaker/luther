#!/usr/bin/python
import config
from api import app, new_ddns, update_ddns, delete_ddns, validate_ip
from models import User, Subdomain, db

from getpass import getpass

from tabulate import tabulate

import click

db.init_app(app)

@click.group()
def cli():
    pass

@cli.command('add_user')
@click.argument('email')
@click.argument('password')
@click.option('--role', default=1, help='User role (0 admin, 1 user)')
@click.option('--quota', default=config.default_user_quota, help='User subdomain quota')
def add_user(email, password, role, quota):
    with app.app_context():
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
        new_user = User(email=email, role=role, quota=quota)
        new_user.hash_password(password)
        db.session.add(new_user)
        db.session.commit()
        print(email+' added!')

@cli.command('edit_user')
@click.argument('email')
@click.option('--password', help='Users password')
@click.option('--role', help='User role (0 admin, 1 user)')
@click.option('--quota', help='User subdomain quota')
def edit_user(email, password, role, quota):
    with app.app_context():
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                if password:
                    user.hash_password(password)
                if quota:
                    user.quota = quota
                if role:
                    user.role = role
                db.session.commit()
                print('User '+user.email+' updated')
            else:
                print('User '+email+' doesnt exist')
                return False
        else:
            return False

@cli.command('delete_user')
@click.argument('email')
def delete_user(email):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            for sub in user.subdomains:
                if not delete_ddns(sub.name, on_api=False):
                    print('Error deleting subdomain: '+sub.name+'!')
                    return False
            db.session.delete(user)
            db.session.commit()
            print('Deleted user: '+user.email)
        else:
            print('Error deleting user: '+user.email)
            return False

@cli.command('view_user')
@click.argument('email')
def view_user(email):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            print(tabulate([user.email, user.role, user.quota, user.subdomains.count()], ['email', 'role', 'quota', 'num subdomains']))
        else:
            return False

@cli.command('list_users')
def list_users():
    with app.app_context():
        results = []
        for user in User.query.all():
            results.append([user.email, user.role, user.quota, user.subdomains.count()])
        print(tabulate(results, ['email', 'role', 'quota', 'num subdomains']))


@cli.command('count_users')
def count_users():
    with app.app_context():
        print(str(User.query.count())+' users exist.')

@cli.command('list_users_subdomains')
@click.argument('email')
def users_subdomains(email):
    user = User.query.filter_by(email=email).first()
    if user:
        if user.subdomains.count() > 0:
            results = []
            print(user.email+' has these subdomains')
            for sub in user.subdomains:
                results.append([sub.name, sub.ip, sub.token, sub.last_updated])
            print(tabulate(results, ['subdomain', 'ip', 'token', 'last updated']))
        else:
            print(user.email+' has not subdomains.')
    else:
        return False

@cli.command('add_subdomain')
@click.argument('user_email')
@click.argument('name')
@click.argument('ip')
def add_subdomain(user_email, name, ip):
    with app.app_context():
        user = User.query.filter_by(email=user_email).first()
        if user:
            if not Subdomain.query.filter_by(name=name).first():
                ipv6 = False
                if not validate_ip(ip):
                    if validate_ip(ip, v6=True):
                        ipv6 = True
                    else:
                        print('Invalid IP')
                        return False
                if new_ddns(name, ip, v6=ipv6, on_api=False):
                    sub = Subdomain(name=name, ip=ip, v6=ipv6, user=user)
                    sub.generate_domain_token()
                    db.session.add(sub)
                    db.session.commit()
                    print('Added new subdomain: '+sub.name+' for '+user.email)
                else:
                    return False
            else:
                print('Subdomain already exists!')
                return False
        else:
            return False

@cli.command('edit_subdomain')
@click.argument('name')
@click.option('--ip', help='IP Address to point to')
@click.option('--v6/--v4', default=False, help='Whether the address is IPv6 or IPv4')
@click.option('--user_email', help='Email of user who owns the subdomain')
def edit_subdomain(name, ip, v6, user_email):
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            if ip:
                sub.ip = ip
            if v6:
                sub.v6 = v6
            if user_email:
                user = User.query.filter_by(email=user_email).first()
                if user:
                    sub.user = user
                else:
                    print('User '+user_email+' doesnt exist')
                    return False
            db.session.commit()
            print('Subdomain '+sub.name+' updated!')
        else:
            return False

@cli.command('delete_subdomain')
@click.argument('name')
def delete_subdomain(name):
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            if delete_ddns(name, on_api=False):
                db.session.delete(sub)
                db.session.commit()
                print('Deleted subdomain: '+name)
            else:
                print('Error deleting subdomain: '+name)
                return False
        else:
            return False

@cli.command('regen_subdomain_token')
@click.argument('name')
def regen_subdomain_token(name):
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name)
        if sub:
            sub.generate_domain_token()
            db.session.commit()
            print('Subdomain token for '+sub.name+' regenerated: '+sub.token)
        else:
            return False

@cli.command('view_subdomain')
@click.argument('name')
def view_subdomain(name):
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            print(tabulate([sub.name, sub.ip, sub.token, sub.last_updated, sub.user.email], ['subdomain', 'ip', 'token', 'last updated', 'user']))
        else:
            return False

@cli.command('count_subdomains')
def count_subdomains():
    with app.app_context():
        print(str(Subdomain.query.count())+' subdomains exist.')

@cli.command('list_subdomains')
def list_subdomains():
    with app.app_context():
        results = []
        for sub in Subdomain.query.all():
            results.append([sub.name, sub.ip, sub.token, sub.last_updated, sub.user.email])
        print(tabulate(results, ['subdomain', 'ip', 'token', 'last updated', 'user']))

if __name__ == "__main__":
    cli()
