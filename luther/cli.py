#!/usr/bin/python
import config
from api import app, new_ddns, update_ddns, delete_ddns, validate_ip
from models import User, Subdomain, db

from getpass import getpass

from tabulate import tabulate

import click

import dns.resolver

db.init_app(app)

@click.group()
def cli():
    """CLI tool for interacting with luther -- v0.1 -- roland shoemaker

    [this is somewhat dangerous to luther, i guess. so be careful ._.]"""
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
        if User.query.filter_by(email=email).first():
            click.secho('Email already exists silly.', fg='red')
            return False
        if not password:
            password = getpass()
            if not password == getpass(prompt='Confirm Password: '):
                click.secho('Passwords dont match...', fg='red')
                return False
            if password is '':
                click.secho('Password cannot be blank.', fg='red')
                return False
        new_user = User(email=email, role=role, quota=quota)
        new_user.hash_password(password)
        db.session.add(new_user)
        db.session.commit()
        click.secho(email+' added!', fg='green')

@cli.command('edit_user')
@click.argument('email')
@click.password_option(help='Users password')
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
                click.secho('User '+user.email+' updated', fg='green')
            else:
                click.secho('User '+email+' doesnt exist', fg='red')
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
                    click.secho('Error deleting subdomain: '+sub.name+'!', fg='red')
                    return False
            db.session.delete(user)
            db.session.commit()
            click.secho('Deleted user: '+user.email, fg='green')
        else:
            click.secho('Error deleting user: '+user.email, fg='red')
            return False

@cli.command('view_user')
@click.argument('email')
def view_user(email):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            click.echo(tabulate([user.email, user.role, user.quota, user.subdomains.count()], ['email', 'role', 'quota', 'num subdomains']))
        else:
            return False

@cli.command('list_users')
def list_users():
    with app.app_context():
        results = []
        for user in User.query.all():
            results.append([user.email, user.role, user.quota, user.subdomains.count()])
        click.echo(tabulate(results, ['email', 'role', 'quota', 'num subdomains']))


@cli.command('count_users')
def count_users():
    with app.app_context():
        click.secho(str(User.query.count())+' users exist.', fg='yellow')

@cli.command('list_users_subdomains')
@click.argument('email')
def users_subdomains(email):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            if user.subdomains.count() > 0:
                results = []
                click.secho(user.email+' has these subdomains', fg='green')
                for sub in user.subdomains:
                    results.append([sub.name, sub.ip, sub.token, sub.last_updated])
                click.echo(tabulate(results, ['subdomain', 'ip', 'token', 'last updated']))
            else:
                click.secho(user.email+' has no subdomains.', fg='yellow')
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
                        click.secho('Invalid IP', fg='red')
                        return False
                if new_ddns(name, ip, v6=ipv6, on_api=False):
                    sub = Subdomain(name=name, ip=ip, v6=ipv6, user=user)
                    sub.generate_domain_token()
                    db.session.add(sub)
                    db.session.commit()
                    click.secho('Added new subdomain: '+sub.name+' for '+user.email, fg='green')
                else:
                    return False
            else:
                click.secho('Subdomain already exists!', fg='red')
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
                    click.secho('User '+user_email+' doesnt exist', fg='red')
                    return False
            db.session.commit()
            click.secho('Subdomain '+sub.name+' updated!', fg='green')
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
                click.secho('Deleted subdomain: '+name, fg='green')
            else:
                click.secho('Error deleting subdomain: '+name, fg='ref')
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
            click.secho('Subdomain token for '+sub.name+' regenerated: '+sub.token, fg='green')
        else:
            return False

@cli.command('regen_users_subdomain_tokens')
@click.argument('email')
def regen_users_subdomain_tokens(email):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            for sub in user.subdomains:
                sub.regen_subdomain_token()
            click.secho('Regenerated all of the subdomain tokens for '+user.email, fg='green')
        else:
            return False

@cli.command('view_subdomain')
@click.argument('name')
def view_subdomain(name):
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            click.echo(tabulate([sub.name, sub.ip, sub.token, sub.last_updated, sub.user.email], ['subdomain', 'ip', 'token', 'last updated', 'user']))
        else:
            return False

@cli.command('count_subdomains')
def count_subdomains():
    with app.app_context():
        click.secho(str(Subdomain.query.count())+' subdomains exist.', fg='yellow')

@cli.command('list_subdomains')
def list_subdomains():
    with app.app_context():
        results = []
        for sub in Subdomain.query.all():
            results.append([sub.name, sub.ip, sub.token, sub.last_updated, sub.user.email])
        click.echo(tabulate(results, ['subdomain', 'ip', 'token', 'last updated', 'user']))

@cli.command('dig_subdomain')
@click.argument('name')
def dig_subdomain(name):
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            answer = dns.resolver.query(sub.name+config.dns_root_domain, 'A')
            match = bool()
            for rdata in answer:
                if rdata.address is sub.ip:
                    match = True
            if match:
                click.secho('IP address returned from nameservers matches address in database', fg='green')
            else:
                click.secho('IP address returned from nameservers doesnt match address in database', fg='red')
                return False
        else:
            return False

@cli.command('init_db')
def init_db():
    with app.app_context():
        db.create_all()
        db.commit()

if __name__ == "__main__":
    cli()
