#!/usr/bin/python
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

"""
.. module:: luther.cli
    :platform: Unix
    :synopsis: CLI interface for interacting with a luther service.

.. moduleauthor:: Roland Shoemaker <rolandshoemaker@gmail.com>
"""

from luther import app
from luther.api import new_ddns, update_ddns, \
    delete_ddns, validate_ip, predis
from luther.models import User, Subdomain, db

from getpass import getpass

from tabulate import tabulate

import click

import dns.message
import dns.query
import dns.resolver

db.init_app(app)


@click.group()
def cli():
    """CLI tool for interacting with luther -- v0.1 -- roland shoemaker

    [this is somewhat dangerous to luther, i guess. so be careful ._.]
    """
    pass


@cli.command('add_user')
@click.argument('email')
@click.argument('password')
@click.option('--role', default=1, help='User role (0 admin, 1 user)')
@click.option('--quota', default=app.config['DEFAULT_USER_QUOTA'], help='User subdomain quota')
def add_user(email, password, role, quota):
    """Add a user"""
    with app.app_context():
        if not email:
            email = input('Email: ')
        if User.query.filter_by(email=email).first():
            click.secho('Email already exists silly.\n', fg='red')
            return False
        if not password:
            password = getpass()
            if not password == getpass(prompt='Confirm Password: '):
                click.secho('Passwords dont match...\n', fg='red')
                return False
            if password is '':
                click.secho('Password cannot be blank.\n', fg='red')
                return False
        new_user = User(email=email, role=role, quota=quota)
        new_user.hash_password(password)
        db.session.add(new_user)
        db.session.commit()
        click.secho(email+' added!\n', fg='green')

@cli.command('edit_user')
@click.argument('email')
@click.password_option(help='Users password')
@click.option('--role', help='User role (0 admin, 1 user)')
@click.option('--quota', help='User subdomain quota')
def edit_user(email, password, role, quota):
    """Edit a user"""
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
                click.secho('User '+user.email+' updated.\n', fg='green')
            else:
                click.secho('User '+email+' doesnt exist.\n', fg='red')
                return False
        else:
            click.secho('No user: '+email+'.\n', fg='red')

@cli.command('delete_user')
@click.argument('email')
def delete_user(email):
    """Delete a user"""
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            for sub in user.subdomains:
                if not delete_ddns(sub.name, on_api=False):
                    click.secho('Error deleting subdomain: '+sub.name+'!\n', fg='red')
                    return False
            db.session.delete(user)
            db.session.commit()
            click.secho('Deleted user: '+user.email+'.\n', fg='green')
        else:
            click.secho('No user: '+email+'.\n', fg='red')

@cli.command('view_user')
@click.argument('email')
@click.pass_context
def view_user(ctx, email):
    """View a specific user"""
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            click.echo(tabulate([[user.email, user.role, user.quota, user.subdomains.count()]], ['email', 'role', 'quota', 'num subdomains']))
            click.echo()
            ctx.invoke(users_subdomains, email=email)
        else:
            click.secho('No user: '+email+'.\n', fg='red')

@cli.command('count_users')
@click.option('--role', help='Role to filter users by (0/1)')
def count_users(role):
    """Count all users"""
    with app.app_context():
        if role:
            click.secho(str(User.query.filter_by(role=role).count())+' users exist.\n', fg='yellow')
        else:
            click.secho(str(User.query.count())+' users exist.\n', fg='yellow')

@cli.command('list_users')
@click.option('--role', help='Role to filter users by (0/1)')
@click.pass_context
def list_users(ctx, role):
    """List all users"""
    with app.app_context():
        results = []
        if role:
            ctx.invoke(count_users, role=role)
            users = User.query.filter_by(role=role).all()
        else:
            ctx.invoke(count_users)
            users = User.query.all()
        for user in users:
            results.append([user.email, user.role, user.quota, user.subdomains.count()])
        click.echo(tabulate(results, ['email', 'role', 'quota', 'num subdomains']))
        click.echo()

@cli.command('list_users_subdomains')
@click.argument('email')
def users_subdomains(email):
    """List all a users subdomains"""
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            if user.subdomains.count() > 0:
                results = []
                click.secho(user.email+' has these subdomains.\n', fg='green')
                for sub in user.subdomains:
                    results.append([sub.name, sub.ip, sub.token, sub.last_updated])
                click.echo(tabulate(results, ['subdomain', 'ip', 'token', 'last updated']))
                click.echo()
            else:
                click.secho(user.email+' has no subdomains.\n', fg='yellow')
        else:
            click.secho('No user: '+email+'.\n', fg='red')

@cli.command('add_subdomain')
@click.argument('user_email')
@click.argument('name')
@click.argument('ip')
def add_subdomain(user_email, name, ip):
    """Add a new subdomain"""
    with app.app_context():
        user = User.query.filter_by(email=user_email).first()
        if user:
            if not Subdomain.query.filter_by(name=name).first():
                ipv6 = False
                if not validate_ip(ip):
                    if validate_ip(ip, v6=True):
                        ipv6 = True
                    else:
                        click.secho('Invalid IP\n', fg='red')
                        return False
                if new_ddns(name, ip, v6=ipv6, on_api=False):
                    sub = Subdomain(name=name, ip=ip, v6=ipv6, user=user)
                    sub.generate_domain_token()
                    db.session.add(sub)
                    db.session.commit()
                    click.secho('Added new subdomain: '+sub.name+' for '+user.email+'.\n', fg='green')
                else:
                    return False
            else:
                click.secho('Subdomain already exists!\n', fg='red')
                return False
        else:
            click.secho('No user: '+user_email+'.\n', fg='red')

@cli.command('edit_subdomain')
@click.argument('name')
@click.option('--ip', help='IP Address to point to')
@click.option('--v6/--v4', default=False, help='Whether the address is IPv6 or IPv4')
@click.option('--user_email', help='Email of user who owns the subdomain')
def edit_subdomain(name, ip, v6, user_email):
    """Edit a subdomain"""
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
                    click.secho('User '+user_email+' doesnt exist.\n', fg='red')
                    return False
            if update_ddns(sub.name, ip, v6=v6, on_api=False):
                db.session.commit()
                click.secho('Subdomain '+sub.name+' updated!\n', fg='green')
            else:
                click.secho('DNS Update for '+sub.name+' failed.')
                return False
        else:
            click.secho('No subdomain: '+name+'.\n', fg='red')
            return False

@cli.command('delete_subdomain')
@click.argument('name')
def delete_subdomain(name):
    """Delete a subdomain"""
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            if delete_ddns(name, on_api=False):
                db.session.delete(sub)
                db.session.commit()
                click.secho('Deleted subdomain: '+name+'.\n', fg='green')
            else:
                click.secho('Error deleting subdomain: '+name+'.\n', fg='ref')
                return False
        else:
            click.secho('No subdomain: '+name+'.\n', fg='red')

@cli.command('regen_subdomain_token')
@click.argument('name')
def regen_subdomain_token(name):
    """Regenerate the token for a subdomain"""
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name)
        if sub:
            sub.generate_domain_token()
            db.session.commit()
            click.secho('Subdomain token for '+sub.name+' regenerated: '+sub.token+'.\n', fg='green')
        else:
            click.secho('No subdomain: '+name+'.\n', fg='red')

@cli.command('regen_users_subdomain_tokens')
@click.argument('email')
def regen_users_subdomain_tokens(email):
    """Regenerate all subdomain tokens for a user"""
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            for sub in user.subdomains:
                sub.regen_subdomain_token()
            click.secho('Regenerated all of the subdomain tokens for '+user.email+'.\n', fg='green')
        else:
            click.secho('No user: '+email+'.\n', fg='red')

@cli.command('view_subdomain')
@click.argument('name')
def view_subdomain(name):
    """View a specific subdomain"""
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            click.echo(tabulate([[sub.name, sub.ip, sub.token, sub.last_updated, sub.user.email]], ['subdomain', 'ip', 'token', 'last updated', 'user']))
            click.echo()
        else:
            click.secho('No subdomain: '+name+'.\n', fg='red')

@cli.command('count_subdomains')
def count_subdomains():
    """Count all subdomains"""
    with app.app_context():
        click.secho(str(Subdomain.query.count())+' subdomains exist.\n', fg='yellow')

@cli.command('list_subdomains')
@click.pass_context
def list_subdomains(ctx):
    """List all subdomains"""
    ctx.forward(count_subdomains)
    with app.app_context():
        results = []
        for sub in Subdomain.query.all():
            results.append([sub.name, sub.ip, sub.token, sub.last_updated, sub.user.email])
        click.echo(tabulate(results, ['subdomain', 'ip', 'token', 'last updated', 'user']))
        click.echo()

@cli.command('search_subdomains')
@click.option('--name', help='Name to search for')
@click.option('--ip', help='IP address to search for')
def search_users(name, ip):
    """Search for users by email"""
    with app.app_context():
        results = []
        if name and not ip:
            subdomains = Subdomain.query.filter(Subdomain.name.like('%'+name+'%')).all()
        elif ip and not name:
            subdomains = Subdomain.query.filter(Subdomain.ip.like('%'+ip+'%')).all()
        else:
            return False
        for sub in subdomains:
            results.append([sub.name, sub.ip, sub.token, sub.last_updated, sub.user.email])
        click.echo(tabulate(results, ['subdomain', 'ip', 'token', 'last updated', 'user']))
        click.echo()

@cli.command('search_users')
@click.argument('email')
def search_users(email):
    """Search for users by email"""
    with app.app_context():
        results = []
        users = User.query.filter(User.email.like('%'+email+'%')).all()
        for user in users:
            results.append([user.email, user.role, user.quota, user.subdomains.count()])
        click.echo(tabulate(results, ['email', 'role', 'quota', 'num subdomains']))
        click.echo()

@cli.command('dig_subdomain')
@click.argument('name')
@click.option('--nameserver', default='localhost', help='Specific nameserver to query')
def dig_subdomain(name, nameserver):
    """Check subdomain IP address in database against the address returned from nameservers"""
    with app.app_context():
        sub = Subdomain.query.filter_by(name=name).first()
        if sub:
            if sub.v6:
                rtype = 'AAAA'
            else:
                rtype = 'A'
            dns.resolver.nameservers = [nameserver]
            answer = dns.resolver.query(sub.name+'.'+app.config['DNS_ROOT_DOMAIN'], rtype)
            match = bool()
            returned_ips = []
            for rdata in answer:
                returned_ips.append([rdata.address])
                if rdata.address == sub.ip:
                    match = True
            if match:
                click.secho('IP address returned from nameservers matches address in database ('+sub.ip+').\n', fg='green')
            else:
                click.secho('IP address returned from nameservers doesnt match address in database. Returned addresses where:', fg='red')
                click.echo(tabulate(returned_ips))
                click.echo()
                return False
        else:
            click.secho('No subdomain: '+name+'.\n', fg='red')

@cli.command('init_db')
def init_db():
    """Initiailize the luther db"""
    with app.app_context():
        db.create_all()
        db.commit()
        click.secho('Initialized database, you may want to add a (admin) user now!\n', fg='green')

@cli.command('check_stats')
def check_stats():
    """Get the most recent stats from redis (relies on app.config['ENABLE_STATS'] = True)"""
    stats = predis.get('luther/stats')
    click.echo(tabulate([[stats['users'][len(stats['users'])-1][1], stats['subdomains'][len(stats['subdomains'])-1][1], stats['users'][len(stats['users'])-1][0]]], ['num users', 'num subdomains', 'updated']))
    return True

if __name__ == "__main__":
    cli()