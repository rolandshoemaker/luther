#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

"""
.. module:: luther.api
    :platform: Unix
    :synopsis: lightweight REST API for managing Dynamic DNS.

.. moduleauthor:: Roland Shoemaker <rolandshoemaker@gmail.com>
"""

##################
# luther imports #
##################

from luther import app, db
from luther.models import User, Subdomain

#################
# flask imports #
#################

from flask import g, request, jsonify, \
    render_template, make_response
from flask.ext.httpauth import HTTPBasicAuth

###############
# dns imports #
###############

import dns.query
import dns.tsigkeyring
import dns.update
from dns.query import UnexpectedSource, BadResponse
import dns.resolver
from dns.resolver import NoAnswer, NXDOMAIN

#################
# redis imports #
#################

from redis import Redis

##################
# system imports #
##################

from functools import update_wrapper
import time
import ipaddress
import re
import datetime

##############################
# flask + plugin object init #
##############################

auth = HTTPBasicAuth()

# db.init_app(app)

redis = Redis()

keyring = dns.tsigkeyring.from_text({
    app.config['DNS_ROOT_DOMAIN']+'.': app.config['TSIG_KEY']
})

##################
# luther logging #
##################

if not app.debug:
    import logging
    import logging.handlers
    from logging import Formatter
    fh = logging.handlers.RotatingFileHandler(
        app.config['LOG_FILE_PATH'],
        maxBytes=app.config['LOG_MAX_BYTES'],
        backupCount=app.config['LOG_BACKUP_COUNT']
    )
    fh.setLevel(logging.WARNING)
    fh.setFormatter(Formatter(app.config['LOG_FORMAT']))
    loggers = [app.logger]
    for logger in loggers:
        logger.addHandler(fh)

##################
# Util functions #
##################


def validate_ip(ip, v6=False):
    """validate_ip uses the ipaddress library to validate IPv4 and IPv6
    Addresses.

    :param ip: The IP Address to test.
    :type ip: string.
    :param v6: Address is IPv6.
    :type v6: bool.
    :returns: bool -- If Address is valid.

    """
    try:
        if not v6:
            test = ipaddress.IPv4Address(ip)
        else:
            test = ipaddress.IPv6Address(ip)
        correct_subnet = False
        for subnet in app.config['ALLOWED_DDNS_IPV4_SUBNETS']:
            if test in ipaddress.IPv4Network(subnet):
                correct_subnet = True
        for subnet in app.config['ALLOWED_DDNS_IPV6_SUBNETS']:
            if test in ipaddress.IPv6Network(subnet):
                correct_subnet = True
        if (test.is_private and not app.config['ALLOW_PRIVATE_ADDRESSES']) \
                or not correct_subnet:
            return False
        return test.exploded
    except ipaddress.AddressValueError:
        return False

def in_allowed_network(ip, v4_networks=app.config['ALLOWED_USER_V4_SUBNETS'],
                       v6_networks=app.config['ALLOWED_USER_V6_SUBNETS']):
    """in_allowed_network tests whether an IP Address
    is within a list of defined networks (v4/v6).

    :param ip: The IP Address to test.
    :type ip: string.
    :param v4_networks: List of IPv4 networks to check against.
    :type v4_networks: list.
    :param v6_networks: List of IPv6 networks to check against.
    :type v6_networks: list.
    :returns: bool -- If address is in one of the provided networks.

    """
    in_net = False
    v6 = False
    try:
        ip_obj = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        try:
            ip_obj = ipaddress.IPv6Address(ip)
            v6 = True
        except ipaddress.AddressValueError:
            return False
    if not v6 and v4_networks:
        for subnet in v4_networks:
            if ip_obj in ipaddress.IPv4Network(subnet):
                in_net = True
    elif v6 and v6_networks:
        for subnet in v6_networks:
            if ip_obj in ipaddress.IPv6Network(subnet):
                in_net = True
    return in_net

# This could be better (should really support subsub domains...)
SUBDOMAIN_REGEX = re.compile('^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$', re.IGNORECASE)

def validate_subdomain(subdomain):
    """validate_subdomain checks to see if a subdomain is valid
    and not in a list of restricted names.

    :param subdomain: The subdomain to test.
    :type subdomain: string.
    :returns: bool -- If the subdomain is valid and not restricted.

    """
    if re.match(SUBDOMAIN_REGEX, subdomain) \
            and subdomain not in app.config['RESTRICTED_SUBDOMAINS']:
        return True
    else:
        return False


def json_status_message(message, code, extra=''):
    """json_status_message builds a JSON status response with
    assosiated HTTP status code, and extra stuff if you want.

    :param message: The message to to return.
    :type message: string.
    :param code: The HTTP status code.
    :type code: int.
    :param extra: Any extra stuff you want appended to the message.
    :type extra: string.
    :returns: obj -- A response object with http status code.

    """
    if extra is not '':
        extra = ', '+extra
    message = {'status': code, 'message': message+extra}
    resp = jsonify(message)
    resp.status_code = code
    return resp

##################
# Error handling #
##################


class LutherBroke(Exception):
    """super special luther Exception."""
    status_code = 400
    message = 'Bad request'

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['status'] = self.status_code
        return rv


@app.errorhandler(LutherBroke)
def handle_broken(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)
    # return 403 instead of 401 to prevent browsers from
    # displaying the default auth dialog

#################
# DNS functions #
#################


def dns_message_check(msg, on_api):
    """dns_message_check checks the rcode of a dns.message.Message response.

    :param msg: The dns.message.Message object.
    :type msg: object.
    :returns: object -- None on success or a internal_error()
        JSON response based on the rcode.

    """
    rcode_errors = {
        1: 'malformed dns message',
        2: '',
        3: 'subdomain does not exist on master dns server',
        4: 'master dns server does not support that opcode',
        5: ('master dns server refuses to perform the specified '
            'operation for policy or security reasons'),
        6: 'subdomain already exists on master dns server',
        7: 'record that shouldnt exist does exist',
        8: 'record that should exist doesnt exist',
        9: ('server is not authorized or is using bad tsig key to '
            'make updates to zone \''+app.config['DNS_ROOT_DOMAIN']+'.'+'\' '
            'on master dns server'),
        10: ('zone \''+app.config['DNS_ROOT_DOMAIN']+'.'+'\' does not exist '
             'on master dns server'),
        16: ''
        }
    error_info = rcode_errors.get(msg.rcode())
    if error_info is not None:
        if error_info is not '':
            error_info = ', '+error_info
        if on_api:
            raise LutherBroke('Internal server error'+error_info,
                              status_code=500)
        else:
            return False
    else:
        return True


def dns_query(update,
              on_api,
              server=app.config['DNS_MASTER_SERVER'],
              port=app.config['DNS_MASTER_PORT'],
              source_port=app.config['DNS_MASTER_SOURCE_PORT'],
              timeout=app.config['DNS_MASTER_TIMEOUT']):
    """dns_query sends dns.update.Update objects to a dns
    server and parses the response.

    :param update:
    :type update: object.
    :param on_api:
    :type on_api: bool.
    :param server:
    :type server: string.
    :param port:
    :type port: int.
    :param source_port:
    :type source_port: int.
    :param timeout:
    :type timeout: int.
    :returns: object -- None on success or JSON response indicating the error.

    """
    try:
        resp = dns.query.tcp(update,
                             server,
                             port=port,
                             source_port=source_port,
                             timeout=timeout)
        if dns_message_check(resp, on_api):
            return True
    except NoAnswer:
        raise LutherBroke(
            'Internal server error, response contained no answer',
            status_code=500
        )
    except UnexpectedSource:
        raise LutherBroke(
            'Internal server error, response came from unexpected source',
            status_code=500
        )
    except BadResponse:
        raise LutherBroke(
            'Internal server error, malformed response from master dns server',
            status_code=500
        )
    except TimeoutError:
        raise LutherBroke(
            'Gateway timeout, tcp connection to master DNS server timed out',
            status_code=504
        )
    except OSError:
        raise LutherBroke(
            ('Internal server error, OSError '
             '(most likely no route to dns master server)'),
            status_code=500
        )


def new_ddns(name, ip, v6=False, on_api=True):
    """new_ddns formats a dns.update.Update object to add A/AAA
    (and optionally TXT) records for a subdomain and sends it to
    a dns server via dns_query().

    :param name: The subdomain name
    :type name: string.
    :param ip: The new IP address to point to.
    :type ip: string.
    :param v6: If the address to point to is a IPv6 address.
    :type b6: bool.
    :param on_api:
    :type on_api: bool.
    :returns: object -- None on success or JSON response indicating the error.
    """
    new_record = dns.update.Update(
        app.config['DNS_ROOT_DOMAIN'],
        keyring=keyring
    )
    addr = validate_ip(ip, v6=v6)
    if not v6:
        new_record.add(name, app.config['DEFAULT_TTL'], 'A', addr)
    else:
        new_record.add(name, app.config['DEFAULT_TTL'], 'AAAA', addr)
    new_record.absent(name)
    if app.config['ADD_TXT_RECORDS']:
        new_record.add(
            name,
            app.config['DEFAULT_TTL'],
            'TXT',
            ('"Record for '+name+'.'+app.config['DNS_ROOT_DOMAIN']+' last '
             ' updated at '+str(datetime.datetime.utcnow())+' UTC"')
        )
    if dns_query(new_record, on_api):
        return True
    else:
        return False


def update_ddns(subdomain, ip, v6=False, on_api=True):
    """update_ddns formats a dns.update.Update object to update A/AAA
    (and optionally TXT) records for a subdomain and sends it to a dns
    server via dns_query().

    :param name: The subdomain name
    :type name: string.
    :param ip: The new IP address to point to.
    :type ip: string.
    :param v6: If the address to point to is a IPv6 address.
    :type b6: bool.
    :param on_api:
    :type on_api: bool.
    :returns: object -- None on success or JSON response indicating the error.
    """
    # addr = validate_ip(ip, v6=v6)
    addr = ip
    update = dns.update.Update(
        app.config['DNS_ROOT_DOMAIN'],
        keyring=keyring
    )
    update.present(subdomain.name)
    if not v6:
        if validate_ip(ip, v6=False):
            update.replace(subdomain.name, app.config['DEFAULT_TTL'], 'A', addr)
            if app.config['ADD_TXT_RECORDS']:
                update.replace(
                    subdomain.name,
                    app.config['DEFAULT_TTL'],
                    'TXT',
                    ('"Record for '+subdomain.name+'.'+app.config['DNS_ROOT_DOMAIN']+' last '
                     'updated at '+str(datetime.datetime.utcnow())+' UTC"')
                )
        elif validate_ip(ip, v6=True):
            update.delete(subdomain.name)
            update.add(subdomain.name, app.config['DEFAULT_TTL'], 'AAAA', addr)
            if app.config['ADD_TXT_RECORDS']:
                update.add(
                    subdomain.name,
                    app.config['DEFAULT_TTL'],
                    'TXT',
                    ('"Record for '+subdomain.name+'.'+app.config['DNS_ROOT_DOMAIN']+' last '
                     ' updated at '+str(datetime.datetime.utcnow())+' UTC"')
                )
            subdomain.v6 = True
            db.session.commit()
        else:
            if on_api:
                raise LutherBroke('Bad request, invalid IP address')
            else:
                return False
    else:
        if validate_ip(ip, v6=True):
            update.replace(subdomain.name, app.config['DEFAULT_TTL'], 'AAAA', addr)
            if app.config['ADD_TXT_RECORDS']:
                update.replace(
                    subdomain.name,
                    app.config['DEFAULT_TTL'],
                    'TXT',
                    ('"Record for '+subdomain.name+'.'+app.config['DNS_ROOT_DOMAIN']+' last '
                     'updated at '+str(datetime.datetime.utcnow())+' UTC"')
                )
        elif validate_ip(ip, v6=False):
            update.delete(subdomain.name)
            update.add(subdomain.name, app.config['DEFAULT_TTL'], 'A', addr)
            if app.config['ADD_TXT_RECORDS']:
                update.add(
                    subdomain.name,
                    app.config['DEFAULT_TTL'],
                    'TXT',
                    ('"Record for '+subdomain.name+'.'+app.config['DNS_ROOT_DOMAIN']+' last '
                     ' updated at '+str(datetime.datetime.utcnow())+' UTC"')
                )
            subdomain.v6 = False
            db.session.commit()
        else:
            if on_api:
                raise LutherBroke('Bad request, invalid IP address')
            else:
                return False
    if dns_query(update, on_api):
        return True
    else:
        return False


def delete_ddns(name, on_api=True):
    """delete_ddns formats a dns.update.Update object to delete
    the RRSET for a subdomain.

    :param name: The subdomain name
    :type name: string.
    :param on_api:
    :type on_api: bool.
    :returns: object -- None on success or JSON response indicating the error.

    """
    delete = dns.update.Update(app.config['DNS_ROOT_DOMAIN'], keyring=keyring)
    delete.delete(name)
    delete.present(name)
    if dns_query(delete, on_api):
        return True
    else:
        return False

#######################
# Rate limiting logic #
#######################


class RateLimit(object):
    """The RateLimit class implements... well rate limiting!
    (borrowed from http://flask.pocoo.org/snippets/70/ and slightly modified)
    """
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)


def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)


def on_over_limit(limit):
    if not limit.send_x_headers:
        raise LutherBroke(
            ('You have reached the rate limit '
             '(limit: '+str(limit.limit)+', per: '+str(limit.per)+' seconds)'),
            status_code=429
        )
    else:
        raise LutherBroke('You have reached the rate limit', status_code=429)


def ratelimit(limit, per=225,
              send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit \
                    and not g.user.is_admin:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator


@app.after_request
def inject_x_rate_headers(response):
    """inject_x_rate_headers adds rate limiting headers to HTTP responses.

    """
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response

################################
# User/Auth functions + routes #
################################


@app.before_request
def check_user_network():
    """Before request is processed check if the users remote addreses
    is within the configured allowed networks using in_allowed_network().
    """
    if not in_allowed_network(request.remote_addr):
        raise LutherBroke('You are not in an authorized network',
                          status_code=403)

# Somewhat 2822-y email regex...
RFC_2822_REG = ('(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&\'*'
                '+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f!#-[]'
                '-\x7f]|\\[\x01-\t\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9'
                '](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-'
                'z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?'
                ')\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0'
                '-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f!-ZS-\x7f'
                ']|\\[\x01-\t\x0b\\x0c\x0e-\x7f])+)\\])')


def verify_email(email):
    """Verify an email address with RFC 2822 regex
    and optional MX record check.

       :param email: The email to verify.
       :type email: string.
       :returns: bool -- Whether the email is valid.
    """
    if app.config['VALIDATE_USER_EMAIL_MX']:
        def check_mx(email):
            """Check if a MX record exists for provided email.

               :param email: The email to verify.
               :type email: string.
               :returns: bool -- Whether the MX record exists.
            """
            try:
                domain = email.split('@')[-1]
                msg = dns.resolver.query(domain, 'MX')
                if msg:
                    if msg.response and msg.response.rcode() not in [3, 8]:
                        return True
                    elif msg.response and msg.response.rcode() in [1, 2, 4, 5, 6, 7, 8, 9, 10, 16]:
                        raise LutherBroke(
                            ('Internal server error, weird answer to DNS '
                             'MX query'),
                            status_code=500
                        )
                    else:
                        raise LutherBroke('Invalid email address')
                else:
                    raise LutherBroke('Invalid email address')
            except NXDOMAIN:
                raise LutherBroke('Invalid email address, domain has no MX record')
            except NoAnswer:
                raise LutherBroke(
                    'Internal server error, no answer to DNS MX query',
                    status_code=500
                )
            except UnexpectedSource:
                raise LutherBroke(
                    ('Internal server error, response came from '
                     'unexpected source'),
                    status_code=500
                )
            except BadResponse:
                raise LutherBroke(
                    ('Internal server error, malformed response from '
                     'master dns server'),
                    status_code=500
                )
            except TimeoutError:
                raise LutherBroke(
                    ('Gateway timeout, tcp connection to master DNS '
                     'server timed out'),
                    status_code=504
                )
            except OSError:
                raise LutherBroke(
                    ('Internal server error, OSError (most likely no route '
                     'to dns master server)'),
                    status_code=500
                )
    if re.match(RFC_2822_REG, email):
        if app.config['VALIDATE_USER_EMAIL_MX']:
            if check_mx(email):
                return True
            else:
                raise LutherBroke('Internal server error', status_code=500)
        else:
            return True
    else:
        raise LutherBroke('Invalid email address')


@auth.verify_password
def verify_password(email, password):
    """Verify a supplied token or email and password credentials.

    :param email: Users email.
    :type email_or_token: string.
    :param password: The users password.
    :type password: string or None.
    :returns: bool -- Whether the credentials were verified.
    """
    # try to authenticate with username/password
    user = User.query.filter_by(email=email).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


@app.route('/api/v1/user', methods=['POST'])
def new_user():
    """Add a new user, parameters can be passed as
    either JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.
    """
    if request.json and not request.args:
        email = request.json.get('email')
        password = request.json.get('password')
    elif request.args and not request.json:
        email = request.args.get('email')
        password = request.args.get('password')
    else:
        raise LutherBroke('Bad request, no data')
    if email in [None, ''] or password in [None, '']:
        raise LutherBroke('Bad request, missing arguments')
    if not verify_email(email):
        raise LutherBroke('Bad request, invalid email')
    if User.query.filter_by(email=email).first() is not None:
        raise LutherBroke(
            'Conflict in request, existing user',
            status_code=409
        )
    user = User(email=email, quota=app.config['DEFAULT_USER_QUOTA'], role=1)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    resp = jsonify({
        'status': 201,
        'email': user.email,
        'resources': {
            'Subdomains':
            app.config['ROOT_HTTP']+'/api/v1/subdomains',
            'Guess_IP':
            app.config['ROOT_HTTP']+'/api/v1/guess_ip'
        }
    })
    resp.status_code = 201
    return resp


@app.route('/api/v1/user', methods=['DELETE', 'PUT'])
@auth.login_required
def edit_user():
    """Delete an existing user or change it's password, parameters
    can be passed as either JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.
    """
    if request.method == 'DELETE':
        if request.json and not request.args:
            sure = request.json.get('confirm')
        elif request.args:
            sure = request.args.get('confirm')
        else:
            raise LutherBroke('Bad request, no data')
        if sure in [None, ''] or not sure == 'DELETE':
            print(sure)
            raise LutherBroke('Bad request, missing or malformed arguments')
        for d in g.user.subdomains:
            delete_ddns(d.name)
        db.session.delete(g.user)
        g.user = None
        db.session.commit()
        return json_status_message('User deleted, bai bai :<', 200)
    elif request.method == 'PUT':
        if request.json and not request.args:
            password = request.json.get('new_password')
        elif request.args:
            password = request.args.get('new_password')
        else:
            raise LutherBroke('Bad request, no data')
        if password in [None, '']:
            raise LutherBroke('Bad request, missing arguments')
        g.user.hash_password(password)
        db.session.commit()
        return json_status_message('Password updated', 200)

################################
# Domain create / delete route #
################################


@app.route('/api/v1/subdomains', methods=['GET', 'POST', 'DELETE'])
# @ratelimit(limit=100, per=60*60)
@auth.login_required
def domain_mainuplator():
    """Create subdomain, delete subdomain, or get list of users subdomains,
    parameters can be passed as either JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.
    """
    if request.method == 'GET':
        domains = g.user.subdomains if \
            not g.user.is_admin else Subdomain.query.all()
        info = {'email': g.user.email, 'subdomains': []}
        for d in domains:
            info['subdomains'].append({
                'subdomain': d.name,
                'full_domain': d.name+"."+app.config['DNS_ROOT_DOMAIN'],
                'ip': d.ip,
                'subdomain_token': d.token,
                'regenerate_subdomain_token_endpoint': app.config['ROOT_HTTP']+'/api/v1/regen_subdomain_token/'+d.name,
                'GET_update_endpoint': app.config['ROOT_HTTP']+'/api/v1/update/'+d.name+'/'+d.token,
                'last_updated': str(d.last_updated)})
        if len(info['subdomains']) > 0:
            info['status'] = 200
            return jsonify(info)
        else:
            return jsonify({
                'subdomains': [],
                'message': 'You have no '+app.config['ROOT_DOMAIN']+' subdomains',
                'status': 200
                })
    elif request.method == 'POST':
        if Subdomain.query.count() <= app.config['TOTAL_SUBDOMAIN_LIMIT']:
            if g.user.quota is 0 \
                    or not g.user.subdomains.count() == g.user.quota:
                if request.json and not request.args:
                    domain_name = request.json.get('subdomain')
                    ip = request.json.get('ip')
                elif request.args and not request.json:
                    domain_name = request.args.get('subdomain')
                    ip = request.args.get('ip')
                else:
                    raise LutherBroke('Bad request, no data')
                if domain_name in [None, '']:
                    raise LutherBroke('Bad request, missing arguments')
                if Subdomain.query.filter_by(name=domain_name).first():
                    raise LutherBroke('Conflict in request, subdomain already exists', status_code=409)
                if ip in [None, '']:
                    ip = request.remote_addr
                if not validate_subdomain(domain_name):
                    raise LutherBroke('Bad request, invalid subdomain')
                if validate_ip(ip):
                    ipv6 = False
                else:
                    if validate_ip(ip, v6=True):
                        ipv6 = True
                    else:
                        raise LutherBroke('Bad request, IP address invalid or not in allowed subnets')
                new_domain = Subdomain(
                    name=domain_name,
                    ip=ip,
                    v6=ipv6,
                    user=g.user
                )
                new_domain.generate_domain_token()
                ddns_result = new_ddns(domain_name, ip, ipv6)
                if ddns_result:
                    db.session.add(new_domain)
                    db.session.commit()
                    resp = jsonify({
                        'status': 201,
                        'subdomain': domain_name,
                        'full_domain': new_domain.name+"."+app.config['DNS_ROOT_DOMAIN'],
                        'ip': ip,
                        'subdomain_token': new_domain.token,
                        'GET_update_endpoint': app.config['ROOT_HTTP']+'/api/v1/update/'+new_domain.name+'/'+new_domain.token,
                        'last_updated': str(new_domain.last_updated)
                    })
                    resp.status_code = 201
                    return resp
                else:
                    raise LutherBroke()
            else:
                raise LutherBroke(
                    'You have reached your subdomain quota, the subdomain wasn\'t added'
                )
        else:
            raise LutherBroke(
                'Bad request, service subdomain limit reached!'
            )
    elif request.method == 'DELETE':
        if request.json and not request.args:
            domain_name = request.json.get('subdomain')
            confirm = request.json.get('confirm')
        elif request.args and not request.json:
            domain_name = request.args.get('subdomain')
            confirm = request.args.get('confirm')
        else:
            raise LutherBroke('Bad request, no data')
        if domain_name in [None, '']:
            raise LutherBroke('Bad request, missing arguments')
        if not confirm == 'DELETE':
            raise LutherBroke('Bad request, malformed or missing arguments')
        domains = g.user.subdomains if \
            not g.user.is_admin else Subdomain.query.all()
        for d in domains:
            if d.name == domain_name:
                ddns_result = delete_ddns(d.name)
                if ddns_result:
                    db.session.delete(d)
                    db.session.commit()
                    return json_status_message('Subdomain deleted', 200)
                else:
                    raise LutherBroke('Internal server error', status_code=500)
        raise LutherBroke('Bad request, invalid subdomain')


@app.route('/api/v1/regen_subdomain_token/<subdomain_name>', methods=['POST'])
@app.route('/api/v1/regen_subdomain_token', methods=['POST'])
# @ratelimit(limit=100, per=60*60)
@auth.login_required
def regen_subdomain_token(subdomain_name=None):
    """Regenerate subdomain token, parameters can be passed as either
    JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.
    """
    if request.json and not request.args and not subdomain_name:
        domain_name = request.json.get('subdomain')
    elif request.args and not request.json and not subdomain_name:
        domain_name = request.args.get('subdomain')
    elif subdomain_name and not request.json and not request.args:
        domain_name = subdomain_name
    else:
        raise LutherBroke('Bad request, no data')
    if domain_name in [None, '']:
        raise LutherBroke('Bad request, missing arguments')
    domains = g.user.subdomains if \
        not g.user.is_admin else Subdomain.query.all()
    for d in domains:
        if domain_name == d.name:
            d.generate_domain_token()
            db.session.commit()
            return jsonify({
                'status': 200,
                'subdomain': d.name,
                'full_domain': d.name+"."+app.config['DNS_ROOT_DOMAIN'],
                'ip': d.ip,
                'subdomain_token': d.token,
                'GET_update_endpoint': app.config['ROOT_HTTP']+'/api/v1/update/'+d.name+'/'+d.token,
                'last_updated': str(d.last_updated),
                'message': 'Subdomain token regenerated'
            })
    raise LutherBroke('Bad request, invalid subdomain')

#################################
# JSON / URL param update route #
#################################


@app.route('/api/v1/update', methods=['POST'])
# @ratelimit(limit=100, per=60*60)
def fancy_interface():
    """The fancy interface for updating subdomain IP addresses,
    this is the only for a user to update multiple subdomains
    at once. Parameters can be passed as either JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.
    """
    if request.json and not request.args:
        domain_list = []
        if request.json.get('subdomains'):
            for d in request.json.get('subdomains'):
                if d.get('subdomain') in ['', None] or d.get('subdomain_token') in ['', None]:
                    raise LutherBroke(
                        'Bad request, missing or malformed arguments111'
                    )
                if not d.get('ip'):
                    d['ip'] = request.remote_addr
                domain_list.append([d['subdomain'], d['subdomain_token'], d['ip']])
        else:
            raise LutherBroke(
                'Bad request, missing or malformed arguments'
            )
    elif request.args and not request.json:
        domain_list = []
        names = request.args.get('subdomains')
        tokens = request.args.get('subdomain_tokens')
        ips = request.args.get('addresses')
        if names in ['', None] or tokens in ['', None]:
            raise LutherBroke('Bad request, missing or malformed arguments')
        names = names.split(',')
        tokens = tokens.split(',')
        if ips:
            ips = ips.split(',')
        if len(names) is not len(tokens) or len(ips) > len(names):
            raise LutherBroke('Bad request, malformed arguments')
        for i in range(len(names)):
            if len(ips)-1 <= i:
                if ips[i] == '':
                    ips[i] = request.remote_addr
                domain_list.append([names[i], tokens[i], ips[i]])
            else:
                domain_list.append([names[i], tokens[i], request.remote_addr])
    else:
        raise LutherBroke('Bad request, no data')
    if not len(domain_list) > 0:
        raise LutherBroke()
    results = []
    for domain_obj in domain_list:
        domain = Subdomain.query.filter_by(name=domain_obj[0]).first()
        if domain and domain.verify_domain_token(domain_obj[1]):
            if domain_obj[2] == domain.ip:
                results.append({
                    'status': 200,
                    'subdomain': domain.name,
                    'full_domain': domain.name+"."+app.config['DNS_ROOT_DOMAIN'],
                    'ip': domain.ip,
                    'subdomain_token': domain.token,
                    'GET_update_endpoint': app.config['ROOT_HTTP']+'/api/v1/update/'+domain.name+'/'+domain.token,
                    'last_updated': str(domain.last_updated),
                    'message': 'Nothing to do, supplied IP is the same as current IP.'})
            else:
                if domain.v6:
                    ddns_result = update_ddns(
                        domain,
                        domain_obj[2],
                        v6=True
                    )
                else:
                    ddns_result = update_ddns(domain, domain_obj[2])
                if ddns_result:
                    domain.ip = domain_obj[2]
                    db.session.commit()
                    results.append({
                        'status': 200,
                        'subdomain': domain.name,
                        'full_domain': domain.name+"."+app.config['DNS_ROOT_DOMAIN'],
                        'ip': domain.ip,
                        'subdomain_token': domain.token,
                        'GET_update_endpoint': app.config['ROOT_HTTP']+'/api/v1/update/'+domain.name+'/'+domain.token,
                        'last_updated': str(domain.last_updated),
                        'message': 'Subdomain updated.'})
                else:
                    raise LutherBroke()
        else:
            raise LutherBroke('Bad request, invalid subdomain or token')
    if len(results) > 0:
        return jsonify({'status': 200, 'subdomains': results})
    else:
        raise LutherBroke('Internal server error', status_code=500)

#########################
# GET only update route #
#########################


@app.route(
    '/api/v1/update/<domain_name>/<domain_token>/<domain_ip>',
    methods=['GET']
)
@app.route(
    '/api/v1/update/<domain_name>/<domain_token>',
    methods=['GET']
)
# @ratelimit(limit=100, per=60*60)
def get_interface(domain_name, domain_token, domain_ip=None):
    """The (stone age) GET interface for updating a single subdomain
    IP address.

    :param domain_name: The subdomain name to update.
    :type domain_name: string.
    :param domain_token: The authentication token for the subdomain.
    :type domain_token: string.
    :param domain_ip: The IP address point to.
    :type domain_ip: string.
    :returns: object -- JSON response indicating the outcome of action.
    """
    domain = Subdomain.query.filter_by(name=domain_name).first()
    if domain and domain.verify_domain_token(domain_token):
        if domain_ip in [None, '']:
            domain_ip = request.remote_addr
        if domain_ip == domain.ip:
            return jsonify({
                'status': 200,
                'subdomain': domain.name,
                'full_domain': domain.name+"."+app.config['DNS_ROOT_DOMAIN'],
                'ip': domain.ip,
                'subdomain_token': domain.token,
                'GET_update_endpoint': app.config['ROOT_HTTP']+'/api/v1/update/'+domain.name+'/'+domain.token,
                'last_updated': str(domain.last_updated),
                'message': 'Nothing to do, supplied IP is the same as current IP.'
            })
        else:
            if domain.v6:
                ddns_result = update_ddns(domain, domain_ip, v6=True)
            else:
                ddns_result = update_ddns(domain, domain_ip)
            if ddns_result:
                domain.ip = domain_ip
                db.session.commit()
                return jsonify({
                    'status': 200,
                    'subdomain': domain.name,
                    'full_domain': domain.name+"."+app.config['DNS_ROOT_DOMAIN'],
                    'ip': domain.ip,
                    'subdomain_token': domain.token,
                    'GET_update_endpoint': app.config['ROOT_HTTP']+'/api/v1/update/'+domain.name+'/'+domain.token,
                    'last_updated': str(domain.last_updated),
                    'message': 'Subdomain updated.'
                })
            else:
                raise LutherBroke()
    else:
        raise LutherBroke('Bad request, invalid domain or token')

################
# GET IP route #
################


@app.route('/api/v1/geuss_ip', methods=['GET'])
def get_ip():
    """Return the IP used to request the endpoint.

    :returns: string -- The IP address used to request the endpoint.
    """
    return jsonify({'guessed_ip': request.remote_addr, 'status': 200})

###################
# luther frontend #
###################


if app.config['ENABLE_FRONTEND']:
    @app.route('/')
    def index():
        # results = {'users': [], 'subdomains': [], 'subdomain_limit': [], 'updates': []}
        if app.config['ENABLE_STATS']:
            stats = predis.get('luther/stats')
        else:
            stats = None
        # for a, b in stats['users']:
        #     results['users'].append([str(a), b])
        # for a, b in stats['subdomains']:
        #     results['subdomains'].append([str(a), b])
        # for a, b in stats['subdomain_limit']:
        #     results['subdomain_limit'].append([str(a), b])
        # for a, b in stats['updates']:
        #     results['updates'].append([str(a), b])
        return render_template(
            'luther.html',
            client_ip=request.remote_addr,
            luther_stats=stats # results
        )

if app.config['ENABLE_STATS']:
    import threading
    import pickle
    from redis import StrictRedis

    class PickledRedis(StrictRedis):
        def get(self, name):
            pickled_value = super(PickledRedis, self).get(name)
            if pickled_value in [None, '']:
                return None
            return pickle.loads(pickled_value)

        def set(self, name, value, ex=None, px=None, nx=False, xx=False):
            return super(PickledRedis, self).set(
                name,
                pickle.dumps(value),
                ex,
                px,
                nx,
                xx
            )

    predis = PickledRedis(
        host=app.config['REDIS_HOST'],
        port=app.config['REDIS_PORT']
    )

    def update_stats():
        threading.Timer(app.config['STATS_INTERVAL'], update_stats).start()
        with app.app_context():
            stats = predis.get('luther/stats')
            now = str(datetime.datetime.utcnow())
            if not stats:
                stats = {
                    'users': [],
                    'subdomains': [],
                    'subdomain_limit': [],
                    'updates': []
                }

            if len(stats['users']) >= app.config['STATS_ENTRIES']:
                stats['users'].pop(0)
                stats['subdomains'].pop(0)
                stats['subdomain_limit'].pop(0)
                stats['updates'].pop(0)
            stats['users'].append([now, User.query.count()])
            stats['subdomains'].append([now, Subdomain.query.count()])
            stats['subdomain_limit'].append([
                now,
                app.config['TOTAL_SUBDOMAIN_LIMIT']
            ])
            if len(stats['updates']) > 0:
                last_update = datetime.datetime.strptime(stats['updates'][-1][0], '%Y-%m-%d %H:%M:%S.%f')
                stats['updates'].append([
                    now,
                    Subdomain.query.filter(
                        Subdomain.last_updated > last_update
                    ).count()
                ])
            else:
                stats['updates'].append([now, 0])
            predis.set('luther/stats', stats)
