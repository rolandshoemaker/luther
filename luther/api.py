##################
# luther imports #
##################

import config
from models import db, User, Subdomain

#################
# flask imports #
#################

from flask import Flask, g, request, jsonify, render_template
from flask.ext.httpauth import HTTPBasicAuth

#################
# other imports #
#################

import dns.query, dns.tsigkeyring, dns.update
from dns.query import UnexpectedSource, BadResponse
from redis import Redis
import time
from functools import update_wrapper
import ipaddress
import re
import datetime

##############################
# flask + plugin object init #
##############################

app = Flask(__name__)

app.config['SECRET_KEY'] = config.secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = config.db

auth = HTTPBasicAuth()

db.init_app(app)

redis = Redis()

keyring = dns.tsigkeyring.from_text({
    config.tsig_zone: config.tsig_key
})

##################
# luther logging #
##################

if not app.debug:
    import logging, logging.handlers
    from logging import Formatter
    fh = logging.handlers.RotatingFileHandler(config.log_file_path, maxBytes=config.log_max_bytes, backupCount=config.log_backup_count) # maybe timedrotating?
    fh.setLevel(logging.WARNING)
    fh.setFormatter(Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    loggers = [app.logger] # , getLogger('sqlalchemy')]
    for logger in loggers:
        logger.addHandler(fh)

##################
# Util functions #
##################

def validate_ip(ip, v6=False):
    """validate_ip uses the ipaddress library to validate IPv4 and IPv6 Addresses.

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
        if not v6:
            for subnet in config.allowed_ddns_ipv4_subnets:
                if test in ipaddress.IPv4Network(subnet):
                    correct_subnet = True
        else:
            for subnet in config.allowed_ddns_ipv6_subnets:
                if test in ipaddress.IPv6Network(subnet):
                    correct_subnet = True
        if (test.is_private and not config.allow_private_addresses) or not correct_subnet:
            return False
        return test.exploded
    except ipaddress.AddressValueError:
        return False

def in_allowed_network(ip, v4_networks=config.allowed_user_v4_subnets, v6_networks=config.allowed_user_v6_subnets):
    """in_allowed_network tests whether an IP Address is within a list of defined networks (v4/v6).

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

def validate_subdomain(subdomain):
    """validate_subdomain checks to see if a subdomain is valid and not in a list of restricted names.

    :param subdomain: The subdomain to test.
    :type subdomain: string.
    :returns: bool -- If the subdomain is valid and not restricted.

    """
    if re.match('^[0-9a-z-]{'+str(config.min_subdomain_length)+','+str(config.max_subdomain_length)+'}$', subdomain, re.IGNORECASE) and subdomain not in config.restricted_subdomains:
        return True
    else:
        return False

def json_status_message(message, code, extra=''):
    """json_status_message builds a JSON status response with assosiated HTTP status code, and extra stuff if you want.

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
    status_code = 400
    message = 'Bad request'

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = 403 if status_code == 401 and config.enable_frontend else status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

@app.errorhandler(LutherBroke)
def handle_broken(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

#################
# DNS functions #
#################

def dns_message_check(msg, on_api):
    """dns_message_check checks the rcode of a dns.message.Message response.

    :param msg: The dns.message.Message object.
    :type msg: object.
    :returns: object -- None on success or a internal_error() JSON response based on the rcode.
    
    """
    rcode_errors = {1: 'malformed dns message',
        2: '',
        3: 'subdomain does not exist on master dns server',
        4: 'master dns server does not support that opcode',
        5: 'master dns server refuses to perform the specified operation for policy or security reasons',
        6: 'subdomain already exists on master dns server',
        7: 'record that shouldnt exist does exist',
        8: 'record that should exist doesnt exist',
        9: 'server is not authorized or is using bad tsig key to make updates to zone \''+config.tsig_zone+'\' on master dns server',
        10: 'zone \''+config.tsig_zone+'\' does not exist on master dns server',
        16: ''}
    error_info = rcode_errors.get(msg.rcode())
    if error_info is not None:
        if error_info is not '':
            error_info = ', '+error_info
        if on_api:
            raise LutherBroke('Internal server error'+error_info, status_code=500)
        else:
            return False
    else:
        return True

def dns_query(update, on_api, server=config.dns_master_server, port=config.dns_master_port, source_port=config.dns_master_source_port, timeout=config.dns_master_timeout):
    """dns_query sends dns.update.Update objects to a dns server and parses the response.

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
        resp = dns.query.tcp(update, server, port=port, source_port=source_port, timeout=timeout)
        if dns_message_check(resp, on_api):
            return True
    except UnexpectedSource:
        raise LutherBroke('Internal server error, response came from unexpected source', status_code=500)
    except BadResponse:
        raise LutherBroke('Internal server error, malformed response from master dns server', status_code=500)
    except TimeoutError:
        raise LutherBroke('Gateway timeout, tcp connection to master DNS server timed out', status_code=504)
    except OSError:
        raise LutherBroke('Internal server error, OSError (most likely no route to dns master server)', status_code=500)

def new_ddns(name, ip, v6=False, on_api=True):
    """new_ddns formats a dns.update.Update object to add A/AAA (and optionally TXT) records for a subdomain and sends it to a dns server via dns_query().

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
    new_record = dns.update.Update(config.dns_root_domain, keyring=keyring)
    addr = validate_ip(ip, v6=v6)
    if not v6:
        new_record.add(name, config.default_ttl, 'A', addr)
        if config.add_txt_records:
            new_record.add(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
    else:
        new_record.add(name, config.default_ttl, 'AAAA', addr)
        if config.add_txt_records:
            new_record.add(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
    new_record.absent(name)
    if dns_query(new_record, on_api):
        return True
    else:
        return False

def update_ddns(name, ip, v6=False, on_api=True):
    """update_ddns formats a dns.update.Update object to update A/AAA (and optionally TXT) records for a subdomain and sends it to a dns server via dns_query().

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
    addr = validate_ip(ip, v6=v6)
    if addr:
        update = dns.update.Update(config.dns_root_domain, keyring=keyring)
        if not v6:
            update.replace(name, config.default_ttl, 'A', addr)
            if config.add_txt_records:
                update.replace(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
        else:
            update.replace(name, config.default_ttl, 'AAAA', addr)
            if config.add_txt_records:
                update.replace(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
        if dns_query(update, on_api):
            return True
        else:
            return False
    else:
        if on_api:
            if not v6:
                raise LutherBroke('Bad request, invalid IPv4 address')
            else:
                raise LutherBroke('Bad request, invalid IPv6 address')
        else:
            return False

def delete_ddns(name, on_api=True):
    """delete_ddns formats a dns.update.Update object to delete the RRSET for a subdomain.

    :param name: The subdomain name
    :type name: string.
    :param on_api:
    :type on_api: bool.
    :returns: object -- None on success or JSON response indicating the error.

    """
    delete = dns.update.Update(config.dns_root_domain, keyring=keyring)
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
    """The RateLimit class implements... well rate limiting! (borrowed from http://flask.pocoo.org/snippets/70/ and slightly modified)

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
        raise LutherBroke('You have reached the rate limit (limit: '+str(limit.limit)+', per: '+str(limit.per)+' seconds)', status_code=429)
    else:
        raise LutherBroke('You have reached the rate limit', status_code=429)

def ratelimit(limit, per=225, send_x_headers=True,
    over_limit=on_over_limit,
    scope_func=lambda: request.remote_addr,
    key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit and not g.user.role is 0:
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
    """Before request is processed check if the users remote addreses is within the configured allowed networks using in_allowed_network().

    """
    if not in_allowed_network(request.remote_addr):
        raise LutherBroke('You are not in an authorized network', status_code=403)

@auth.verify_password
def verify_password(email_or_token, password=None):
    """Verify a supplied token or email and password credentials.

    :param email_or_token: Users email or an authentication token from /api/v1/auth_token.
    :type email_or_token: string.
    :param password: The users password.
    :type password: string or None.
    :returns: bool -- Whether the credentials were verified.

    """
    # first try to authenticate by token
    user = User.verify_auth_token(email_or_token)
    if not user:
        if password:
            # try to authenticate with username/password
            user = User.query.filter_by(email=email_or_token).first()
            if not user or not user.verify_password(password):
                return False
        else:
            return False
    g.user = user
    return True

# @app.route('/api/v1/auth_token')
# @auth.login_required
# def get_auth_token():
#     """Generate or retrieve an authentication that can be used instead of email/password credentials to authenticate.

#     :returns: string -- The users current authentication token.

#     """
#     token = g.user.generate_auth_token()
#     return jsonify({'status': 201, 'token': token.decode('ascii')})

@app.route('/api/v1/user', methods=['POST'])
def new_user():
    """Add a new user, parameters can be passed as either JSON or URL arguments.

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
    if email is None or password is None:
        raise LutherBroke('Bad request, missing arguments') # missing arguments
    if User.query.filter_by(email=email).first() is not None:
        raise LutherBroke('Conflict in request, existing user', status_code=409) # existing user
    user = User(email=email, quota=config.default_user_quota, role=1)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    resp = jsonify({'status': 201, 'email': user.email, 'resources': {'Subdomains': {'url': 'https://'+config.root_domain+'/api/v1/subdomains'}, 'Subdomain updates': 'https://'+config.root_domain+'/api/v1/update'}})
    resp.status_code = 201
    return resp

@app.route('/api/v1/user', methods=['DELETE', 'POST'])
@auth.login_required
def edit_user():
    """Delete an existing user or change it's password, parameters can be passed as either JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.

    """
    if request.method == 'DELETE':
        if request.json and not request.args:
            sure = request.json.get('confirm')
        elif request.args:
            sure = request.args.get('confirm')
        else:
            raise LutherBroke('Bad request, no data')
        if sure is None or sure is not 'DELETE':
            raise LutherBroke('Bad request, missing or malformed arguments')
        for d in g.user.subdomains:
            delete_ddns(d.name)
        db.session.delete(g.user)
        g.user = None
        db.session.commit()
        return json_status_message('User deleted, bai bai :<', 200)
    elif request.method == 'POST':
        if request.json and not request.args:
            password = request.json.get('new_password')
        elif request.args:
            password = request.args.get('new_password')
        else:
            raise LutherBroke('Bad request, no data')
        if password is None:
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
    """Create subdomain, delete subdomain, or get list of users subdomains, parameters can be passed as either JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.

    """
    if request.method == 'GET':
        if g.user.role is 1:
            domains = g.user.subdomains
        else:
            domains = Subdomain.query.all()
        info = {'email': g.user.email, 'subdomains': []}
        for d in domains:
            info['subdomains'].append({'subdomain': d.name, 'full_domain': d.name+"."+config.root_domain, 'ip': d.ip, 'subdomain_token': d.token, 'regenerate_subdomain_token_endpoint': 'https://'+config.root_domain+'/api/v1/regen_subdomain_token/'+d.name, 'GET_update_endpoint': 'https://'+config.root_domain+'/api/v1/update/'+d.name+'/'+d.token, 'last_updated': str(d.last_updated)})
        if len(info['subdomains']) > 0:
            resp = jsonify(info)
            resp.status_code = 200
            return resp
        else:
            return jsonify({'subdomains': [], 'message': 'You have no '+config.root_domain+' subdomains', 'status': 200})
    elif request.method == 'POST':
        if Subdomain.query.count() <= config.total_subdomain_limit:
            if g.user.quota is 0 or not g.user.subdomains.count() == g.user.quota:
                if request.json and not request.args:
                    domain_name = request.json.get('subdomain')
                    ip = request.json.get('ip')
                elif request.args and not request.json:
                    domain_name = request.args.get('subdomain')
                    ip = request.args.get('ip')
                else:
                    raise LutherBroke('Bad request, no data')
                print(request.json)
                if not domain_name:
                    raise LutherBroke('Bad request, missing arguments')
                if not ip:
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
                new_domain = Subdomain(name=domain_name, ip=ip, v6=ipv6, user=g.user)
                new_domain.generate_domain_token()
                ddns_result = new_ddns(domain_name, ip, ipv6)
                if ddns_result:
                    db.session.add(new_domain)
                    db.session.commit()
                    return jsonify({'status': 201, 'subdomain': domain_name, 'full_domain': new_domain.name+"."+config.root_domain, 'ip': ip, 'subdomain_token': new_domain.token, 'GET_update_endpoint': 'https://'+config.root_domain+'/api/v1/update/'+new_domain.name+'/'+new_domain.token, 'last_updated': str(new_domain.last_updated)})
                else:
                    raise LutherBroke()
            else:
                return json_status_message('You have reached your subdomain quota', 200)
        else:
            raise LutherBroke('Bad request, service subdomain limit reached!') # prob wrong error...
    elif request.method == 'DELETE':
        if request.json and not request.args:
            domain_name = request.json.get('subdomain')
            domain_token = request.json.get('subdomain_token')
        elif request.args and not request.json:
            domain_name = request.args.get('subdomain')
            domain_token = request.args.get('subdomain_token')
        else:
            raise LutherBroke('Bad request, no data')
        if not domain_name or not domain_token:
            raise LutherBroke('Bad request, missing arguments')
        if not validate_subdomain(domain_name):
            raise LutherBroke('Bad request, invalid subdomain')
        sub_iterator = g.user.subdomains if g.user.role is 1 else Subdomain.query.all()
        for d in sub_iterator:
            if d.name == domain_name:
                if d.verify_domain_token(domain_token):
                    ddns_result = delete_ddns(d.name)
                    if ddns_result:
                        db.session.delete(d)
                        db.session.commit()
                        return json_status_message('Subdomain deleted', 200)
                    else:
                        raise LutherBroke()
                else:
                    raise LutherBroke('Bad request, invalid subdomain_token')
        raise LutherBroke('Bad request, invalid subdomain')

@app.route('/api/v1/regen_subdomain_token/<subdomain_name>/', methods=['POST'])
# @ratelimit(limit=100, per=60*60)
@auth.login_required
def regen_subdomain_token(subdomain_name=None):
    """Regenerate subdomain token, parameters can be passed as either JSON or URL arguments.

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
    if not domain_token or not domain_name:
        raise LutherBroke('Bad request, missing arguments')
    for d in g.user.domains:
        if domain_name is d.name:
            d.generate_domain_token()
            db.session.commit()
            return jsonify({'status': 200, 'subdomain': d.name, 'full_domain': d.name+"."+config.root_domain, 'ip': d.ip,  'subdomain_token': d.token, 'GET_update_endpoint': 'https://'+config.root_domain+'/api/v1/update/'+d.name+'/'+d.token, 'last_updated': str(d.last_updated), 'message': 'Subdomain token regenerated.'})
        else:
            raise LutherBroke('Bad request, invalid subdomain')

#################################
# JSON / URL param update route #
#################################

@app.route('/api/v1/update', methods=['POST'])
# @ratelimit(limit=100, per=60*60)
def fancy_interface():
    """The fancy interface for updating subdomain IP addresses, this is the only for a user to update multiple subdomains at once. Parameters can be passed as either JSON or URL arguments.

    :returns: object -- JSON response indicating the outcome of action.

    """
    if request.json and not request.args:
        domain_list = []
        for d in request.json:
            if not d.name or not d.token:
                raise LutherBroke('Bad request, missing or malformed arguments')
            if not d.get('address'):
                d['address'] = request.remote_addr
            domain_list.append([d.name, d.token, d['address']])
    elif request.args and not request.json:
        domain_list = []
        names = request.args.get('names')
        tokens = request.args.get('tokens')
        ips = request.args.get('addresses')
        if not names or not tokens:
            raise LutherBroke('Bad request, missing or malformed arguments')
        names = names.split(',')
        tokens = tokens.split(',')
        if len(names) is not len(tokens) or len(ips) > len(names):
            raise LutherBroke('Bad request, malformed arguments')
        if ips:
            ips = ips.split(',')
        for i in range(len(names)):
            if len(ips) <= i:
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
                results.append({'status': 200, 'subdomain': domain.name, 'full_domain': domain.name+"."+config.root_domain, 'ip': domain.ip,  'subdomain_token': domain.token, 'GET_update_endpoint': 'https://'+config.root_domain+'/api/v1/update/'+domain.name+'/'+domain.token, 'last_updated': str(domain.last_updated), 'message': 'Nothing to do, supplied IP is the same as current IP.'})
            else:
                if domain.v6:
                    ddns_result = update_ddns(domain.name, domain_obj[2], v6=True)
                else:
                    ddns_result = update_ddns(domain.name, domain_obj[2])
                if ddns_result:
                    domain.ip = domain_obj[2]
                    db.session.commit()
                    results.append({'status': 200, 'subdomain': domain.name, 'full_domain': domain.name+"."+config.root_domain, 'ip': domain.ip,  'subdomain_token': domain.token, 'GET_update_endpoint': 'https://'+config.root_domain+'/api/v1/update/'+domain.name+'/'+domain.token, 'last_updated': str(domain.last_updated), 'message': 'Subdomain updated.'})
                else:
                    raise LutherBroke()
        else:
            raise LutherBroke('Bad request, invalid subdomain or token')
    if len(results) > 0:
        return jsonify({'results': [results]})
    else:
        raise LutherBroke('Internal server error', status_code=500)

#########################
# GET only update route #
#########################

@app.route('/api/v1/update/<domain_name>/<domain_token>/<domain_ip>', methods=['GET'])
# @ratelimit(limit=100, per=60*60)
def get_interface(domain_name, domain_token, domain_ip=None):
    """The (stone age) GET interface for updating a single subdomain IP address.

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
        if domain_ip is None:
            domain_ip = request.remote_addr
        if domain_ip == domain.ip:
            return jsonify({'status': 200, 'subdomain': domain.name, 'full_domain': domain.name+"."+config.root_domain, 'ip': domain.ip,  'subdomain_token': domain.token, 'GET_update_endpoint': 'https://'+config.root_domain+'/api/v1/update/'+domain.name+'/'+domain.token, 'last_updated': str(domain.last_updated), 'message': 'Nothing to do, supplied IP is the same as current IP.'})
        else:
            if domain.v6:
                ddns_result = update_ddns(domain.name, domain_ip, v6=True)
            else:
                ddns_result = update_ddns(domain.name, domain_ip)
            if ddns_result:
                domain.ip = domain_ip
                db.session.commit()
                return jsonify({'status': 200, 'subdomain': domain.name, 'full_domain': domain.name+"."+config.root_domain, 'ip': domain.ip,  'subdomain_token': domain.token, 'GET_update_endpoint': 'https://'+config.root_domain+'/api/v1/update/'+domain.name+'/'+domain.token, 'last_updated': str(domain.last_updated), 'message': 'Subdomain updated.'})
            else:
                raise LutherBroke()
    else:
        raise LutherBroke('Bad request, invalid domain or token')

###################
# luther frontend #
###################

if config.enable_frontend:
    @app.route('/')
    def index():
        return render_template('luther.html', client_ip=request.remote_addr)

    if config.enable_stats:
        import threading, pickle
        from redis import StrictRedis

        class PickledRedis(StrictRedis):
            def get(self, name):
                pickled_value = super(PickledRedis, self).get(name)
                if pickled_value is None:
                    return None
                return pickle.loads(pickled_value)

            def set(self, name, value, ex=None, px=None, nx=False, xx=False):
                return super(PickledRedis, self).set(name, pickle.dumps(value), ex, px, nx, xx)

        predis = PickledRedis(host=config.redis_host, port=config.redis_port)

        def update_stats():
            threading.Timer(config.stats_interval, update_stats).start()
            with app.app_context():
                stats = predis.get('luther/stats')
                now = datetime.datetime.now()
                if not stats:
                    stats = {'users': [], 'subdomains': []}
                if (len(stats['users'])+len(stats['subdomains']))/2 >= config.stats_entries:
                    stats['users'].pop(0)
                    stats['subdomains'].pop(0)
                stats['users'].append([now, User.query.count()])
                stats['subdomains'].append([now, Subdomain.query.count()])
                predis.set('luther/stats', stats)

        update_stats()

        @app.route('/stats')
        def stats():
            stats = predis.get('luther/stats')
            return render_template('stats.html')

##############
# Dev server #
##############

if __name__ == '__main__':
    app.debug = True
    # with app.app_context():
    #     db.create_all()
    #     admin = User(email='admin', role=0, quota=0)
    #     admin.hash_password(config.default_admin_password)
    #     db.session.add(admin)
    #     db.session.commit()
    app.run(use_reloader=True, host='192.168.1.8', port=80)