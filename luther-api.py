##################
# luther imports #
##################

import config
from models import db, User, Domain

#################
# flask imports #
#################

from flask import Flask, g, request, jsonify, abort
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

##################
# Util functions #
##################

def validate_ip(ip, v6=False):
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

def in_allowed_network(ip):
	in_net = False
	try:
		for subnet in config.allowed_user_v4_subnets:
			if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(subnet):
				in_net = True
		for subnet in config.allowed_user_v6_subnets:
			if ipaddress.IPv6Address(ip) in ipaddress.IPv6Network(subnet):
				in_net = True
	except ipaddress.AddressValueError:
		return False
	return in_net

def validate_subdomain(subdomain):
	if re.match('^[0-9a-z][0-9a-z-]{1,18}[0-9a-z]$', subdomain, re.IGNORECASE) and subdomain not in config.restricted_subdomains:
		return True
	else:
		return False

def json_status_message(message, code, extra=''):
	if extra is not '':
		extra = ', '+extra
	message = {'status': code, 'message': message+extra}
	resp = jsonify(message)
	resp.status_code = code
	return resp

########################
# Error handler routes #
########################

@app.errorhandler(400)
def bad_request(error=None, extra=''):
	return json_status_message('Bad request', 400, extra)

@app.errorhandler(404)
def not_found(error=None, extra=''):
	return json_status_message('Not found', 404, extra)

@app.errorhandler(405)
def method_not_allowed(error=None, extra=''):
	return json_status_message('Method not allowed', 405, extra)

@app.errorhandler(409)
def conflict(error=None, extra=''):
	return json_status_message('Conflict in request', 409, extra)

def nothing_to_do(error=None, extra=''):
	return json_status_message('Nothing to do', 200, extra)

@app.errorhandler(204)
def no_content(error=None, extra=''):
	return json_status_message('No content', 204, extra)

@app.errorhandler(401)
def unauthorized(error=None, extra=''):
	return json_status_message('Unauthorized', 401, extra)

@app.errorhandler(403)
def forbidden(error=None, extra=''):
	return json_status_message('Forbidden', 403, extra)

@app.errorhandler(500)
def internal_error(error=None, extra=''):
	return json_status_message('Internal server error', 500, extra)

@app.errorhandler(504)
def upstream_timeout(error=None, extra=''):
	return json_status_message('Gateway timeout', 504, extra)

#########################
# DNS setup + functions #
#########################

def rcode_check(rcode):
	if rcode == 0: # NOERROR
		return False
	elif rcode == 1: # FORMERR
		pass
	elif rcode == 2: # SERVFAIL
		pass
	elif rcode == 3: # NXDOMAIN
		return bad_request('subdomain does not exist on master dns server')
	elif rcode == 4: # NOTIMP
		pass
	elif rcode == 5: # REFUSED
		pass
	elif rcode == 6: # YXDOMAIN
		return bad_request('subdomain already exists on master dns server')
	elif rcode == 7: # YXRRSET
		pass
	elif rcode == 8: # NXRRSET
		pass
	elif rcode == 9: # NOTAUTH
		return unauthorized('server is not authorized to make updates to zone \''+config.tsig_zone+'\' on master dns server')
	elif rcode == 10: # NOTZONE
		pass
	elif rcode == 16: # BADVERS
		pass

keyring = dns.tsigkeyring.from_text({
	config.tsig_zone: config.tsig_key
})

def update_ddns(name, ip, v6=False):
	addr = validate_ip(ip, v6=v6)
	if addr:
		update = dns.update.Update(config.root_domain, keyring=keyring)
		if not v6:
			update.replace(name, config.default_ttl, 'A', addr)
			update.replace(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
		else:
			update.replace(name, config.default_ttl, 'AAAA', addr)
			update.replace(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
		try:
			resp = dns.query.tcp(update, config.dns_master_server, port=config.dns_master_port, source_port=config.dns_master_source_port, timeout=config.dns_master_timeout)
			error = rcode_check(resp.rcode)
			if error:
				return error
		except UnexpectedSource:
			return bad_request()
		except BadResponse:
			return bad_request()
		except TimeoutError:
			return upstream_timeout(extra='tcp connection to master DNS server timed out')
	else:
		if not v6:
			return 'invalid IPv4 address'
		else:
			return 'invalid IPv6 address'

def new_ddns(name, ip, v6=False):
	new_record = dns.update.Update(config.root_domain, keyring=keyring)
	if not v6:
		new_record.add(name, config.default_ttl, 'A', ip)
		new_record.add(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
	else:
		new_record.add(name, config.default_ttl, 'AAAA', ip)
		new_record.add(name, config.default_ttl, 'TXT', '"Record for '+name+'.'+config.root_domain+' last updated at '+str(datetime.datetime.utcnow())+' UTC"')
	new_record.absent(name)
	try:
		resp = dns.query.tcp(new_record, config.dns_master_server, port=config.dns_master_port, source_port=config.dns_master_source_port, timeout=config.dns_master_timeout)
		error = rcode_check(resp.rcode)
		if error:
			return error
	except UnexpectedSource:
		return bad_request()
	except BadResponse:
		return bad_request()
	except TimeoutError:
		return upstream_timeout(extra='tcp connection to master DNS server timed out')

def delete_ddns(name):
	delete = dns.update.Update(config.root_domain, keyring=keyring)
	delete.delete(name)
	delete.present(name)
	try:
		resp = dns.query.tcp(delete, config.dns_master_server, port=config.dns_master_port, source_port=config.dns_master_source_port, timeout=config.dns_master_timeout)
		error = rcode_check(resp.rcode)
		if error:
			return error
	except UnexpectedSource:
		return bad_request()
	except BadResponse:
		return bad_request()
	except TimeoutError:
		return upstream_timeout(extra='tcp connection to master DNS server timed out')

#######################
# Rate limiting logic #
#######################

redis = Redis()

class RateLimit(object):
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
			return json_status_message('You  have reached the rate limit (limit: '+str(limit.limit)+', per: '+str(limit.per)+' seconds)', 429)
		else:
			return json_status_message('You  have reached the rate limit', 429)

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
def before_request():
	if not in_allowed_network(request.remote_addr):
		return abort(403)

@auth.verify_password
def verify_password(email_or_token, password):
	user = User.verify_auth_token(email_or_token)
	if not user:
		user = User.query.filter_by(email=email_or_token).first()
		if not user or not user.verify_password(password):
			return False
	g.user = user
	return True

@app.route('/api/v1/auth_token')
@auth.login_required
def get_auth_token():
	token = g.user.generate_auth_token()
	return jsonify({'status': 201, 'token': token.decode('ascii')})

@app.route('/api/v1/user', methods = ['POST'])
def new_user():
	if request.json and not request.args:
		email = request.json.get('email')
		password = request.json.get('password')
	elif request.args and not request.json:
		email = request.args.get('email')
		password = request.args.get('password')
	else:
		return bad_request('no JSON data or URL Parameters, or both')
	if email is None or password is None:
		return bad_request('missing arguments') # missing arguments
	if User.query.filter_by(email = email).first() is not None:
		return conflict('existing user') # existing user
	user = User(email=email, quota=5, role=1)
	user.hash_password(password)
	db.session.add(user)
	db.session.commit()
	resp = jsonify({'status': 201, 'email': user.email, 'resources': {'Subdomains': {'url': 'https://'+config.root_domain+'/api/v1/subdomains'}, 'Subdomain updates': 'https://'+config.root_domain+'/api/v1/update'}})
	resp.status_code = 201
	return resp

@app.route('/api/v1/user', methods = ['DELETE', 'UPDATE'])
@auth.login_required
def edit_user():
	if request.method == 'DELETE':
		if request.json and not request.args:
			sure = request.json.get('confirm')
		elif request.args:
			sure = request.args.get('confirm')
		else:
			return bad_request(extra='no JSON data or URL Parameters, or both')
		if sure is None or sure is not 'DELETE':
			return bad_request(extra='missing or malformed arguments')
		for d in g.user.subdomains:
			delete_ddns(d.name)
		db.session.delete(g.user)
		g.user = None
		db.session.commit()
		return json_status_message('User deleted, bai bai :<', 200)
	elif request.method == 'UPDATE':
		if request.json and not request.args:
			password = request.json.get('password')
		elif request.args:
			password = request.args.get('password')
		else:
			return bad_request(extra='no JSON data or URL Parameters, or both')
		if password is None:
			return bad_request(extra='missing arguments')
		g.user.hash_password(password)
		db.session.commit()
		return json_status_message('Password updated', 200)

################################
# Domain create / delete route #
################################

@app.route('/api/v1/subdomains', methods=['GET', 'POST', 'DELETE'])
@ratelimit(limit=100, per=60*60)
@auth.login_required
def domain_mainuplator():
	if request.method == 'GET':
		domains = g.user.subdomains
		info = {'email': g.user.email, 'domains': []}
		for d in domains:
			info['domains'].append({'subdomain': d.name, 'full_domain': d.name+"."+config.root_domain, 'ip': d.ip, 'subdomain_token': d.token})
		if len(info['domains']) > 0:
			resp = jsonify(info)
			resp.status_code = 200
			return resp
		else:
			return json_status_message('You have no '+config.root_domain+' subdomains', 200)
	if request.method == 'POST':
		if g.user.quota is 0 or not g.user.subdomains.count() == g.user.quota:
			if request.json and not request.args:
				domain_name = request.json.get('subdomain')
				ip = request.json.get('ip')
			elif request.args and not request.json:
				domain_name = request.args.get('subdomain')
				ip = request.args.get('ip')
			else:
				return bad_request(extra='no JSON data or URL Parameters, or both')
			if not domain_name:
				return bad_request(extra='missing arguments')
			if not ip:
				ip = request.remote_addr
			if not validate_subdomain(domain_name):
				return bad_request(extra='invalid subdomain')
			if validate_ip(ip):
				ipv6 = False
			else:
				if validate_ip(ip, v6=True):
					ipv6 = True
				else:
					return bad_request(extra='IP address invalid or not in allowed subnets')
			new_domain = Subdomain(name=domain_name, ip=ip, v6=ipv6, user=g.user)
			new_domain.generate_domain_token()
			ddns_result = new_ddns(domain_name, ip, ipv6)
			if not ddns_result:
				db.session.add(new_domain)
				db.session.commit()
				return jsonify({'status': 201, 'subdomain': domain_name, 'full_domain': domain_name+"."+config.root_domain, 'ip': ip, 'subdomain_token': new_domain.token, 'GET_update_path': 'htts://'+config.root_domain+'/api/v1/update/'+domain_name+'/'+domain_token+'{/optional-IP}'})
			else:
				return ddns_result
		else:
			return json_status_message('You have reached your subdomain quota', 200)
	elif request.method == 'DELETE':
		if request.json and not request.args:
			domain_name = request.json.get('subdomain')
			domain_token = request.json.get('subdomain_token')
		elif request.args and not request.json:
			domain_name = request.args.get('subdomain')
			domain_token = request.args.get('subdomain_token')
		else:
			return bad_request(extra='no JSON data or URL Parameters, or both')
		if not domain_name or not domain_token:
			return bad_request(extra='missing arguments')
		if not validate_subdomain(domain_name):
			return bad_request(extra='invalid subdomain')
		for d in g.user.subdomains:
			if d.name == domain_name:
				if d.verify_domain_token(domain_token):
					ddns_result = delete_ddns(d.name)
					if not ddns_result:
						db.session.delete(d)
						db.session.commit()
						return json_status_message('Subdomain deleted', 200)
					else:
						return ddns_result
				else:
					return bad_request(extra='invalid subdomain_token')
		return bad_request(extra='invalid subdomain')

@app.route('/api/v1/regen_subdomain_token', methods=['POST'])
@ratelimit(limit=100, per=60*60)
@auth.login_required
def regen_subdomain_token:
	if request.json and not request.args:
		domain_name = request.json.get('subdomain')
		domain_token = request.json.get('subdomain_token')
	elif request.args and not request.json:
		domain_name = request.args.get('subdomain')
		domain_token = request.args.get('subdomain_token')
	else:
		return bad_request(extra='no JSON data or URL Parameters, or both')
	if not domain_token or not domain_name:
		return bad_request(extra='missing arguments')
	for d in g.user.domains:
		if domain_name is d.name:
			if d.verify_domain_token(domain_token):
				d.generate_domain_token()
				db.session.commit()
				return jsonify({'status': 200, 'subdomain': d.name, 'subdomain_token': d.token})
			else:
				return bad_request(extra='invalid subdomain_token')
		else:
			return bad_request(extra='invalid subdomain')


#################################
# JSON / URL param update route #
#################################

@app.route('/api/v1/update', methods=['POST'])
@ratelimit(limit=100, per=60*60)
def fancy_interface():
	if request.json and not request.args:
		domain_list = []
		for d in request.json:
			if not d.name or not d.token:
				return bad_request(extra='missing or malformed arguments')
			if not d.get('address'):
				d['address'] = request.remote_addr
			domain_list.append([d.name, d.token, d['address']])
	elif request.args and not request.json:
		domain_list = []
		names = request.args.get('names')
		tokens = request.args.get('tokens')
		ips = request.args.get('addresses')
		if not names or not tokens:
			return bad_request(extra='missing or malformed arguments')
		names = names.split(',')
		tokens = tokens.split(',')
		if len(names) is not len(tokens) or len(ips) > len(names):
			return bad_request(extra='malformed arguments')
		if ips:
			ips = ips.split(',')
		for i in range(len(names)):
			if len(ips) <= i:
				domain_list.append([names[i], tokens[i], ips[i]])
			else:
				domain_list.append([names[i], tokens[i], request.remote_addr])
	else:
		return bad_request(extra='no JSON data or URL Parameters, or both')
	if not len(domain_list) > 0:
		return bad_request()
	results = []
	for domain_obj in domain_list:
		domain = Domain.query.filter_by(name=domain_obj[0]).first()
		if domain and domain.verify_domain_token(domain_obj[1]):
			if domain_obj[2] == domain.ip:
				return nothing_to_do(extra='supplied IP is the same as current IP')
			else:
				if domain.v6:
					ddns_result = update_ddns(domain.name, domain_obj[2], v6=True)
				else:
					ddns_result = update_ddns(domain.name, domain_obj[2])
				if not ddns_result:
					domain.ip = domain_obj[2]
					db.session.commit()
					results.append({'status': 200, 'subdomain': domain_obj[0], 'full_domain': domain_obj[0]+"."+config.root_domain, 'ip': domain_obj[2]})
				else:
					return ddns_result
		else:
			return bad_request(extra='invalid domain or token')
	if len(results) > 0:
		return jsonify({'results': [results]})
	else:
		return internal_error()


#########################
# GET only update route #
#########################

@app.route('/api/v1/update/<domain_name>/<domain_token>/<domain_ip>', methods=['GET'])
@ratelimit(limit=100, per=60*60)
def get_interface(domain_name, domain_token, domain_ip=None):
	domain = Domain.query.filter_by(name=domain_name).first()
	if domain and domain.verify_domain_token(domain_token):
		if domain_ip is None:
			domain_ip = request.remote_addr
		if domain_ip == domain.ip:
			return nothing_to_do(extra='supplied IP is the same as current IP')
		else:
			if domain.v6:
				ddns_result = update_ddns(domain.name, domain_ip, v6=True)
			else:
				ddns_result = update_ddns(domain.name, domain_ip)
			if not ddns_result:
				domain.ip = domain_ip
				db.session.commit()
				return jsonify({'status': 200, 'subdomain': domain_name, 'full_domain': domain_name+"."+config.root_domain, 'ip': domain_ip})
			else:
				return ddns_result
	else:
		return bad_request(extra='invalid domain or token')

##############
# Dev server #
##############

if __name__ == '__main__':
	app.debug = True
	with app.app_context():
		db.create_all()
		admin = User(email='admin', role=0, quota=0)
		admin.hash_password(config.default_admin_password)
		db.session.add(admin)
		db.session.commit()
	app.run(use_reloader=False, host='192.168.50.2', port=80)
