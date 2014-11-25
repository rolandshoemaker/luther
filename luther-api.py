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

import dns.query, dns.tsigkeyring, dns.update, dns.exception
import ipaddress
import re

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

def json_status_message(message, code):
	message = {'status': code, 'message': message}
	resp = jsonify(message)
	resp.status_code = code
	return resp

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
		if test.is_private or not correct_subnet:
			return False
		return test.exploeded
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

########################
# Error handler routes #
########################

@app.errorhandler(400)
def bad_request(error=None, extra=None):
	if extra:
		return json_status_message('Bad request, '+extra, 400)
	else:
		return json_status_message('Bad request', 400)

@app.errorhandler(404)
def not_found(error=None, extra=None):
	if extra:
		return json_status_message('Not found, '+extra, 404)
	else:
		return json_status_message('Not found', 404)

@app.errorhandler(405)
def method_not_allowed(error=None, extra=None):
	if extra:
		return json_status_message('Method not allowed, '+extra, 405)
	else:
		return json_status_message('Method not allowed', 405)

@app.errorhandler(409)
def conflict(error=None, extra=None):
	if extra:
		return json_status_message('Conflict in request, '+extra, 409)
	else:
		return json_status_message('Conflict in request', 409)

def nothing_to_do(error=None, extra=None):
	if extra:
		return json_status_message('Nothing to do, '+extra, 200)
	else:
		return json_status_message('Nothing to do', 200)

@app.errorhandler(204)
def no_content(error=None, extra=None):
	if extra:
		return json_status_message('No content, '+extra, 204)
	else:
		return json_status_message('No content', 204)

@app.errorhandler(403)
def forbidden(error=None, extra=None):
	if extra:
		return json_status_message('Forbidden, '+extra, 403)
	else:
		return json_status_message('Forbidden', 403)

#########################
# DNS setup + functions #
#########################

keyring = dns.tsigkeyring.from_text({
	config.tsig_zone: config.tsig_key
})

def update_ddns(name, ip, v6=False):
	addr = validate_ip(ip, v6=v6)
	if addr:
		update = dns.update.Update(config.root_domain, keyring=keyring)
		if not v6:
			update.replace(name+'.'+config.root_domain, config.default_ttl, 'A', addr)
		else:
			update.replace(name+'.'+config.root_domain, config.default_ttl, 'AAAA', addr)
		try:
			resp = dns.query.tcp(update, config.dns_master_server, port=config.dns_master_server, source_port=config.dns_master_source_port)
		except dns.exception.UnexpectedSource or dns.exception.BadResponse:
			return bad_request()
	else:
		if not v6:
			return bad_request('invalid IPv4 address')
		else:
			return bad_request('invalid IPv6 address')

def new_ddns(name, ip, v6=False):
	new_record = dns.update.Update(config.root_domain, keyring=keyring)
	if not v6:
		new_record.add(name+'.'+config.root_domain, config.default_ttl, 'A', ip)
	else:
		new_record.replace(name+'.'+config.root_domain, config.default_ttl, 'AAAA', ip)
	new_record.absent(name+'.'+config.root_domain)
	try:
		resp = dns.query.tcp(new_record, config.dns_master_server, port=config.dns_master_server, source_port=config.dns_master_source_port)
	except dns.exception.UnexpectedSource or dns.exception.BadResponse:
		# return 'DNS message error'
		return bad_request()

def delete_ddns(name):
	delete = dns.update.Update(config.root_domain, keyring=keyring)
	delete.delete(name)
	delete.present(name)
	try:
		resp = dns.query.tcp(delete, config.dns_master_server, port=config.dns_master_server, source_port=config.dns_master_source_port)
	except dns.exception.UnexpectedSource or dns.exception.BadResponse:
		return bad_request()


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
    email = request.json.get('email')
    password = request.json.get('password')
    if email is None or password is None:
        return bad_request(extra='missing arguments') # missing arguments
    if User.query.filter_by(email = email).first() is not None:
        return conflict(extra='existing user') # existing user
    user = User(email=email, quota=5, role=1)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    resp = jsonify({'status': 201, 'email': user.email, 'resources': {'Domains': {'url': 'https://'+config.root_domain+'/api/v1/domain'}, 'Domain updates': 'https://'+config.root_domain+'/api/v1/update'}})
    resp.status_code = 201
    return resp

@app.route('/api/v1/user', methods = ['DELETE', 'UPDATE'])
@auth.login_required
def edit_user():
	if request.method == 'DELETE':
		sure = request.json.get('confirm')
		if sure is None or sure is not 'DELETE':
			return bad_request(extra='missing or malformed arguments')
		for d in g.user.domains:
			delete_ddns(d.name)
		db.session.delete(g.user)
		g.user = None
		db.session.commit()
		return json_status_message('User deleted, bai bai :<', 200)
	elif request.method == 'UPDATE':
		password = request.json.get('password')
		if password is None:
			return bad_request(extra='missing arguments')
		g.user.hash_password(password)
		db.session.commit()
		return json_status_message('Password updated', 200)

################################
# Domain create / delete route #
################################

@app.route('/api/v1/domains', methods=['GET', 'POST', 'DELETE'])
@auth.login_required
def domain_mainuplator():
	if request.method == 'GET':
		domains = g.user.domains
		info = {'email': g.user.email, 'domains': []}
		for d in domains:
			domains.append({'domain_name': d.name, 'ip': d.ip, 'domain_token': d.token})
		if len(info['domains']) > 0:
			resp = jsonify(info)
			resp.status_code = 200
			return resp
		else:
			return json_status_message('You have no '+config.root_domain+' subdomains', 200)
	elif request.method == 'POST':
		if not g.user.domains.count() == g.user.quota:
			domain_name = request.json.get('domain_name')
			if not domain_name:
				return bad_request('missing arguments')
			ip = request.json.get('ip')
			if not ip:
				ip = request.remote_addr
			if not validate_subdomain(domain_name):
				return bad_request('invalid subdomain')
			if validate_ip(ip):
				ipv6 = False
			else:
				if validate_ip(ip, v6=True):
					ipv6 = True
				else:
					return bad_request('IP address invalid or not in allowed subnets')
			new_domain = Domain(name=domain_name, ip=ip, v6=ipv6, user=g.user)
			new_domain.generate_domain_token()
			db.session.add(new_domain)
			db.session.commit()
			ddns_result = new_ddns(domain_name, ip, ipv6)
			if not ddns_result:
				return jsonify({'status': 201, 'subdomain': domain_name, 'full_domain': domain_name+"."+config.root_domain, 'ip': ip, 'domain_token': new_domain.token})
			else:
				return bad_request(extra=ddns_result)
		else:
			return json_status_message('You have reached your subdomain quota', 200)
	elif request.method == 'DELETE':
		domain_name = request.json.get('domain_name')
		domain_token = request.json.get('domain_token')
		if not domain_name or not domain_token:
			return bad_request('missing arguments')
		if not validate_subdomain(domain_name):
			return bad_request('invalid subdomain')
		for d in g.user.domains:
			if d.name is domain_name and d.verify_domain_token(domain_token):
				db.session.delete(d)
				db.session.commit()
				return json_status_message('Subdomain deleted', 200)
			else:
				return bad_request('invalid domain_token')


#################################
# JSON / URL param update route #
#################################

@app.route('/api/v1/update', methods=['POST'])
def fancy_interface():
	pass

#########################
# GET only update route #
#########################

@app.route('/api/v1/update/<domain_name>/<domain_token>/<domain_ip>', methods=['GET'])
def get_interface(domain_name, domain_token, domain_ip=None):
	domain = Domain.query.filter_by(name=domain_name).first()
	if domain and domain.verify_domain_token(domain_token):
		if domain_ip is None:
			domain_ip = request.remote_addr
		if domain_ip == domain.ip:
			return nothing_to_do(extra='supplied IP is the same as current IP')
		else:
			if domain.v6:
				result = update_ddns(domain, domain_ip, v6=True)
			else:
				result = update_ddns(domain, domain_ip)
			if not result:
				return jsonify({'status': 200, 'subdomain': domain_name, 'full_domain': domain_name+"."+config.root_domain, 'ip': domain_ip})
			else:
				return result
	else:
		return bad_request('invalid domain or token')

##############
# Dev server #
##############

if __name__ == '__main__':
	app.host = ''
	app.port = 80
	app.debug = True
	with app.app_context():
		db.create_all()
		admin = User(email='admin', role=0, quota=0)
		admin.hash_password(config.default_admin_password)
		db.session.add(admin)
		db.session.commit()
	app.run(use_reloader=False)