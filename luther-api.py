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
		if test.is_private or not correct_subnet:
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
		return unauthorized('server is not authorized to make updates to zone on master dns server')
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
	    if email is None or password is None:
	        return bad_request('missing arguments') # missing arguments
	    if User.query.filter_by(email = email).first() is not None:
	        return conflict('existing user') # existing user
	    user = User(email=email, quota=5, role=1)
	    user.hash_password(password)
	    db.session.add(user)
	    db.session.commit()
	    resp = jsonify({'status': 201, 'email': user.email, 'resources': {'Domains': {'url': 'https://'+config.root_domain+'/api/v1/domain'}, 'Domain updates': 'https://'+config.root_domain+'/api/v1/update'}})
	    resp.status_code = 201
	    return resp
	elif request.args and not request.json:
		pass
	else:
		return bad_request('no JSON data or URL Parameters, or both')

@app.route('/api/v1/user', methods = ['DELETE', 'UPDATE'])
@auth.login_required
def edit_user():
	if request.json and not request.args:
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
	elif request.args:
		pass
	else:
		return bad_request(extra='no JSON data or URL Parameters, or both')

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
			info['domains'].append({'subdomain': d.name, 'full_domain': d.name+"."+config.root_domain, 'ip': d.ip, 'subdomain_token': d.token})
		if len(info['domains']) > 0:
			resp = jsonify(info)
			resp.status_code = 200
			return resp
		else:
			return json_status_message('You have no '+config.root_domain+' subdomains', 200)
	if request.json and not request.args:
		if request.method == 'POST':
			if g.user.quota is 0 or not g.user.domains.count() == g.user.quota:
				domain_name = request.json.get('subdomain')
				if not domain_name:
					return bad_request(extra='missing arguments')
				ip = request.json.get('ip')
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
				new_domain = Domain(name=domain_name, ip=ip, v6=ipv6, user=g.user)
				new_domain.generate_domain_token()
				ddns_result = new_ddns(domain_name, ip, ipv6)
				if not ddns_result:
					db.session.add(new_domain)
					db.session.commit()
					return jsonify({'status': 201, 'subdomain': domain_name, 'full_domain': domain_name+"."+config.root_domain, 'ip': ip, 'subdomain_token': new_domain.token})
				else:
					return ddns_result
			else:
				return json_status_message('You have reached your subdomain quota', 200)
		elif request.method == 'DELETE':
			domain_name = request.json.get('subdomain')
			domain_token = request.json.get('subdomain_token')
			if not domain_name or not domain_token:
				return bad_request(extra='missing arguments')
			if not validate_subdomain(domain_name):
				return bad_request(extra='invalid subdomain')
			for d in g.user.domains:
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
	elif request.args and not request.json:
		pass
	else:
		return bad_request(extra='no JSON data or URL Parameters, or both')


#################################
# JSON / URL param update route #
#################################

@app.route('/api/v1/update', methods=['POST'])
def fancy_interface():
	if request.json and not request.args:
		pass
	elif request.args and not request.json:
		pass
	else:
		return bad_request(extra='no JSON data or URL Parameters, or both')

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
