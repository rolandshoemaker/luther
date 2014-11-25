import config
from models import db, User, Domain

from flask import Flask, g, request, jsonify
from flask.ext.httpauth import HTTPBasicAuth

import dns.query, dns.tsigkeyring, dns.update
import ipaddress

app = Flask(__name__)
app.config['SECRET_KEY'] = config.secret_key
db.init_app(app)
auth = HTTPBasicAuth()

##################
# Util functions #
##################

def json_status_message(message, code):
	message = {'status': code, 'message': message}
	resp = jsonify(message)
	resp.status_code = code
	return resp

def validate_ipv4(ip):
	try:
		test = ipaddress.IPv4Address(ip)
		return True
	except ipaddress.AddressValueError:
		return False

def validate_ipv6(ip):
	try:
		test = ipaddress.IPv6Address(ip)
		return True
	except ipaddress.AddressValueError:
		return False

#########################
# DNS setup + functions #
#########################

keyring = dns.tsigkeyring.from_text({
	config.tsig_name: config.tsig_key
})

def update_v4(name, ip):
	if validate_ipv4(ip):
		update = dns.update.Update(config.root_domain, keyring=keyring)
		update.replace(name+'.'+config.root_domain, config.default_ttl, 'A', ip)
		resp = dns.query.tcp(update, dns_master)
	else:
		return bad_request('invalid IPv4 address')

def update_v6(name, ip):
	if validate_ipv6(ip):
		update = dns.update.Update(config.root_domain, keyring=keyring)
		update.replace(name+'.'+config.root_domain, config.default_ttl, 'AAAA', ip)
		resp = dns.query.tcp(update, dns_master)
	else:
		return bad_request('invalid IPv6 address')

########################
# Error handler routes #
########################

@app.errorhandler(400)
def bad_request(extra=None):
	if extra:
		return json_status_message('Bad request, '+extra, 400)
	else:
		return json_status_message('Bad request', 400)

@app.errorhandler(404)
def not_found(extra=None):
	if extra:
		return json_status_message('Not found, '+extra, 404)
	else:
		return json_status_message('Not found', 404)

@app.errorhandler(405)
def method_not_allowed(extra=None):
	if extra:
		return json_status_message('Method not allowed, '+extra, 405)
	else:
		return json_status_message('Method not allowed', 405)

@app.errorhandler(409)
def conflict(extra=None):
	if extra:
		return json_status_message('Conflict in request, '+extra, 409)
	else:
		return json_status_message('Conflict in request', 409)

def nothing_to_do(extra=None):
	if extra:
		return json_status_message('Nothing to do, '+extra, 200)
	else:
		return json_status_message('Nothing to do', 200)

def no_content(extra=None):
	if extra:
		return json_status_message('No content, '+extra, 204)
	else:
		return json_status_message('No content', 204)

####################
# User/Auth routes #
####################

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

@app.route('/api/v1/user', methods = ['DELETE', 'UPDATE'])
@auth.login_required
def edit_user():
	if request.method == 'DELETE':
		sure = request.json.get('delete')
		if sure is None or sure is not 'DELETE':
			return bad_request('missing or malformed arguments')
		db.session.delete(g.user)
		g.user = None
		db.session.commit()
		return no_content('user deleted')
	elif request.method == 'UPDATE':
		password = request.json.get('password')
		if password is None:
			return bad_request('missing arguments')
		g.user.hash_password(password)
		db.session.commit()
		return json_status_message('Password updated', 200)

################################
# Domain create / delete route #
################################

@app.route('/api/v1/domain', methods=['GET', 'POST', 'DELETE'])
@auth.login_required
def domain_mainuplator():
	if request.method == 'GET':
		pass
	elif request.method == 'POST':
		pass
	elif request.method == 'DELETE':
		pass

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
		if domain_ip == domain.ip:
			return nothing_todo('supplied IP is the same as current IP')
		else:
			if domain.v6:
				result = update_v6(domain, domain_ip)
			else:
				result = update_v4(domain, domain_ip)
			if not result:
				return jsonify({'status': 200, 'subdomain': domain_name, 'domain_name': domain_name+"."+config.root_domain, 'ip': domain_ip})
			else:
				return bad_request(result)
	else:
		return bad_request('invalid domain or token')

##############
# Dev server #
##############

if __name__ == '__main__':
	app.host = ''
	app.port = 80
	app.debug = True
	app.run()
