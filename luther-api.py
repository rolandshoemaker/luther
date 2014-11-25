import config

from flask import Flask. g. request, abort, jsonify
from flask.ext.httpauth import HTTPBasicAuth

from models import db, User, Domain

app = Flask(__name__)
app.config['SECRET_KEY'] = config.secret_key
db.init_app(app)
auth = HTTPBasicAuth()

#################
# DNS functions #
#################

def update_v4(name, ip):
	pass

def update_v6(name, ip):
	pass

##################
# Util functions #
##################

def json_status_message(message, code):
	message = {'status': code, 'message': message}
	resp = jsonify(message)
	resp.status_code = code
	return resp

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
    return jsonify({'token': token.decode('ascii')})

###########################
# JSON / URL param routes #
###########################

@app.route('/api/v1/user', methods = ['POST'])
def new_user():
    email = request.json.get('email')
    password = request.json.get('password')
    if email is None or password is None:
        abort(400) # missing arguments
    if User.query.filter_by(email = email).first() is not None:
        abort(400) # existing user
    user = User(email = email)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'status': 201, 'email': user.email, 'resources': {'Domains': {'url': 'https://'+config.root_domain+'/api/v1/domain'}}})

@app.route('/api/v1/domain', methods=['GET', 'POST', 'DELETE'])
@auth.login_required
def domain_mainuplator():
	pass

@app.route('/api/v1/update')
def fancy_interface():
	pass

###################
# GET only routes #
###################

@app.route('/api/v1/update/<str:domain_name>/<str:domain_token>/<str:domain_ip>', methods=['GET'])
def get_interface(domain_name, domain_token, domain_ip=None):
	domain = Domain.query.filter_by(name=domain_name).first()
	if domain and domain.verify_domain_token(domain_token):
		if domain_ip == domain.ip:
			return nothing_todo('supplied IP is the same as current IP'):
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

if __name__ == '__main__':
	app.host = ''
	app.port = 80
	app.debug = True
	app.run()
