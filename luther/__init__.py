#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#


"""
.. module:: luther
    :synopsis: lightweight DDNS service with REST API and JS frontend.

.. moduleauthor:: Roland Shoemaker <rolandshoemaker@gmail.com>
"""

from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_envvar('LUTHER_SETTINGS')

if app.config.get('OVERRIDE_HTTPS') and app.config['OVERRIDE_HTTPS']:
    app.config['ROOT_HTTP'] = 'http://'+app.config['ROOT_DOMAIN']
else:
    app.config['ROOT_HTTP'] = 'https://'+app.config['ROOT_DOMAIN']

db = SQLAlchemy(app)

from luther.apiv1 import api_v1, run_stats
app.register_blueprint(api_v1, url_prefix='/api/v1')
if app.config['ENABLE_FRONTEND']:
    from luther.frontend import frontend
    app.register_blueprint(frontend)

from luther.models import init_db
init_db()

if app.config['PROXIED']:
    from werkzeug.contrib.fixers import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app)

timer = run_stats()
