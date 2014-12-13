#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#


"""lightweight REST API for managing DDNS.

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

from luther.apiv1 import api_v1
app.register_blueprint(api_v1)
