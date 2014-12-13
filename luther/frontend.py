#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

"""
.. module:: luther.frontend
    :platform: Unix
    :synopsis: Frontend for luther service.

.. moduleauthor:: Roland Shoemaker <rolandshoemaker@gmail.com>
"""

#################
# flask imports #
#################

from flask import render_template, Blueprint, request, make_response, jsonify
from flask.ext.httpauth import HTTPBasicAuth

frontend = Blueprint('frontend', __name__, None)

###################
# luther frontend #
###################

auth = HTTPBasicAuth()


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)
    # return 403 instead of 401 to prevent browsers from
    # displaying the default auth dialog


@frontend.route('/')
def index():
    return render_template(
        'luther.html',
        client_ip=request.remote_addr
    )
