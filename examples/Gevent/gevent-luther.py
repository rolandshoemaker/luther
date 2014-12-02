#!/usr/bin/python
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

from gevent.wsgi import WSGIServer
from luther import app

http_server = WSGIServer(('', 5000), app)
http_server.serve_forever()
