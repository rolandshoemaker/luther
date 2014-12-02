#!/usr/bin/python
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from luther import app

http_server = HTTPServer(WSGIContainer(app))
http_server.listen(5000)
IOLoop.instance().start()
