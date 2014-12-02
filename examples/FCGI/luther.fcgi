#!/usr/bin/python
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

from flup.server.fcgi import WSGIServer
from luther import app

if __name__ == '__main__':
    WSGIServer(app).run()  # Apache2
    # WSGIServer(app, bindAddress='/path/to/fcgi.sock').run()  # nginx / older lighthttpd
