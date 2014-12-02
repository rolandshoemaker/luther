#!/usr/bin/python
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

from wsgiref.handlers import CGIHandler
from luther import app

CGIHandler().run(app)
