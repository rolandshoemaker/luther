#!/usr/bin/env python
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

##############
# Dev server #
##############

from luther import app

app.run(debug=True, use_reloader=False, host='192.168.1.8', port=80)
