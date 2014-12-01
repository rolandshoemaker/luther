##############
# Dev server #
##############

from luther import app

app.debug = True
app.run(use_reloader=True, host='192.168.1.8', port=80)
