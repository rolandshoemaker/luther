##############
# Dev server #
##############

from luther import app

app.run(debug=True, use_reloader=False, host='192.168.1.8', port=80)
