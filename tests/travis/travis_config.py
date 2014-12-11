#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

# only needed if you aren't going to set
# a SECRET_KEY manually (which you should)
import uuid

##################
# Flask settings #
##################

# Database URI
SQLALCHEMY_DATABASE_URI = 'sqlite://'
# Flask secret key
SECRET_KEY = str(uuid.uuid4())

##############
# luther api #
##############

# Root domain of REST API
ROOT_DOMAIN = 'localhost'
# Subdomains restricted from being added by users ('' probably isn't needed)
RESTRICTED_SUBDOMAINS = ['', 'www', 'ww', 'w', 'mail', 'mx', 'ns',
                         'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'dns']
RATE_LIMIT_ACTIONS = 100 
RATE_LIMIT_WINDOW = 60*60
# Hard limit on subdomains that can be added by users
TOTAL_SUBDOMAIN_LIMIT = 5000
# Should luther display the Knockout.js frontend?
ENABLE_FRONTEND = True

################
# luther stats #
################

# Should luther collect statistics
ENABLE_STATS = True
# Redis server hostname/address
REDIS_HOST = 'localhost'
# Redis server port
REDIS_PORT = 6379
# How many entries should luther keep
STATS_ENTRIES = 730
# Interval in seconds that luther should collect stats
STATS_INTERVAL = 43200

##############
# luther dns #
##############

# Root domain subdomains will be provided for
DNS_ROOT_DOMAIN = 'example.com'
# DNS master server hostname/address
DNS_MASTER_SERVER = '127.0.0.1'
# DNS master server port
DNS_MASTER_PORT = 53
# Port luther should send DNS messages from
DNS_MASTER_SOURCE_PORT = 0
# How long to wait before DNS messages timeout (in seconds)
DNS_MASTER_TIMEOUT = 60
# Zone TSIG Key
TSIG_KEY = 'FbpOCJbGUchAZG1iKSfhJQ=='
# Default TTL for A, AAAA, and TXT records
DEFAULT_TTL = 86400
# IPv4 subnets that A record addresses are allowed in (default is IPv4 default route, i.e. everyone)
ALLOWED_DDNS_IPV4_SUBNETS = ['0.0.0.0/0']
# IPv6 subnets that AAAA record addresses are allowed in (default is IPv6 default route, i.e. everyone)
ALLOWED_DDNS_IPV6_SUBNETS = ['::/0']
# Should private IP addresses be allowed in A/AAAA records?
ALLOW_PRIVATE_ADDRESSES = True
# Should luther add TXT records for each subdomain with the last update time?
ADD_TXT_RECORDS = True

################
# luther users #
################

# IPv4 subnets that users are allowed in (default is IPv4 default route, i.e. everyone)
ALLOWED_USER_V4_SUBNETS = ['0.0.0.0/0']
# IPv6 subnets that users are allowed in (default is IPv6 default route, i.e. everyone)
ALLOWED_USER_V6_SUBNETS = ['::/0']
# User subdomain quota
DEFAULT_USER_QUOTA = 5
# Should luther validate emails? (using RFC 2822-ish regex)
VALIDATE_USER_EMAIL = True
# Should we go further and check for a MX record for the users email domain
VALIDATE_USER_EMAIL_MX = True

###############
# luther misc #
###############

# Switch to http for dev
OVERRIDE_HTTPS = True
# Where should luther store it's log?
LOG_FILE_PATH = 'luther.log'
# For rotating log: how many backups
LOG_BACKUP_COUNT = 0
# For rotating log: maximum size of each log
LOG_MAX_BYTES = 0
# Python style log formatter
LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s \
    [in %(pathname)s:%(lineno)d]'
