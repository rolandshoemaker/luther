import uuid

root_domain = 'dnsd.co'
db = 'sqlite:///tmp.db'
secret_key = str(uuid.uuid4())
allowed_subnets = ['0.0.0.0']
dns_master = 'ns.dnsd.co'
restricted_subdomains = ['www*', 'mail', 'ns*']
tsig_name = root_domain
tsig_key = ''
default_ttl = 86400