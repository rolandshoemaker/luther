import uuid

root_domain = 'dnsd.co'
db = 'sqlite:///tmp.db'
secret_key = str(uuid.uuid4())
allowed_subnets = ['0.0.0.0']
dns_masters = ['ns.dnsd.co']
restricted_subdomains = ['www*', 'mail', 'ns*']
