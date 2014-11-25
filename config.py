import uuid

root_domain = 'dnsd.co'
dns_master_server = 'ns.dnsd.co'
dns_master_port = 53
dns_master_source_port = 0
tsig_zone = root_domain
tsig_key = ''
db = 'sqlite:///luther.db'
secret_key = str(uuid.uuid4())
allowed_user_v4_subnets = ['0.0.0.0/0']
allowed_user_v6_subnets = []
allowed_ddns_ipv4_subnets = ['0.0.0.0/0']
allowed_ddns_ipv6_subnets = []
restricted_subdomains = ['www', 'ww', 'w', 'mail', 'mx', 'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'dns']
default_ttl = 86400
default_admin_password = 'admin'
