ORIGIN .
$TTL 86400	; 1 day
example.com		IN SOA	ns.example.com. hostmaster.example.com. (
				2014111328 ; serial
				10800      ; refresh (3 hours)
				1800       ; retry (30 minutes)
				604800     ; expire (1 week)
				86400      ; minimum (1 day)
				)
			NS	ns.example.com.
			A	184.105.184.147
$ORIGIN example.com.
ns			A	184.105.184.149
