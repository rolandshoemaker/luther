     _         _    _                 
    | | _   _ | |_ | |__    ___  _ __ 
    | || | | || __|| '_ \  / _ \| '__|
    | || |_| || |_ | | | ||  __/| |   
    |_| \__,_| \__||_| |_| \___||_|   
                                  


<p align="center">
  <img src="luther.png"/>
</p>
<p align="center">
  "your non-lutheran ddns worries me" - Martin Luther, 1538
</p>

## Introduction

luther is an open source lightweight Dynamic DNS REST API that allows users 
to setup a DDNS service (similar to dyndns, duckdns, no-ip, etc) for their 
own domains quickly and painlessly.

luther is also the backend infrastructure for the free (*__beta__, 5 subdomain limit per user*) dynamic dns service [dnsd.co](https://dnsd.co).

## Quickstart

### Requirements

If you install *luther* using `setup.py` all these modules will attempt to be installed.

* Python packages
  * dnspython3
  * flask
  * flask.ext.httpauth
  * sqlalchemy
  * tabulate (for the cli tool)
  * click (for the cli tool)
  * redis (for storing stats)
* Local or remote services not provided by *luther*
  * DNS server that supports RFC 2136 DNS Updates (BIND > 8, PowerDNS > 3.4, etc)
  * SQL database (MySQL, PostgreSQL, SQLite, etc)
  * Redis database

### Installation

    python setup.py install

### Configuration

#### DNS TSIG Key

To generate a TSIG key for the zone you want to use, if you don't already have one, run `dnssec-keygen` to generate the TSIG key files (make sure you use the FQDN, including the trailing **.**)

    # dnssec-keygen -a HMAC-MD5 -b 512 -n HOST example.com.
    Kexample.com.+157+32502

Open the resulting `.key` file and copy the shared secret at the end of the KEY record, highlighted here in bold (the key here is truncated because 512 bits is long)

<pre><code>example.com. IN KEY 512 3 157 <strong>ZGep1GQGC7l5vPSevN2q9+H55/2eiok7ejwxNAO6Pniv0Zh...</strong></code></pre>

To allow this key to be used to update a DNS server you need to add the key configuration to your `named.conf` / `named.conf.keys` configuration file on the DNS server, like this

    key example.com. {
        algorithm hmac-md5;
        secret "ZGep1GQGC7l5vPSevN2q9+H55/2eiok7ejwxNAO6Pniv0Zh...";
    };

and in your zone definition file append an `allow-update` statement to the relevant zone

    zone "example.com" {
        ...
        allow-update {
            key example.com.;
        };
    };

#### luther.config

#### Dev server

To run the development server run

    # python3 scripts/dev_server.py
    
    -- or --
    
    # luther-cli devserver

#### WSGI Server

### Using the CLI tool

### Interacting with *luther*

## Documentation

Sphinx documentation can be built from source be navigating to `docs/` and typing

    # make html

or you can view the documentation for the latest release at [https://docs.lutherd.org](https://docs.lutherd.org).

## TODO

* ADD: dynamic switching between ipv6 and ipv4 addresses in DB and on NS...
* ADD: Write example client tools
* FINISH: `setup.py` installer file
* ADD: registration stuff in luther.js
* ADD: change pass/delete user drop down to frontend
* ADD: write tests
* FIX: Slim down configuration file, there is a bit of duplication
* **DONE**: table doesn't update properly when you add a domain :<
* finish writing the README (._.)
* finish writing all the documentation


## License

*luther* is released under the GPLv2 license.
