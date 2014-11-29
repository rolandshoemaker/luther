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

a lightweight dynamic dns REST API backend for BIND written in Python using the 
[Flask](http://flask.pocoo.org/) web application framework. this repo makes up the 
infrastructure for the free (*beta*) dynamic dns service [dnsd.co](https://dnsd.co).

## Quickstart

### Requirements

If you install *luther* using `setup.py` all these modules will attempt to be installed.

* Python packages
  * dnspython3
  * flask
  * flask.ext.httpauth
  * sqlalchemy
  * tabulate
  * click (for the cli tool)
  * redis (for storing stats
* Local or remote services not provided by *luther*
  * DNS server that supports RFC 2136 DNS Updates (BIND > 8, PowerDNS > 3.4, etc) and a TSIG zone key
  * SQL database (MySQL, PostgreSQL, SQLite, etc)
  * redis-server

### Installation

### Configuration

## Documentation

Sphinx documentation can be built from source be navigating to `docs` and typing

    # make html

or you can view the documentation for the latest release at [https://docs.lutherd.org](https://docs.lutherd.org).

## TODO

* FIX: table doesn't update properly when you add a domain :<
* ADD: registration stuff in luther.js
* ADD: change pass/delete user drop down to frontend
* finish writing the README (._.)
* finish writing all the documentation

## License

*luther* is released under the GPLv2 license.
