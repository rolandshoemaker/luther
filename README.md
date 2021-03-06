<pre align="center">
<code style="color: rgb(211, 69, 69);"> _         _    _                 
| |       | |  | |                
| | _   _ | |_ | |__    ___  _ __ 
| || | | || __|| '_ \  / _ \| '__|
| || |_| || |_ | | | ||  __/| |   
|_| \__,_| \__||_| |_| \___||_|   
</code></pre>

<p align="center">
  <img src="luther.png"/>
</p>
<p align="center">
  <em>"your non-lutheran ddns worries me"</em> &mdash; Martin Luther, 1538
</p>

## Introduction

luther is an open source lightweight Dynamic DNS REST API that allows users to setup a DDNS service (similar to dyndns, duckdns, no-ip, etc) for their own domains quickly and painlessly.

luther is also the backend infrastructure for the free (*__beta__, 5 subdomain limit per user*) dynamic dns service [dnsd.co](https://dnsd.co).

luther is written by [Roland Shoemaker](https://www.bind.es/).

## Features

* `GET` subdomain update
* `POST` JSON/URL args multiple subdomain update
* Interchangable `IPv4/6` address use
* REST User account creation, management, and deletion
* Simple *Knockout.js* frontend interface
* CLI tool for admin management

## *Table of Contents*

- [**Documentation**](#documentation)
- [**Contributing**](#contributing)
- [**TODO**](#todo)
- [**Quickstart**](#quickstart)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Configuration](#configuration)
    - [DNS TSIG Key](#dns-tsig-key)
    - [*luther* configuration file](#luther-configuration-file)
    - [Dev server](#dev-server)
    - [WSGI Server](#wsgi-server)
  - [Using the `luther-manage` CLI tool](#using-the-luther-manage-cli-tool)
- [**Interacting with the *luther* REST API as a user**](#interacting-with-the-luther-rest-api-as-a-user)
  - [Endpoints](#endpoints)
  - [Creating a User](#creating-a-user)
  - [Changing your password](#changing-your-password)
  - [Deleting your account](#deleting-your-account)
  - [Checking what *luther* thinks your IP address is](#checking-what-luther-thinks-your-ip-address-is)
  - [Creating a Subdomain](#creating-a-subdomain)
  - [Getting your Subdomains](#getting-your-subdomains)
  - [Deleting a Subdomain](#deleting-a-subdomain)
  - [Updating a Subdomain](#updating-a-subdomain)
    - [GET interface](#get-interface)
    - [Fancy interface](#fancy-interface)
      - [JSON](#json)
      - [URL parameters](#url)
  - [Regenerating a subdomain_token](#regenerating-a-subdomain_token)
- [**License**](#license)


## Documentation

Sphinx documentation can be built from source be navigating to `docs/` and typing

    # make html

or you can view the documentation for the latest release at [https://www.lutherd.org/docs](https://www.lutherd.org/docs).

## Contributing

Please do! Pull requests are welcomed at the *luther* [github page](https://github.com/rolandshoemaker/luther).

## TODO

* ADD: Write python cli update tool (probably seperate repo, luther-update)
* ADD: atom-shell portable gui update tool (probably seperate repo, luther-update-gui)
* FINISH: tests
  * Mostly need tests for invalid input and stuff
* ADD: Load set of config defaults from a default object (not complete, just things that can be set by default without worrying), load again from ENV to overwrite with user changes to defaults and the rest of the config (api url/dns address stuff)
* FIX: Slim down configuration file, there is a bit of duplication
* FINISH: write/rewrite/update sphinx docs

## Quickstart

Lets get *luther* up and running!

### Requirements

If you install *luther* using `setup.py` all these Python packages will be installed (or attempted).

* Python packages
  * dnspython3
  * flask
  * flask.ext.httpauth
  * sqlalchemy
  * tabulate
  * click
  * redis

You will also need these extra services that *luther* relies on to function.

* Local or remote services not provided by *luther*
  * WSGI capable Web server (*Apache, nginx, gunicorn, etc*)
  * DNS server that supports RFC 2136 DNS Updates (*BIND > 8, PowerDNS > 3.4, etc*)
  * SQL database (*MySQL, PostgreSQL, SQLite, etc*)
  * Redis

### Installation

    python setup.py install

### Configuration

Setting up *luther* is pretty simple, but before we get to that we need a TSIG zone key, if you already have a key and your DNS server is configured to accept it you can skip this section

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

#### *luther* configuration file

First copy the example configuration file `examples/luther-config.py.example`

#### Dev server

You can use `luther-manage` to run the simple *Flask* development server using the command `dev_server`

    # luther-manage dev_server (will automatically run on 127.0.0.1:5000, --host and --port can be used for different settings)

#### WSGI Server

#### Running the *luther* tests

To run the tests (*yay you*) run the `tests/run_tests.py`. **But** remember you should have `LUTHER_SETTINGS` set and a DNS server/TSIG zone key setup for DNS update tests.

    # python tests/run_tests.py

### Using the `luther-manage` CLI tool

`luther-manage` is a simple CLI tool for admistering a luther service, allowing you to add, edit, delete, list, and search both Users and Subdomains among a few other random functions you might need or want access to.

    # luther-manage
    Usage: luther-manage [OPTIONS] COMMAND [ARGS]...

      CLI tool for interacting with luther -- v0.1 -- roland shoemaker

      [this can be somewhat dangerous to your luther service, i guess. so be careful ._.]

    Options:
      --help  Show this message and exit.

    Commands:
      add_subdomain                 Add a new subdomain
      add_user                      Add a user
      check_stats                   Get the most recent stats from redis
                                    (relies...
      count_subdomains              Count all subdomains
      count_users                   Count all users
      count_users_subdomains        Count a users subdomains
      delete_subdomain              Delete a subdomain
      delete_user                   Delete a user
      dig_subdomain                 Check subdomain IP address in database...
      edit_subdomain                Edit a subdomain
      edit_user                     Edit a user
      init_db                       Initiailize the luther db
      list_subdomains               List all subdomains
      list_users                    List all users
      list_users_subdomains         List all a users subdomains
      regen_subdomain_token         Regenerate the token for a subdomain
      regen_users_subdomain_tokens  Regenerate all subdomain tokens for a user
      search_subdomains             Search for subdomains by subdomain names
      search_users                  Search for users by email
      view_subdomain                View a specific subdomain
      view_user                     View a specific user

## Interacting with the *luther* REST API as a user

Here we will be using the command `curl` to interact with the API, but any other tool or library can be used.

All of the endpoints we will be talking about here, with the exception of the `GET` subdomain interface and get-ip endpoint, can be used either with URL parameters or with JSON data, just to make your life easier.

### Endpoints

This table provides a quick layout of the entirety of the *luther* API.

    Endpoint                                                                  HTTP Method
    --------                                                                  -----------

    /api/v1/guess_ip                                                          GET             
    > Retrieve the IP luther thinks you are coming from

    /api/v1/user                                                              POST
    > Create a new user
    /api/v1/user                                                              PUT
    > Change your password
    /api/v1/user                                                              DELETE
    > Delete your user

    /api/v1/subdomains                                                        GET
    > Get a list of subdomains you own
    /api/v1/subdomains                                                        POST
    > Add a new subdomain
    /api/v1/subdomains                                                        DELETE
    > Delete a subdomain

    /api/v1/subdomains                                                        PUT
    > Update single/multiple subdomains using the fancy update interface
    /api/v1/subdomains/<subdomain_name>/<subdomain_token>{</optional_ip>}     GET
    > Update a single subdomain using the GET update interface

    /api/v1/regen_token                                                       POST
    > Regenerate the token used to authenticate subdomain updates


***NOTE:*** In the following examples I have generally used `IPv4` addresses, **BUT** `IPv6` and `IPv4` addresses can be used interchangably!
Beware though that the `IP` guessing system *luther* uses is somewhat `IPv4`-biased so if you are using `IPv6` you will probably want to set the `IP` manually when creating and updating subdomains.

### Creating a User

Creating a user can be accomplised through a POST request to `https://dnsd.co/api/v1/user` with the email
address and password you wish to use.

    # curl 'https://dnsd.co/api/v1/user' -i -X POST -H 'Content-type: application/json' -d '{"email":"guy@gmail.com", "password":"password"}'

    -- or --

    # curl 'https://dnsd.co/api/v1/user?email=guy@gmail.com&password=password' -i -X POST

    HTTP/1.0 201 CREATED
    Content-Type: application/json
    Content-Length: 189
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 10:04:05 GMT

    {
      "email": "guy@gmail.com",
      "resources": {
        "Subdomains": "https://dnsd.co/api/v1/subdomains"
      },
      "status": 201
    }%

### Changing your password

To change your password all you need to do it a simple PUT request to `https://dnsd.co/api/v1/user` with your new password.
Since you need an account to do this you can use `curl -u username:password` to identify yourself to the service.

    # curl -u guy@gmail.com:password 'https://dnsd.co/api/v1/user' -i -X PUT -H 'Content-type: application/json' -d '{"new_password":"betterpassword"}'

    -- or --

    # curl -u guy@gmail.com:password 'https://dnsd.co/api/v1/user?new_password=betterpassword' -i -X PUT 

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 52
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 10:13:41 GMT

    {
      "message": "Password updated",
      "status": 200
    }%

### Deleting your account

If you'd like to delete your account (`:<`) you can with a DELETE request to `https://dnsd.co/api/v1/user` with the variable `confirm` set to `DELETE`. When you delete your account all of your user information and subdomains will be immediately deleted.

    # curl -u guy@gmail.com:betterpassword 'https://dnsd.co/api/v1/user' -i -X DELETE -H 'Content-type: application/json' -d '{"confirm":"DELETE"}'

    -- or --

    # curl -u guy@gmail.com:betterpassword 'https://dnsd.co/api/v1/user?confirm=DELETE' -i -X DELETE

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 60
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 10:20:01 GMT

    {
      "message": "User deleted, bai bai :<",
      "status": 200
    }%

### Checking what *luther* thinks your IP address is

When creating and updating subdomains *luther* will either use the IP address you specify or, if none is specified, *luther* will attempt to guess your address. Sometimes it might be useful to know what this is guess is before letting *luther* run wild.

A very simple endpoint allows you do do this by sending a GET request to `https://dnsd.co/api/v1/geuss_ip`

    # curl -i 'https://dnsd.co/api/v1/guess_ip'

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 42
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Fri, 05 Dec 2014 00:13:46 GMT

    {
      "guessed_ip": "1.1.1.1",
      "status": 200
    }% 

### Creating a Subdomain

To create a new subdomain you need to send a PT request to `https://dnsd.co/api/v1/subdomains` with the variables `subdomain` (optionally `ip`, if you don't set this *luther* will try to guess the IP that you are coming from).

    # curl -u guy@gmail.com:betterpassword 'https://dnsd.co/api/v1/subdomains' -i -X POST -H 'Content-type: application/json' -d '{"subdomain":"example"}'

    -- or --

    # curl -u guy@gmail.com:betterpassword 'https://dnsd.co/api/v1/subdomains?subdomain=example' -i -X POST

        -- or with IP address specified --

    # curl -u guy@gmail.com:betterpassword 'https://dnsd.co/api/v1/subdomains' -i -X POST -H 'Content-type: application/json' -d '{"subdomain":"example", "ip":"1.1.1.1"}'

    -- or --

    # curl -u guy@gmail.com:betterpassword 'https://dnsd.co/api/v1/subdomains?subdomain=example&ip=1.1.1.1' -i -X POST

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 317
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 10:30:11 GMT

    {
      "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example/bd6b24e3-ac7f-46d9-abd9-baecfc386a0c",
      "full_domain": "example.dnsd.co",
      "ip": "1.1.1.1",
      "last_updated": "2014-12-04 10:30:11",
      "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example",
      "status": 201,
      "subdomain": "example",
      "subdomain_token": "bd6b24e3-ac7f-46d9-abd9-baecfc386a0c"
    }%

### Getting your Subdomains

To get a list of all of your subdomains and their update tokens you need to send a GET request to `https://dnsd.co/api/v1/subdomains`.

    # curl -u guy@gmail.com:betterpassword 'https://dnsd.co/api/v1/subdomains' -i

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 1382
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 10:49:33 GMT

    {
      "email": "guy@gmail.com",
      "status": 200,
      "subdomains": [
        {
          "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example/6b89fa82-4b20-4bd7-90d2-3e33f3980bde",
          "full_domain": "example.dnsd.co",
          "ip": "1.1.1.1",
          "last_updated": "2014-12-04 10:36:24",
          "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example",
          "subdomain": "example",
          "subdomain_token": "6b89fa82-4b20-4bd7-90d2-3e33f3980bde"
        },
        {
          "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example2/23d37da2-be94-4166-8b5b-ab45084be337",
          "full_domain": "example2.dnsd.co",
          "ip": "1.1.1.2",
          "last_updated": "2014-12-04 10:48:01",
          "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example2",
          "subdomain": "example2",
          "subdomain_token": "23d37da2-be94-4166-8b5b-ab45084be337"
        },
        {
          "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example3/e106a924-c39b-4ce0-a683-5b9dd686b4f5",
          "full_domain": "example3.dnsd.co",
          "ip": "1.1.1.4",
          "last_updated": "2014-12-04 10:48:06",
          "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example3",
          "subdomain": "example3",
          "subdomain_token": "e106a924-c39b-4ce0-a683-5b9dd686b4f5"
        }
      ]
    }% 

### Deleting a Subdomain

To delete a subdomain you need to send to a authenticated DELETE request to `https://dnsd.co/api/v1/subdomains` with the variables `subdomain` and `confirm = 'DELETE'`

    # curl -u guy@gmail.com:betterpassword -X POST 'https://dnsd.co/api/v1/subdomains?subdomain=example3&confirm=DELETE' -i -X DELETE

    -- or --

    # curl -u guy@gmail.com:betterpassword -X POST 'https://dnsd.co/api/v1/subdomains' -i -X DELETE -H 'Content-type: application/json' -d '{"subdomain":"example3", "confirm":"DELETE"}'

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 53
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 11:23:04 GMT

    {
      "message": "Subdomain deleted",
      "status": 200
    }%

  
### Updating a Subdomain

You have two options when updating the address of a subdomain, either the `GET` interface, where everything is done via the URL itself which limits you to updating a single subdomain at a time, or the fancy JSON/URL parameter method which allows you to update multiple subdomains at once.

Updating a subdomain is different from updating/deleting users or creating subdomains. Unlike these endpoints we don't require username and password authentication, all we need is the subdomain name, the `subdomain_token` provided when you create a domain or via the `GET /api/v1/subdomains` list, and the address you wish to update the subdomain to (or nothing and *luther* will guess your address).

#### GET interface

The `GET_update_URI` returned via `GET /api/v1/subdomains` and `POST /api/v1/subdomains` points to the simple `GET` interface. This interface allows you to update the IP address associated with a subdomain, but is limited to updating one subdomain at a time. Using this interface all the parameters are specificed in the url path as so (if the last part of the path, indicating the `IP`, is left off *luther* will attempt to guess your IP address)

    # curl -i 'https://dnsd.co/api/v1/subdomains/subdomain_name/subdomain_token(/optional_ip)'

So to update one of the subdomains we already created we would send these requests

    # curl -i 'https://dnsd.co/api/v1/subdomains/example/6b89fa82-4b20-4bd7-90d2-3e33f3980bde'

    -- or --

    # curl -i 'https://dnsd.co/api/v1/subdomains/example/6b89fa82-4b20-4bd7-90d2-3e33f3980bde/2.2.2.2'

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 348
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 10:54:54 GMT

    {
      "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example/6b89fa82-4b20-4bd7-90d2-3e33f3980bde",
      "full_domain": "example.dnsd.co",
      "ip": "2.2.2.2",
      "last_updated": "2014-12-04 10:54:54",
      "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example",
      "message": "Subdomain updated.",
      "status": 200,
      "subdomain": "example",
      "subdomain_token": "6b89fa82-4b20-4bd7-90d2-3e33f3980bde"
    }%

#### Fancy interface

The fancy interface simply means instead of using GET requests it uses PUT requests to `https://dnsd.co/api/v1/subdomains` and allows you to specify multiple domains at a time. Since the way you specify subdomains and subdomain_tokens slightly differently with JSON and URL parameters we will deal with them seperately.

##### JSON

The JSON version of the interface expects a data object that looks like this (where only ip is optional, if not specified *luther* will try to guess your IP)

    {
      "subdomains": [
        {
          "subdomain": "example",
          "subdomain_token": "692508f1-5774-43cb-abc0-4cff25c3eaea"
        },{
          "subdomain": "example2",
          "subdomain_token": "23d37da2-be94-4166-8b5b-ab45084be337",
          "ip": "3.3.3.3"
        }]
    }

so our `curl` command would look like this

    # curl -u guy@gmail.com:betterpassword -X PUT 'https://dnsd.co/api/v1/subdomains' -H 'Content-type: application/json' -i -d '{ 
              "subdomains": [
                {
                  "subdomain": "example",
                  "subdomain_token": "692508f1-5774-43cb-abc0-4cff25c3eaea"
                },{
                  "subdomain": "example2",
                  "subdomain_token": "23d37da2-be94-4166-8b5b-ab45084be337",
                  "ip": "3.3.3.3"
                }]
            }'

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 860
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 11:43:42 GMT

    {
      "results": [
        [
          {
            "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example/692508f1-5774-43cb-abc0-4cff25c3eaea",
            "full_domain": "example.dnsd.co",
            "ip": "1.1.1.1",
            "last_updated": "2014-12-04 11:43:42",
            "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example",
            "message": "Subdomain updated.",
            "status": 200,
            "subdomain": "example",
            "subdomain_token": "692508f1-5774-43cb-abc0-4cff25c3eaea"
          },
          {
            "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example2/23d37da2-be94-4166-8b5b-ab45084be337",
            "full_domain": "example2.dnsd.co",
            "ip": "3.3.3.3",
            "last_updated": "2014-12-04 11:43:42",
            "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example2",
            "message": "Subdomain updated.",
            "status": 200,
            "subdomain": "example2",
            "subdomain_token": "23d37da2-be94-4166-8b5b-ab45084be337"
          }
        ]
      ]
    }%

##### URL parameters

The URL parameter version of the interface is a little finicky (and I'm not 100% sure it needs to continue existing) it expects two variables `subdomains` and `subdomain_tokens` and an optional variable `addresses`, all of these variables should be either a single subdomain name, subdomain_token, and address or a comma-seperated list of the same pieces of information. The three lists must have the exact same number of elements, although `addresses` can have either less than or equal items (if `addresses < subdomains` all addresses after `len(addresses)` will use the guessed address) or not be specified at all, which means *luther* will use your guessed address for all the subdomains you are updating (you can specify empty items in `addresses`, in order to tell *luther* to use the guessed addreses, by typing `,,`, e.g. `1.2.3.4,,1.2.3.5`). These lists should be relative meaning the `subdomain_token` for the subdomain specified first in the `subdomains` list should be first in the `subdomain_tokens` list etc.

So if we want to update these subdomains to these addresses

    example   =>     GUESS where (subdomain_token = 692508f1-5774-43cb-abc0-4cff25c3eaea)
    example2  =>    5.5.5.6 where (subdomain_token = 23d37da2-be94-4166-8b5b-ab45084be337)

we would use this `curl` command

    # curl -i -X PUT 'https://dnsd.co/api/v1/subdomains?subdomains=example,example2&subdomain_tokens=692508f1-5774-43cb-abc0-4cff25c3eaea,23d37da2-be94-4166-8b5b-ab45084be337&addresses=,5.5.5.6'

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 895
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 12:07:54 GMT

    {
      "results": [
        [
          {
            "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example/692508f1-5774-43cb-abc0-4cff25c3eaea",
            "full_domain": "example.dnsd.co",
            "ip": "1.1.1.1",
            "last_updated": "2014-12-04 12:07:25",
            "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example",
            "message": "Subdomain updated.",
            "status": 200,
            "subdomain": "example",
            "subdomain_token": "692508f1-5774-43cb-abc0-4cff25c3eaea"
          },
          {
            "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example2/23d37da2-be94-4166-8b5b-ab45084be337",
            "full_domain": "example2.dnsd.co",
            "ip": "5.5.5.6",
            "last_updated": "2014-12-04 12:07:54",
            "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example2",
            "message": "Subdomain updated.",
            "status": 200,
            "subdomain": "example2",
            "subdomain_token": "23d37da2-be94-4166-8b5b-ab45084be337"
          }
        ]
      ]
    }%

See what I mean, **SILLY!**

### Regenerating a `subdomain_token`

To regenerate the `subdomain_token` used to authenticate updates send a authenticated POST request to `https://dnsd.co/api/v1/regen_token` with the variable `subdomain` indicating which subdomain you'd like to regenerate the `subdomain_token` for

    # curl -u guy@gmail.com:betterpassword -X POST 'https://dnsd.co/api/v1/regen_token' -i -X POST -H 'Content-type: application/json' -d '{"subdomain":"example"}'

    -- or --

    # curl -u guy@gmail.com:betterpassword -X POST 'https://dnsd.co/api/v1/regen_token?subdomain=example' -i

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 357
    Server: Werkzeug/0.9.6 Python/3.4.0
    Date: Thu, 04 Dec 2014 11:09:03 GMT

    {
      "GET_update_URI": "https://dnsd.co/api/v1/subdomains/example/a388a2ba-a461-4fbf-b907-281f25723586",
      "full_domain": "example.dnsd.co",
      "ip": "2.2.2.2",
      "last_updated": "2014-12-04 11:09:03",
      "regenerate_subdomain_token_URI": "https://dnsd.co/api/v1/regen_token/example",
      "message": "subdomain_token regenerated",
      "status": 200,
      "subdomain": "example",
      "subdomain_token": "a388a2ba-a461-4fbf-b907-281f25723586"
    }%

## License

*luther* is released under the GPLv2 license.
