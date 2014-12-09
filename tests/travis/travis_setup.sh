#!/bin/bash
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#
# Script to setup the travis-ci build environment properly 
# for luther to be tested with a BIND server etc

# Install BIND9
echo "# Installing BIND9\n"
sudo apt-get update
sudo apt-get install -y bind9

# Copy example zone and config files to /etc/bind/
echo "# Deleteing /etc/bind/named.conf\n"
sudo rm /etc/bind/named.conf
echo "# Deleteing /etc/bind/named.conf.local\n"
sudo rm /etc/bind/named.conf.local
echo "# Deleteing /etc/bind/named.options\n"
sudo rm /etc/bind/named.conf.options
echo "# Copying BIND9 config and zone files to /etc/bind/\n"
sudo cp tests/travis/named.conf /etc/bind/
echo "# Making /var/lib/bind/zones\n"
sudo mkdir -p /var/lib/bind/zones
echo "# Linking /var/lib/bind/zones to /etc/bind/zones/\n"
sudo ln -s /etc/bind/zones /var/lib/bind/zones
echo "# Copying example zone to /var/lib/bind/zones\n"
sudo cp tests/travis/db.example.com /var/lib/bind/zones/

# Fix /etc/bind permissions
echo "# Fixing permissions\n"
sudo chown -R bind:bind /var/lib/bind
sudo chown -R bind:bind /etc/bind

# Restart BIND, it should be properly setup now
echo "# Restarting BIND\n"
sudo service bind9 restart

# Upgrade setuptools
echo "# Upgrading python setuptools\n"
easy_install -U setuptools
