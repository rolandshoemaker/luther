#!/bin/bash
# Script to setup the travis-ci build environment properly 
# for luther to be tested

# Install BIND9
echo "# Installing BIND9"
sudo apt-get update
sudo apt-get install -y bind9

# Copy example zone and config files to /etc/bind/
echo "# Copying BIND9 config and zone files to /etc/bind/"
sudo rm /etc/bind/named.conf.local
sudo rm /etc/bind/named.conf.options
sudo cp tests/travis/named.conf.options /etc/bind/
sudo mkdir -p /var/lib/bind/zones
sudo ln -s /etc/bind/zones /var/lib/bind/zones
sudo cp tests/travis/db.example.com /var/lib/bind/zones/

# Restart BIND, it should be properly setup now
sudo service bind9 restart

# Set LUTHER_SETTINGS
export LUTHER_SETTINGS="${PWD}/tests/travis/travis_config.py"
