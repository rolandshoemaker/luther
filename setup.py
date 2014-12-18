#!/usr/bin/env python
#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

from setuptools import setup

setup(
    name='luther',
    version='0.1',
    description='lightweight dynamic DNS REST API in Python',
    author='Roland Shoemaker',
    author_email='rolandshoemaker@gmail.com',
    url='https://lutherd.org/',
    packages=['luther'],
    entry_points='''
        [console_scripts]
        luther-manage=luther.scripts.cli:cli
    ''',
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'passlib',
        'flask-sqlalchemy',
        'flask-httpauth',
        'Flask',
        'dnspython3',
        'redis',
        'click',
        'tabulate'
    ]
)
