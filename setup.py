#!/usr/bin/env python

from setuptools import setup

setup(
    name='luther',
    version='0.1',
    description='lightweight dynamic DNS REST API in Python',
    author='Roland Shoemaker',
    author_email='rolandshoemaker@gmail.com',
    url='https://lutherd.org/',
    packages=['luther'],
    scripts=['scripts/luther-cli'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'flask-sqlalchemy',
        'flask-httpauth',
        'Flask',
        'dnspython3',
        'click',
        'tabulate'
    ]
)
