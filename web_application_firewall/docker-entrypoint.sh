#!/bin/bash

service nginx start
pip install pyopenssl
uwsgi portal/wsgi.ini
#python3 portal/flask_webserver.py # uncomment to allow functionality during testing
