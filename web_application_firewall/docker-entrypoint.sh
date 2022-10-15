#!/bin/bash

service nginx start
uwsgi etc/portal/wsgi.ini
#python3 portal/flask_webserver.py
