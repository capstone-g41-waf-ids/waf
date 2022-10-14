#!/bin/bash

service nginx start
pip install pyopenssl
uwsgi app/wsgi.ini
#python3 app/flask_webserver.py
