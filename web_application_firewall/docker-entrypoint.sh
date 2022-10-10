#!/bin/bash

service nginx start
pip install pyopenssl
python3 flask_webserver.py
