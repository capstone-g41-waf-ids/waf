#!/bin/bash

service nginx start
uwsgi portal/wsgi.ini