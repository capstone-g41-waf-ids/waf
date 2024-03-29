""" All Imports here """
import json
import os
import time
import subprocess
import select
import pymongo
import hashlib
from threading import Thread
from flask import Flask, render_template, request, session, redirect
from flask_simple_geoip import SimpleGeoIP
import uwsgidecorators

""" Initialise Flask, secret key for ssl, geoIP """
app = Flask(__name__)
app.secret_key = "hd72bd8a"
simple_geoip = SimpleGeoIP(app)

""" Collect server and portal information from environmental variables """
CONNSTRING = os.environ['MONGODB_CONNSTRING']
SERVER = os.environ['SERVER_NAME']
SERVER_URL = os.environ['SERVER_URL']
PORTAL = os.environ['PORTAL_IP']
PORTAL_PORT = os.environ['PORTAL_PORT']
FLAG_LIST = ["Malicious", "Suspicious", "Benign", "Undefined"]

""" Connect to MongoDB Database """
client = pymongo.MongoClient(CONNSTRING, connect=False)
db = client["database"]


@app.errorhandler(404)
def page_not_found(e):
    """
    Explicit Error handler, return 404 page on error
    :param e:
    :return: Render custom 404 error page /404.html
    """
    return render_template('error/404.html'), 404


@app.route('/login')
def index():
    """
    Route to and render login page if user is not currently logged in
    If user is logged in, route user to Server Status page.
    :return:
    """
    if "user" in session:
        return redirect('/serverstatus')
    else:
        return render_template('login.html')


@app.route('/check_login', methods=['POST'])
def check_login():
    """
    If the user already has a login session, route to the Server Status page
    If user not in session, take credentials from log in page form and check against database
    If credentials correct will create a login session for them and redirect them to the Server Status page
    :return:
    """
    if "user" in session:
        return redirect('/serverstatus')
    else:
        username_local = request.form['uname']
        password_local = request.form['pword']
        account = db.UserAccounts.find_one({'username': username_local, 'password': hash_pword(password_local)})
        if account is not None:
            session["user"] = username_local  #
            return redirect('/serverstatus')
        return redirect('/login')


@app.route('/logout')
def logout():
    """
    User will be removed from login session
    :return:
    """
    if "user" in session:
        session.pop("user", None)
        return redirect('/login')
    else:
        return redirect('/login')


@app.route('/edituser')
def edituser():
    """
    Routes to and renders edit user page
    :return:
    """
    if "user" in session:
        # give user the edit user page
        return render_template('edituser.html', result=session['user'], message='')
    return redirect('/login')


@app.route('/editcurrentuser', methods=['POST'])
def editcurrentuser():
    """
    Edit user function
    Takes input from form on edit user page and updates user password if credentials are correct
    :return: Renders edit user page with success or fail message
    """
    if "user" in session:
        # Accept current (old) and new password from form on Edit User page
        old_pword = hash_pword(request.form['current_pword'])
        new_pword = hash_pword(request.form['pword'])
        old_user = {"username": session["user"], "password": old_pword}

        # Check if old password matches current password for current user in db, if so updates password in db.
        result = db.UserAccounts.update_one(old_user, {'$set': {'password': new_pword}})

        message = "ERROR! User did not update. Please try again."
        if result.modified_count > 0:
            message = "SUCCESS! User updated successfully."
        return render_template('edituser.html', result=session['user'], message=message)
    else:
        return redirect('/login')


@app.route('/')  # Set Server Status is the default page
@app.route('/serverstatus')
def serverstatus():
    """
    Server status page
    Curls webserver to check server status
    This page is the default page for the website
    :return: Renders Server Status page based on curl response status code
    """
    if "user" in session:
        response = os.popen(f"curl --max-time 2 -I {SERVER_URL}").read()  # Curl to webserver
        # Check curl response status code and render Server Status page accordingly
        if "HTTP/1.1 302 Found" in response:
            return render_template('serverstatus.html', status="Active", server=SERVER, emote="\U0001F642")
        return render_template('serverstatus.html', status="Inactive", server=SERVER, emote="\U0001F641")
    else:
        return redirect('/login')


@app.route('/firewall')
def firewall():
    """
    Route to and render Firewall Settings Page
    :return: Renders firewall settings page
    """
    if "user" in session:
        return render_template('firewall.html', ip_blacklist=get_blacklist(), geo_blacklist=get_geoblacklist(),
                               geo_list=get_geoblacklist_options(), rule_list=get_custom_rules())
    else:
        return redirect('/login')


def get_blacklist():
    """
    Returns all IPs recorded in IP Blacklist Collection
    :return:
    """
    if "user" in session:
        return db.IPBlacklist.find()
    return redirect('/login')


@app.route('/blacklist_ip', methods=['POST'])
def blacklist_ip():
    """
    Takes form input from user and adds IP to WAF blacklist
    Checks current user IP to prevent user from blocking themselves
    :return: Renders firewall settings page with success/fail confirmation message
    """
    if "user" in session:
        ip = request.form['block_ip']
        message = "You can't block your own IP"
        if ip != request.remote_addr:  # Rejects if user attempts to block their own IP
            myquery = {'ip': ip}
            db.IPBlacklist.replace_one(myquery, myquery, upsert=True)  # Blacklists the IP
            update_blacklist_file()  # updates the file that nginx reads from
            message = "IP address added to blacklist"
        return render_template('firewall.html', ip_blacklist=get_blacklist(), geo_blacklist=get_geoblacklist(),
                               geo_list=get_geoblacklist_options(), rule_list=get_custom_rules(), message=message)
    else:
        return redirect('/login')


@app.route('/delete_ip', methods=['POST'])
def delete_ip():
    """
    Delete IP from IP blacklist
    :return:
    """
    if "user" in session:
        ip = request.form['delete_ip']
        db.IPBlacklist.delete_one({"ip": ip})  # Will remove ip from collection
        update_blacklist_file()  # Updates nginx blacklist with new IP
        return redirect('/firewall')
    else:
        return redirect('/login')


def update_blacklist_file():
    """
    Updates nginx blacklist file from IPBlacklist database
    Hot reloads nginx
    :return: Does not return anything
    """
    f = open("/etc/nginx/ipblacklist", "w")
    x = db.IPBlacklist.find()
    for data in x:
        if data["ip"] is not None:
            f.write("deny " + data["ip"] + ";\n")
    f.close()
    os.system('service nginx reload')  # reload nginx to update it with the latest blacklist


def get_geoblacklist():
    """
    Returns all Geolocations recorded in Geolocation Blacklist Collection
    :return: Does not return anything
    """
    if "user" in session:
        return db.GEOBlacklist.find()  # gets geo black list from collection
    return redirect('/login')


def get_geoblacklist_options():
    """
    Get all countries and country codes for geolocation blacklisting
    User uses selects from this list when block geolocations
    :return:
    """
    if "user" in session:
        with open("../country_codes") as json_file:
            return json.load(json_file)  # gets the options for the user to choose from when blocking a country
    return redirect('/login')


@app.route('/blacklist_geo', methods=['POST'])
def blacklist_geo():
    """
    Takes form input from user and adds geolocation to WAF blacklist
    Checks current user geolocation to prevent user from blocking themselves
    :return: Renders firewall settings page with success/fail confirmation message
    """
    if "user" in session:
        geolocation = request.form['block_geo']
        geoip_data = simple_geoip.get_geoip_data()  # Gets the users geolocation
        message = "You can't block your own GeoLocation"  # Add error message
        if geolocation != geoip_data["location"]["country"]:  # Won't let the user block their own geolocation
            myquery = {"country_code": geolocation}
            # Blacklists geolocation if it doesn't already exist in the collection
            db.GEOBlacklist.replace_one(myquery, myquery, upsert=True)
            update_geo_file()
            message = "GeoLocation added successfully"
        return render_template('firewall.html', ip_blacklist=get_blacklist(), geo_blacklist=get_geoblacklist(),
                               geo_list=get_geoblacklist_options(), rule_list=get_custom_rules(), message=message)
    else:
        return redirect('/login')


@app.route('/delete_geo', methods=['POST'])
def delete_geo():
    """
    Delete geolocation from blacklist
    :return:
    """
    if "user" in session:
        geo = request.form['delete_geo']
        db.GEOBlacklist.delete_one({"country_code": geo})  # deletes the geolocation from the collection
        update_geo_file()  # updates the file that nginx reads from
        return redirect('/firewall')
    else:
        return redirect('/login')


def update_geo_file():
    """
    Updates nginx blacklist file from geolocation blacklist database
    Hot reloads nginx
    :return:
    """
    f = open("/etc/nginx/geoblacklist", "w")
    x = db.GEOBlacklist.find()
    for data in x:
        if data["country_code"] is not None:
            f.write(data["country_code"] + " no;\n")  # updates the file that nginx reads from
    f.close()
    os.system('service nginx reload')


def get_custom_rules():
    """
    Get list of custom rules from custom rule collection
    :return:
    """
    if "user" in session:
        return db.ModsecCustomRules.find()
    return redirect('/login')


@app.route('/add_rule', methods=['POST'])
def add_rule():
    """
    Add custom rule to custom rule collection
    :return:
    """
    if "user" in session:
        rule = request.form['add_rule']
        myquery = {"rule": rule}
        db.ModsecCustomRules.replace_one(myquery, myquery, upsert=True)
        update_rule_file()
        return redirect('/firewall')
    else:
        return redirect('/login')


@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    """
    Delete custom rule from custom rule collection
    :return:
    """
    if "user" in session:
        rule = request.form['delete_rule']
        db.ModsecCustomRules.delete_one({'rule': rule})
        update_rule_file()
        return redirect('/firewall')
    else:
        return redirect('/login')


@app.route('/edit_rule', methods=['POST'])
def edit_rule():
    """
    Edit existing rule in custom rule collection
    :return:
    """
    if "user" in session:
        old_rule = request.form['old_rule']
        new_rule = request.form['new_rule']
        db.ModsecCustomRules.update_one({'rule': old_rule}, {'$set': {'rule': new_rule}})
        update_rule_file()
        return redirect('/firewall')
    else:
        return redirect('/login')


def update_rule_file():
    """
    Updates ModSecurity custom rules file from Custom rule database
    Hot reloads nginx
    :return:
    """
    f = open("/etc/modsecurity.d/custom_rules.conf", "w")
    x = db.ModsecCustomRules.find()
    for data in x:
        if data["rule"] is not None:
            f.write(data["rule"] + "\n")
    f.close()
    os.system('service nginx reload')


@app.route('/logsearch')
def logsearch():
    """
    Routes to and renders log search page
    Display all WAF logs in table
    :return: Renders log search page
    """
    if "user" in session:
        if "displaylogs" not in session:
            session["displaylogs"] = False  # if user has not specified to show web portal logs, hides them
        return render_template('logsearch.html', results=get_access_logs({}), flag_list=FLAG_LIST)
    return redirect('/login')


def get_access_logs(query):
    """
    Gets all access logs from WAF logs database
    If specified, filters logs to display/hide specific logs
    :param query: Query to specify access logs filtering, also may include
    :return: Returns all access logs, including filtering by above query, sorted by time
    """
    if "user" in session:
        if not session["displaylogs"]:  # checks if user has selected to hide web portal logs
            # adds to query to exclude any logs where the server address and port match the portal (hide portal logs)
            query.update({'$nor': [{'server_addr': PORTAL, 'server_port': PORTAL_PORT}]})
        return db.WAFLogs.find(query).sort('time', -1)
    return redirect('/login')


@app.route('/search', methods=['POST'])
def search():
    """
    Search WAF logs and return logs based on user request
    Takes user input from forms on logsearch page
    Builds pymongo query based input and renders log page based on query
    :return:
    """
    if "user" in session:
        fields = request.form.getlist('field')
        queries = request.form.getlist('query')
        search_query = {}
        for i, field in enumerate(fields):
            search_query.update({field: {'$regex': queries[i], '$options': 'i'}})
        return render_template('logsearch.html', results=get_access_logs(search_query), flag_list=FLAG_LIST)
    else:
        return redirect('/login')


@app.route('/flag_log', methods=['POST'])
def flag_log():
    """
    Flag a log with a value "Malicious", "Suspicious", "Benign" or "Undefined"
    :return:
    """
    if "user" in session:
        new_flag = request.form['new_flag']
        request_id = request.form['request_id']
        db.WAFLogs.update_one({'request_id': request_id}, {'$set': {'flag': new_flag}}) 
        return redirect('/logsearch')
    else:
        return redirect('/login')


@app.route('/hide_log', methods=['POST'])
def hide_log():
    """
    Show/Hides the web portal logs from the logs table
    Toggles display logs value when user clicks display logs button in log page
    User submits empty form and session value "displaylogs" is toggled
    :return: Redirects back to logsearch page
    """
    if "user" in session:
        session["displaylogs"] ^= True  # toggles displaylogs value
        return redirect('/logsearch')
    else:
        return redirect('/login')


@uwsgidecorators.postfork
@uwsgidecorators.thread  # tells uWSGI that this function will be threaded
def nginx_logger():
    """
    Send logs from WAF to WAFLogs database
    Combines with existing entries from ModSec, if any.
    :return: nothing
    """
    f = subprocess.Popen(['tail', '-F', '/var/log/nginx/host.access.log'], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)
    while True:
        if p.poll(1):
            log = json.loads(f.stdout.readline())
            log.update({'flag': 'Undefined'})
            db.WAFLogs.update_one({'request_id': log['request_id']}, {'$setOnInsert': {'messages': []}, '$set': log},
                                  upsert=True)
        time.sleep(5)


@uwsgidecorators.postfork
@uwsgidecorators.thread  # tells uWSGI that this function will be threaded
def modsec_logger():
    """
    Send logs from ModSec to WAFLog database
    Combines with existing entries from NGINX, if any.
    :return: nothing
    """
    f = subprocess.Popen(['tail', '-F', '/var/log/nginx/modsec_audit_log.log'], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)  # logger will tail the file and catch any updates
    p = select.poll()
    p.register(f.stdout)
    while True:
        if p.poll(1):  # poll will only take in responses from the file if they haven't been posted before
            log = json.loads(f.stdout.readline())  # reads line and converts to json format
            db.WAFLogs.update_one({'request_id': log['transaction']['unique_id']},
                                  {'$addToSet': {'messages': modsec_log_parser(log)}}, upsert=True)
        time.sleep(5)


def modsec_log_parser(log):
    """
    Parse Modsec logs to return relevant information
    :param log:
    :return:
    """
    if len(log['transaction']['messages']) > 0:
        message = log['transaction']['messages'][0]['message']
        rule = log['transaction']['messages'][0]['details']['ruleId']
        return "Rule:" + rule + " (" + message + ")"
    return ""


def hash_pword(var):
    """
    MD5 hash the password
    :param var: Plaintext password
    :return: MD5 hashed password
    """
    return hashlib.md5(var.encode('utf-8')).hexdigest()


if __name__ == '__main__':
    update_blacklist_file()
    update_geo_file()
    update_rule_file()
    nginx_logger = Thread(
        target=nginx_logger)  # Threaded workload logger runs in the background while flask runs in the main thread
    nginx_logger.start()
    modsec_logger = Thread(
        target=modsec_logger)  # Threaded workload logger runs in the background while flask runs in the main thread
    modsec_logger.start()
    app.run(host='0.0.0.0')  # Start flask
