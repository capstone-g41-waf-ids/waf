import json
import os
import time
import subprocess
import select
import pymongo
import hashlib
from threading import Thread
from flask import Flask, render_template, request, session, redirect
import uwsgidecorators

app = Flask(__name__)
app.secret_key = "hd72bd8a"

CONNSTRING = os.environ['MONGODB_CONNSTRING']  # from container env
SERVER = os.environ['SERVER_NAME']  # from container env
PORTAL = os.environ['IP']  # from container env
PORTAL_PORT = os.environ['PORTAL_PORT']
FLAG_LIST = ["Malicious", "Suspicious", "Benign", "Undefined"]

client = pymongo.MongoClient(CONNSTRING, connect=False)  # connect to mongo
db = client["database"]


@app.route('/login')
def index():
    return render_template('login.html')


@app.route('/check_login', methods=['POST'])
def check_login():
    if "user" in session:
        return redirect('/logsearch')
    else:
        username_local = request.form['uname']
        password_local = request.form['pword']
        account = db.UserAccounts.find_one({'username': username_local, 'password': hash_pword(password_local)})
        if account is not None:
            session["user"] = username_local
            return redirect('/logsearch')
        return redirect('/login')


@app.route('/logout')
def logout():
    if "user" in session:
        session.pop("user", None)
        return redirect('/login')
    else:
        return redirect('/login')


@app.route('/edituser')
def edituser():
    if "user" in session:
        return render_template('edituser.html', result=session['user'], message='')
    return redirect('/login')


@app.route('/editcurrentuser', methods=['POST'])
def editcurrentuser():
    if "user" in session:
        mycol = db["UserAccounts"]

        old_pword = hash_pword(request.form['current_pword'])
        new_pword = hash_pword(request.form['pword'])
        old_user = {"username": session["user"], "password": old_pword}

        result = mycol.update_one(old_user, {'$set': {'password': new_pword}})

        message = "ERROR! User did not update. Please try again."
        if result.modified_count > 0:
            message="SUCCESS! User updated successfully."
        return render_template('edituser.html', result=session['user'], message=message)
    else:
        return redirect('/login')


@app.route('/')
@app.route('/serverstatus')
def serverstatus():
    if "user" in session:
        response = os.popen(f"curl --max-time 2 -I http://webgoat:8080/WebGoat").read()  # HARDCODED WEBGOAT MUST FIX
        if "HTTP/1.1 302 Found" in response:
            return render_template('serverstatus.html', status="Active", server=SERVER, emote="\U0001F642")
        return render_template('serverstatus.html', status="Inactive", server=SERVER, emote="\U0001F641")
    else:
        return redirect('/login')


@app.route('/firewall')
def firewall():
    if "user" in session:
        return render_template('firewall.html', ip_blacklist=get_blacklist(), geo_blacklist=get_geoblacklist(),
                               geo_list=get_geoblacklist_options(), rule_list=get_custom_rules())
    else:
        return redirect('/login')


def get_blacklist():
    if "user" in session:
        return db.IPBlacklist.find()
    return redirect('/login')


@app.route('/blacklist_ip', methods=['POST'])
def blacklist_ip():
    if "user" in session:
        ip = request.form['block_ip']
        myquery = {'ip': ip}
        db.IPBlacklist.replace_one(myquery, myquery, upsert=True)
        update_blacklist_file()
        return redirect('/firewall')
    else:
        return redirect('/login')


@app.route('/delete_ip', methods=['POST'])
def delete_ip():
    if "user" in session:
        ip = request.form['delete_ip']
        db.IPBlacklist.delete_one({"ip": ip})
        update_blacklist_file()
        return redirect('/firewall')
    else:
        return redirect('/login')


def update_blacklist_file():
    f = open("/etc/nginx/ipblacklist", "w")
    x = db.IPBlacklist.find()
    for data in x:
        if data["ip"] is not None:
            f.write("deny " + data["ip"] + ";\n")
    f.close()
    os.system('service nginx reload')


def get_geoblacklist():
    if "user" in session:
        return db.GEOBlacklist.find()
    return redirect('/login')


def get_geoblacklist_options():
    if "user" in session:
        with open("../country_codes") as json_file:
            return json.load(json_file)
    return redirect('/login')


@app.route('/blacklist_geo', methods=['POST'])
def blacklist_geo():
    if "user" in session:
        geolocation = request.form['block_geo']
        myquery = {"country_code": geolocation}
        db.GEOBlacklist.replace_one(myquery, myquery, upsert=True)
        update_geo_file()
        return redirect('/firewall')
    else:
        return redirect('/login')


@app.route('/delete_geo', methods=['POST'])
def delete_geo():
    if "user" in session:
        geo = request.form['delete_geo']
        db.GEOBlacklist.delete_one({"country_code": geo})
        update_geo_file()
        return redirect('/firewall')
    else:
        return redirect('/login')


def update_geo_file():
    f = open("/etc/nginx/geoblacklist", "w")
    x = db.GEOBlacklist.find()
    for data in x:
        if data["country_code"] is not None:
            f.write(data["country_code"] + " no;\n")
    f.close()
    os.system('service nginx reload')


def get_custom_rules():
    if "user" in session:
        return db.ModsecCustomRules.find()
    return redirect('/login')


@app.route('/add_rule', methods=['POST'])
def add_rule():
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
    if "user" in session:
        rule = request.form['delete_rule']
        db.ModsecCustomRules.delete_one({'rule': rule})
        update_rule_file()
        return redirect('/firewall')
    else:
        return redirect('/login')

@app.route('/edit_rule', methods=['POST'])
def edit_rule():
    if "user" in session:
        old_rule = request.form['old_rule']
        new_rule = request.form['new_rule']
        db.ModsecCustomRules.update_one({'rule': old_rule}, {'$set': {'rule': new_rule}})
        update_rule_file()
        return redirect('/firewall')
    else:
        return redirect('/login')



def update_rule_file():
    f = open("/etc/modsecurity.d/custom_rules.conf", "w")
    x = db.ModsecCustomRules.find()
    for data in x:
        if data["rule"] is not None:
            f.write(data["rule"] + "\n")
    f.close()
    os.system('service nginx reload')


@app.route('/logsearch')
def logsearch():
    if "user" in session:
        if "displaylogs" not in session:
            session["displaylogs"] = False
        return render_template('logsearch.html', results=get_access_logs({}), flag_list=FLAG_LIST)
    return redirect('/login')


def get_access_logs(i):
    if "user" in session:
        query = i
        if not session["displaylogs"]:
            query.update({'$nor': [{'server_addr': PORTAL ,'server_port': PORTAL_PORT}]})
        return db.WAFLogs.find(query).sort('time', -1)
    return redirect('/login')


@app.route('/search', methods=['POST'])
def search():
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
    if "user" in session:
        new_flag = request.form['new_flag']
        request_id = request.form['request_id']
        db.WAFLogs.update_one({'request_id': request_id}, {'$set': {'flag': new_flag}})
        return redirect('/logsearch')
    else:
        return redirect('/login')

@app.route('/hide_log', methods=['POST'])
def hide_log():
    if "user" in session:
        session["displaylogs"] ^= True
        return redirect('/logsearch')
    else:
        return redirect('/login')

@uwsgidecorators.postfork
@uwsgidecorators.thread
def nginx_logger():
    f = subprocess.Popen(['tail', '-F', '/var/log/nginx/host.access.log'], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)
    while True:
        if p.poll(1):
            log = json.loads(f.stdout.readline())
            log.update({'flag': 'Undefined'})
            db.WAFLogs.update_one({'request_id': log['request_id']}, {'$setOnInsert': {'messages': ' '}, '$set': log}, upsert=True)
        time.sleep(5)


@uwsgidecorators.postfork
@uwsgidecorators.thread
def modsec_logger():
    f = subprocess.Popen(['tail', '-F', '/var/log/nginx/modsec_audit_log.log'], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)
    while True:
        if p.poll(1):
            log = json.loads(f.stdout.readline())
            db.WAFLogs.update_one({'request_id': log['transaction']['unique_id']}, {'$set': {'messages': modsec_log_parser(log)}}, upsert=True)
        time.sleep(5)


def modsec_log_parser(log):
    if len(log['transaction']['messages']) > 0:
        message = log['transaction']['messages'][0]['message']
        rule = log['transaction']['messages'][0]['details']['ruleId']
        return "Rule:" + rule + " (" + message + ")"
    return ""


def hash_pword(var):
    return hashlib.md5(var.encode('utf-8')).hexdigest()


if __name__ == '__main__':
    update_blacklist_file()
    update_geo_file()
    update_rule_file()
    nginx_logger = Thread(target=nginx_logger)
    nginx_logger.start()
    modsec_logger = Thread(target=modsec_logger)
    modsec_logger.start()
    app.run(host='0.0.0.0')