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

connstring = os.environ['MONGODB_CONNSTRING']  # from container env
myclient = pymongo.MongoClient(connstring, connect=False)  # connect to mongo
mydb = myclient["database"]


@app.route('/')
@app.route('/login')
def index():
    return render_template('login.html')


@app.route('/check_login', methods=['POST'])
def check_login():
    if "user" in session:
        return render_template('/logsearch.html')
    else:
        username_local = request.form['uname']
        password_local = request.form['pword']
        myquery = {"username": username_local, "password": hash(password_local)}
        user = mydb.UserAccounts.find_one(myquery)
        if user is not None:
            session["user"] = username_local
            return render_template('/logsearch.html', results=get_access_logs(), results2=get_audit_logs())
        return redirect('/login')


@app.route('/serverstatus')
def serverstatus():
    if "user" in session:
        response = os.popen(f"curl --max-time 2 -I http://webgoat:8080/WebGoat").read() #HARDCODED WEBGOAT
        if "HTTP/1.1 302 Found" in response:
            return render_template('serverstatus.html', status="Active", emote="&#128578")
        else:
            return render_template('serverstatus.html', status="Inactive", emote="&#128577")
    else:
        return redirect('/login')


@app.route('/edituser')
def edituser():
    if "user" in session:
        return render_template('edituser.html', result=session["user"])
    else:
        return redirect('/login')

def hash(var):
    return hashlib.md5(var.encode('utf-8')).hexdigest()

@app.route('/editcurrentuser', methods=['POST'])
def editcurrentuser():
    if "user" in session:
        mycol = mydb["UserAccounts"]

        old_pword = hash(request.form['current_pword'])
        new_pword = hash(request.form['pword'])
        old_user = {"username": session["user"], "password": old_pword}

        result = mycol.update_one(old_user, {"$set": {"password": new_pword}})

        if result.modified_count > 0:
            message = "SUCCESS! User updated successfully."
        message = "ERROR! User did not update. Please try again."

        return render_template('/updateuser.html', message=message)
    else:
        return redirect('/login')


def get_GeoBlacklist_options():
    if "user" in session:
        with open("../country_codes") as json_file:
            return json.load(json_file)
    else:
        return redirect('/login')


def get_blacklist():
    if "user" in session:
        return mydb.IPBlacklist.find()
    else:
        return redirect('/login')


def get_GeoBlacklist():
    if "user" in session:
        return mydb.GEOIP_blacklist.find()
    else:
        return redirect('/login')


@app.route('/firewall')
def firewall():
    if "user" in session:
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return redirect('/login')


@app.route('/blacklistIP', methods=['POST'])
def blacklistIP():
    if "user" in session:
        ip = request.form['ip_blacked']
        myquery = {'ip': ip}
        mydb.IPBlacklist.replace_one(myquery, myquery, upsert=True)
        update_blacklist_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return redirect('/login')


@app.route('/blacklistGEO', methods=['POST'])
def blacklistGEO():
    if "user" in session:
        geolocation = request.form['geoip_blacked']
        myquery = {"country_code": geolocation}
        mydb.GEOIP_blacklist.replace_one(myquery, myquery, upsert=True)
        update_geoIP_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return redirect('/login')


@app.route('/deleteIP', methods=['POST'])
def deleteIP():
    if "user" in session:
        delete_ip = request.form['deleteIP']
        mydb.IPBlacklist.delete_one({"ip": delete_ip})
        update_blacklist_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return redirect('/login')


@app.route('/delete_geo', methods=['POST'])
def delete_geo():
    if "user" in session:
        delete_geo = request.form['delete_geo']
        mydb.GEOIP_blacklist.delete_one({"country_code": delete_geo})
        update_geoIP_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return redirect('/login')


@app.route('/logsearch')
def logsearch():
    if "user" in session:
        return render_template('logsearch.html', results=get_access_logs(), results2=get_audit_logs())
    else:
        return redirect('/login')


def get_access_logs():
    if "user" in session:
        return mydb.WAFLogs.find().sort("time", -1)
    else:
        return redirect('/login')


def get_audit_logs():
    if "user" in session:
        return mydb.modsec_audit_logs.find().sort("time", -1)
    else:
        return redirect('/login')


@app.route('/search', methods=['POST'])
def search():
    if "user" in session:
        search_data = request.form['searched']
        search_field = request.form['field']
        myquery = {search_field: {"$regex": search_data}}
        result = mydb.WAFLogs.find(myquery)
        return render_template('logsearch.html', results=result, results2=get_audit_logs())
    else:
        return redirect('/login')


@app.route('/auditlogsearch', methods=['POST'])
def auditlogsearch():
    if "user" in session:
        search_data = request.form['searched']
        myquery = {"log": {"$regex": search_data}}
        result = mydb.modsec_audit_logs.find(myquery)
        return render_template('logsearch.html', results=get_access_logs(), results2=result)
    else:
        return redirect('/login')


@app.route('/logout')
def logout():
    if "user" in session:
        session.pop("user", None)
        return redirect('/login')
    else:
        return redirect('/login')


@uwsgidecorators.postfork
@uwsgidecorators.thread
def access_logger():
    f = subprocess.Popen(['tail', '-F', '/var/log/nginx/host.access.log'], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)
    while True:
        if p.poll(1):
            log = json.loads(f.stdout.readline())
            mydb.WAFLogs.update_one({'request_id': log['request_id']}, {'$set': log}, upsert=True)
        time.sleep(5)


@uwsgidecorators.postfork
@uwsgidecorators.thread
def audit_logger():
    f = subprocess.Popen(['tail', '-F', '/var/log/nginx/modsec_audit_log.log'], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)
    while True:
        if p.poll(1):
            log = json.loads(f.stdout.readline())
            mydb.WAFLogs.update_one({'request_id': log['transaction']['unique_id']},
                             {'$set': {'messages': log['transaction']['messages']}}, upsert=True)
        time.sleep(5)


def update_blacklist_file():
    f = open("/etc/nginx/blacklist", "w")
    x = mydb.IPBlacklist.find()
    for data in x:
        if data["ip"] is not None:
            f.write("deny " + data["ip"] + ";\n")
    f.close()
    os.system('service nginx reload')


def update_geoIP_file():
    f = open("/etc/nginx/GEOIP_blacklist", "w")
    x = mydb.GEOIP_blacklist.find()
    for data in x:
        if data["country_code"] is not None:
            f.write(data["country_code"] + " no;\n")
    f.close()
    os.system('service nginx reload')


if __name__ == '__main__':
    update_blacklist_file()
    update_geoIP_file()
    access_logger = Thread(target=access_logger)
    access_logger.start()
    audit_logger = Thread(target=audit_logger)
    audit_logger.start()
    context = ('/etc/nginx/ssl/secret.crt', '/etc/nginx/ssl/secret.key')
    app.run(host='172.2.2.4', port=30, debug=True, ssl_context=context)
