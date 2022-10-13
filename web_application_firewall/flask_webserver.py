import json
import os
import time
import subprocess
import select
import pymongo
from threading import Thread
from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = "hd72bd8a"

connstring = os.environ['MONGODB_CONNSTRING']   # from container env
myclient = pymongo.MongoClient(connstring)   # connect to mongo
mydb = myclient["database"]


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/check_login', methods=['POST'])
def check_login():
    if "user" in session:
        return render_template('/logsearch.html')
    else:
        username_local = request.form['uname']
        password_local = request.form['pword']
        mycol = mydb["UserAccounts"]
        myquery = {"username": username_local, "password": password_local}
        x = mycol.find(myquery)
        for data in x:
            if data["username"] is not None and data["password"] is not None:
                session["user"] = username_local
                return render_template('/logsearch.html', results=get_logs())
            else:
                return render_template('/login.html')
        return render_template('/login.html')


@app.route('/serverstatus.html')
def serverstatus():
    if "user" in session:
        response = os.popen(f"curl --max-time 5 -I http://webgoat:8080/WebGoat").read()
        if "HTTP/1.1 302 Found" in response:
            return render_template('serverstatussuccess.html')
        else:
            return render_template('serverstatusunsuccessfull.html')
    else:
        return render_template('/login.html')


def get_GeoBlacklist_options():
    if "user" in session:
        with open("country_codes") as json_file:
            x = json.load(json_file)
        return x
    else:
        return render_template('/login.html')


@app.route('/edituser.html')
def edituser():
    if "user" in session:
        return render_template('edituser.html')
    else:
        return render_template('/login.html')


def get_blacklist():
    if "user" in session:
        mycol = mydb["IPBlacklist"]
        x = mycol.find()
        return x
    else:
        return render_template('/login.html')


def get_GeoBlacklist():
    if "user" in session:
        mycol = mydb["GEOIP_blacklist"]
        x = mycol.find()
        return x
    else:
        return render_template('/login.html')


@app.route('/firewall.html')
def firewall():
    if "user" in session:
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return render_template('/login.html')


@app.route('/blacklistIP', methods=['POST'])
def blacklistIP():
    if "user" in session:
        ipBLACK = request.form['ip_blacked']
        mycol = mydb["IPBlacklist"]
        mycol.insert_one({"ip": ipBLACK})
        update_blacklist_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return render_template('/login.html')


@app.route('/blacklistGEO', methods=['POST'])
def blacklistGEO():
    if "user" in session:
        geoip_blacked = request.form['geoip_blacked']
        mycol = mydb["GEOIP_blacklist"]
        mycol.insert_one({"country_code": geoip_blacked})
        update_geoIP_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return render_template('/login.html')


@app.route('/deleteIP', methods=['POST'])
def deleteIP():
    if "user" in session:
        deleteIP = request.form['deleteIP']
        mycol = mydb["IPBlacklist"]
        mycol.delete_one({"ip": deleteIP})
        update_blacklist_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return render_template('/login.html')


@app.route('/delete_geo', methods=['POST'])
def delete_geo():
    if "user" in session:
        delete_geo = request.form['delete_geo']
        mycol = mydb["GEOIP_blacklist"]
        mycol.delete_one({"country_code": delete_geo})
        update_geoIP_file()
        return render_template('firewall.html', results_1=get_blacklist(), results_2=get_GeoBlacklist(),
                               results_3=get_GeoBlacklist_options())
    else:
        return render_template('/login.html')


@app.route('/logsearch.html')
def logsearch():
    if "user" in session:
        return render_template('logsearch.html', results=get_logs())
    else:
        return render_template('/login.html')


def get_logs():
    if "user" in session:
        mycol = mydb["WAFLogs"]
        x = mycol.find().sort("time", -1)
        return x
    else:
        return render_template('/login.html')


@app.route('/search', methods=['POST'])
def search():
    if "user" in session:
        search_data = request.form['searched']
        search_field = request.form['field']
        mycol = mydb["WAFLogs"]
        myquery = {search_field: {"$regex": search_data}}
        x = mycol.find(myquery)
        return render_template('search.html', results=x)
    else:
        return render_template('/login.html')


@app.route('/logout')
def logout():
    if "user" in session:
        session.pop("user", None)
        return render_template('/login.html')
    else:
        return render_template('/login.html')


# @app.route('/')
# def e():
#   return render_template('')

def logger():
    mycol = mydb["WAFLogs"]
    f = subprocess.Popen(['tail', '-F', 'var/log/nginx/host.access.log'], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    while True:
        if p.poll(1):
            print(f.stdout.readline())
            mycol.insert_one(json.loads(f.stdout.readline()))
        time.sleep(5)


def update_blacklist_file():
    if os.path.exists('/etc/nginx/blacklist'):
        os.remove("/etc/nginx/blacklist")
    f = open("/etc/nginx/blacklist", "w+")
    mycol = mydb["IPBlacklist"]
    x = mycol.find()

    for data in x:
        if data["ip"] is not None:
            f.write("deny " + data["ip"] + ";\n")
    f.close()
    os.system('service nginx reload')


def update_geoIP_file():
    if os.path.exists('/etc/nginx/GEOIP_blacklist'):
        os.remove("/etc/nginx/GEOIP_blacklist")
    f = open("/etc/nginx/GEOIP_blacklist", "w+")
    mycol = mydb["GEOIP_blacklist"]
    x = mycol.find()

    for data in x:
        if data["country_code"] is not None:
            f.write(data["country_code"] + " no;\n")
    f.close()
    os.system('service nginx reload')


if __name__ == '__main__':
    update_blacklist_file()
    update_geoIP_file()
    logger = Thread(target=logger)
    logger.start()
    app.run(host='172.2.2.4', port=30, debug=True, ssl_context='adhoc')
