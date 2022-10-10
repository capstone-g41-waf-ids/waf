import json
import os
import time
import subprocess
import select
import pymongo
from threading import Thread
from flask import Flask, render_template, Response, request, session

app = Flask(__name__)
app.secret_key = "hd72bd8a"

connstring = os.environ['MONGODB_CONNSTRING'] #from container env
myclient = pymongo.MongoClient(connstring) #connect to mongo
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
            if data["username"] != None and data["password"] != None:
                session["user"] = username_local
                return render_template('/logsearch.html')
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
        

@app.route('/edituser.html')
def edituser():
    if "user" in session:
        return render_template('edituser.html')
    else:
        return render_template('/login.html')

@app.route('/firewall.html')
def firewall():
    if "user" in session:
        return render_template('firewall.html')
    else:
        return render_template('/login.html')

@app.route('/firewall.php')
def firewallphp():
    if "user" in session:
        return render_template('firewall.php')
    else:
        return render_template('/login.html')

@app.route('/forgotpass.html')
def forgotpass():
    if "user" in session:
        return render_template('forgotpass.html')
    else:
        return render_template('/login.html')

@app.route('/logsearch.html')
def logsearch():
    if "user" in session:
        mycol = mydb["WAFLogs"]
        x = mycol.find()
        return render_template('logsearch.html', results = x)
    else:
        return render_template('/login.html')

@app.route('/search', methods=['POST'])
def search():
    if "user" in session:
        search_data = request.form['searched']
        search_field = request.form['field']
        mycol = mydb["WAFLogs"]
        myquery = {search_field : { "$regex": search_data }}
        x = mycol.find(myquery)
        return render_template('search.html', results = x)
    else:
        return render_template('/login.html')

@app.route('/logout')
def logout():
    if "user" in session:
        session.pop("user", None)
        return render_template('/login.html')
    else:
        return render_template('/login.html')


#@app.route('/')
#def e():
#   return render_template('')

def logger():
    mycol = mydb["WAFLogs"]
    f = subprocess.Popen(['tail','-F','var/log/nginx/host.access.log'],\
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    while True:
        if p.poll(1):
            print(f.stdout.readline())
            mycol.insert_one(json.loads(f.stdout.readline()))
        time.sleep(5)
    
if __name__ == '__main__':
    logger = Thread(target=logger)
    logger.start()
    app.run(host='172.2.2.4',port = 30, debug = True, ssl_context='adhoc')

