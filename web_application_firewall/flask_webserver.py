import json
import os
import time
import subprocess
import select
import pymongo
from threading import Thread
from flask import Flask, render_template, Response, request

app = Flask(__name__)

connstring = os.environ['MONGODB_CONNSTRING'] #from container env
myclient = pymongo.MongoClient(connstring) #connect to mongo
mydb = myclient["database"]


@app.route('/')
def index():
    return render_template('login.html')

@app.route('/serverstatus.html')
def serverstatus():
    response = os.popen(f"curl --max-time 5 -I http://webgoat:8080/WebGoat").read()
    if "HTTP/1.1 302 Found" in response:
        return render_template('serverstatussuccess.html')
    else:
       return render_template('serverstatusunsuccessfull.html')

@app.route('/edituser.html')
def edituser():
    return render_template('edituser.html')

@app.route('/firewall.html')
def firewall():
    return render_template('firewall.html')

@app.route('/firewall.php')
def firewallphp():
    return render_template('firewall.php')

@app.route('/forgotpass.html')
def forgotpass():
    return render_template('forgotpass.html')

@app.route('/logsearch.html')
def logsearch():
    mycol = mydb["WAFLogs"]
    x = mycol.find()
 
    return render_template('logsearch.html', results = x)

@app.route('/search', methods=['POST'])
def search():
    search_data = request.form['searched']
    search_field = request.form['field']
    mycol = mydb["WAFLogs"]
    myquery = {search_field : search_data}
    x = mycol.find(myquery)
    return render_template('search.html', results = x)


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
    app.run(host='172.2.2.4',port = 30, debug = True)