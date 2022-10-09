import os

from flask import Flask, render_template, Response, request

app = Flask(__name__)

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
    return render_template('logsearch.html')

#@app.route('/')
#def e():
#   return render_template('')


if __name__ == '__main__':
    app.run(host='172.2.2.4',port = 30, debug = True)