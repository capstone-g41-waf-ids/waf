import os

from flask import Flask, render_template, Response, request

app = Flask(__name__)

@app.route('/serverstatus.html')
def health_check():
    response = os.popen(f"curl --max-time 5 -I http://webgoat:8080/WebGoat").read()
    if "HTTP/1.1 302 Found" in response:
        return render_template('serverstatussuccess.html')
    else:
       return render_template('serverstatusunsuccessfull.html')


@app.route('/')
def index():
    return render_template('login.html')


if __name__ == '__main__':
    app.run(host='172.2.2.4',port = 80, debug = True)