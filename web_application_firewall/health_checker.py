import os
import time

while True:
    response = os.popen(f"curl --max-time 5 -I http://webgoat:8080/WebGoat").read()
    if "HTTP/1.1 302 Found" in response:
        print(f"curl Successful")
    else:
        print(f"curl Unsuccessful")

    time.sleep(5)
