import os
import time


while True:
    response = os.popen(f"ping -c 4 webgoat").read()
    if "4 packets received" in response:
        print(f"Ping Successful")
    else:
        print(f"Ping Unsuccessful")
    time.sleep(5)