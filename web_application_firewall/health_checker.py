import os
import time
from threading import Thread

def health_check():
    while True:
        response = os.popen(f"ping -c 4 webgoat").read()
        if "4 packets received" in response:
            print(f"Ping Successful")
        else:
            print(f"Ping Unsuccessful")
        time.sleep(5)


try:
    print('health_check started')
    if __name__ == "__main__":
        Sniffer_thread1 = Thread(target=health_check)
        Sniffer_thread1.start()

    #KeyboardInterrupt Exit program
except KeyboardInterrupt:
    print('GOOOD BYE - KeyboardInterrupt')