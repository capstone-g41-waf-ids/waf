import os
import time
import pymongo

connstring = os.environ['MONGODB_CONNSTRING'] #from container env
myclient = pymongo.MongoClient(connstring) #connect to mongo
mydb = myclient["database"]
mycol = mydb["WAFLogs"]
response_old = ''
old_result = ''
while True:
    response = os.popen(f"cat var/log/nginx/host.access.log").read()
    if response != response_old:
        result = ''
                
        for i in range(len(response)):
            #use a slice rather than index in case one string longer than other
            letter1=response_old[i:i+1]
            letter2=response[i:i+1]
            #create string with differences
            if letter1 != letter2:
                result+=letter2

        if result != old_result:
            print (result)
            x = mycol.insert_one(result)
            old_result = result

        response_old = response
        

    response = ''
    time.sleep(5)
