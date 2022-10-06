import json
import os
import time
import subprocess
import select
import pymongo

connstring = os.environ['MONGODB_CONNSTRING'] #from container env
myclient = pymongo.MongoClient(connstring) #connect to mongo
mydb = myclient["database"]
mycol = mydb["IPBlacklist"]


#f = subprocess.Popen(['tail','-F','var/log/nginx/host.access.log'],\
#        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
#p = select.poll()
#p.register(f.stdout)

for x in mycol.find():
    print(x)


#while True:
#    if p.poll(1):
#       print(f.stdout.readline())
#        mycol.insert_one(json.loads(f.stdout.readline()))
#    time.sleep(5)

#check for new entire
#check for duplicated entry