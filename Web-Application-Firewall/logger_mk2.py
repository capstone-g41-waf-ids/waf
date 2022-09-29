import os
import pymongo

def get_db():
    connstring = os.environ['MONGODB_CONNSTRING'] #from container env
    print(connstring) #test
    client = pymongo.MongoClient(connstring) #connect to mongo
    db = client['database'] #get db
    collection = db['WAFLogs'] #get collection for waf log storage
    return collection

coll = get_db()