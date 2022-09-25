"""WIP DONT LOOK"""

import os
import pymongo
from scapy import *
from scapy.layers.http import *

""" DATABASE LOGGING STUFF - needs to be  linked in with roys waf.py """

def get_db():
    connstring = os.environ['MONGODB_CONNSTRING'] #from container env
    print(connstring) #test
    client = pymongo.MongoClient(connstring) #connect to mongo
    db = client['database'] #get db
    collection = db['WAFLogs'] #get collection for waf log storage
    return collection

def close_db():
    """"""

def log_packet(packet): #this will go in process packet probably
    """
    This function sends logs packets in db
    """

    coll = get_db()

    log = {
        "packet": packet.content, # contents of packet in string form
        "response": packet.response, # packet response, including
        "blocked": packet.blocked #  if packet was blocked and why. captured from WAF_logger.py
    }

    coll.insert_one(log)
