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
        "method": packet[HTTPRequest].Method.decode(),
        "path": packet[HTTPRequest].Path.decode(),
        "http_version": packet[HTTPRequest].Http_Version.decode(),
        "a_im": packet[HTTPRequest].A_IM.decode(),
        "accept": packet[HTTPRequest].Accept.decode(),
        "accept_charset": packet[HTTPRequest].Accept_Charset.decode(),
        "accept_datetime": packet[HTTPRequest].Accept_Datetime.decode(),
        "accept_encoding": packet[HTTPRequest].Accept_Encoding.decode(),
        "accept_language": packet[HTTPRequest].Accept_Language.decode(),
        "access_control_request_headers": packet[HTTPRequest].Access_Control_Request_Headers.decode(),
        "access_control_request_method": packet[HTTPRequest].Access_Control_Request_Method.decode(),
        "authorization": packet[HTTPRequest].Authorization.decode(),
        "cache_control": packet[HTTPRequest].Cache_Control.decode(),
        "connection": packet[HTTPRequest].Connection.decode(),
        "content_length": packet[HTTPRequest].Content_Length.decode(),
        "content_md5": packet[HTTPRequest].Content_MD5.decode(),
        "content_type": packet[HTTPRequest].Content_Type.decode(),
        "cookie": packet[HTTPRequest].Cookie.decode(),
        "dnt": packet[HTTPRequest].DNT.decode(),
        "date": packet[HTTPRequest].Date.decode(),
        "expect": packet[HTTPRequest].Expect.decode(),
        "forwarded": packet[HTTPRequest].Forwarded.decode(),
        "from": packet[HTTPRequest].From.decode(),
        "front_end_https": packet[HTTPRequest].Front_End_Https.decode(),
        "http2_settings": packet[HTTPRequest].HTTP2_Settings.decode(),
        "host": packet[HTTPRequest].Host.decode(),
        "if_match": packet[HTTPRequest].If_Match.decode(),
        "if_modified_since": packet[HTTPRequest].If_Modified_Since.decode(),
        "if_none_match": packet[HTTPRequest].If_None_Match.decode(),
        "if_range": packet[HTTPRequest].If_Range.decode(),
        "if_unmodified_since": packet[HTTPRequest].If_Unmodified_Since.decode(),
        "keep_alive": packet[HTTPRequest].Keep_Alive.decode(),
        "max_forwards": packet[HTTPRequest].Max_Forwards.decode(),
        "origin": packet[HTTPRequest].Origin.decode(),
        "permanent": packet[HTTPRequest].Permanent.decode(),
        "pragma": packet[HTTPRequest].Pragma.decode(),
        "proxy_authorization": packet[HTTPRequest].Proxy_Authorization.decode(),
        "proxy_connection": packet[HTTPRequest].Proxy_Connection.decode(),
        "range": packet[HTTPRequest].Range.decode(),
        "referer": packet[HTTPRequest].Referer.decode(),
        "save_data": packet[HTTPRequest].Save_Data.decode(),
        "te": packet[HTTPRequest].TE.decode(),
        "upgrade": packet[HTTPRequest].Upgrade.decode(),
        "upgrade_insecure_requests": packet[HTTPRequest].Upgrade_Insecure_Requests.decode(),
        "user_agent": packet[HTTPRequest].User_Agent.decode(),
        "via": packet[HTTPRequest].Via.decode(),
        "warning": packet[HTTPRequest].Warning.decode(),
        "x_att_deviceid": packet[HTTPRequest].X_ATT_DeviceId.decode(),
        "x_correlation_id": packet[HTTPRequest].X_Correlation_ID.decode(),
        "x_csrf_token": packet[HTTPRequest].X_Csrf_Token.decode(),
        "x_forwarded_for": packet[HTTPRequest].X_Forwarded_For.decode(),
        "x_forwarded_host": packet[HTTPRequest].X_Forwarded_Host.decode(),
        "x_forwarded_proto": packet[HTTPRequest].X_Forwarded_Proto.decode(),
        "x_http_method_override": packet[HTTPRequest].X_Http_Method_Override.decode(),
        "x_request_id": packet[HTTPRequest].X_Request_ID.decode(),
        "x_requested_with": packet[HTTPRequest].X_Requested_With.decode(),
        "x_uidh": packet[HTTPRequest].X_UIDH.decode(),
        "x_wap_profile": packet[HTTPRequest].X_Wap_Profile.decode(),
        "unknown_headers": packet[HTTPRequest].Unknown_Headers.decode(),

        "source": packet[IP].src,
    }

    coll.insert_one(log)
