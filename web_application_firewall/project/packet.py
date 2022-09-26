"""file name/structure not finalised. will be consolidated/adjusted"""

class Packet:
    def __init__(self, method, src, dst, path, http_version, a_im, accept, accept_charset, accept_datetime, accept_encoding, accept_language, access_control_request_headers, access_control_request_method, authorization, cache_control, connection, content_length, content_md5, content_type, cookie, dnt, date, expect, forwarded, user_email, front_end_https, http2_settings, host, if_match, if_modified_since, if_none_match, if_range, if_unmodified_since, keep_alive, max_forwards, origin, permanent, pragma, proxy_authorization, proxy_connection, range, referer, save_data, te, upgrade, upgrade_insecure_requests, user_agent, via, warning):
        # delete unecessary parameters - will leave all in until done with rest.
        # this is HTTP request packet.
        self.method = method
        self.src = src
        self.dst = dst
        self.path = path
        self.http_version = http_version
        self.a_im = a_im
        self.accept = accept
        self.accept_charset = accept_charset
        self.accept_datetime = accept_datetime
        self.accept_encoding = accept_encoding
        self.accept_language = accept_language
        self.access_control_request_headers = access_control_request_headers
        self.access_control_request_method = access_control_request_method
        self.authorization = authorization
        self.cache_control = cache_control
        self.connection = connection
        self.content_length = content_length
        self.content_md5 = content_md5
        self.content_type = content_type
        self.cookie = cookie
        self.dnt = dnt
        self.date = date
        self.expect = expect
        self.forwarded = forwarded
        self.user_email = user_email
        self.front_end_https = front_end_https
        self.http2_settings = http2_settings
        self.host = host
        self.if_match = if_match
        self.if_modified_since = if_modified_since
        self.if_none_match = if_none_match
        self.if_range = if_range
        self.if_unmodified_since = if_unmodified_since
        self.keep_alive = keep_alive
        self.max_forwards = max_forwards
        self.origin = origin
        self.permanent = permanent
        self.pragma = pragma
        self.proxy_authorization = proxy_authorization
        self.proxy_connection = proxy_connection
        self.range = range
        self.referer = referer
        self.save_data = save_data
        self.te = te
        self.upgrade = upgrade
        self.upgrade_insecure_requests = upgrade_insecure_requests
        self.user_agent = user_agent
        self.via = via
        self.warning = warning

        """
        method = packet[HTTPRequest].Method.decode(),
        path = packet[HTTPRequest].Path.decode(),
        http_version = packet[HTTPRequest].Http_Version.decode(),
        a_im = packet[HTTPRequest].A_IM.decode(),
        accept = packet[HTTPRequest].Accept.decode(),
        accept_charset = packet[HTTPRequest].Accept_Charset.decode(),
        accept_datetime = packet[HTTPRequest].Accept_Datetime.decode(),
        accept_encoding = packet[HTTPRequest].Accept_Encoding.decode(),
        accept_language = packet[HTTPRequest].Accept_Language.decode(),
        access_control_request_headers = packet[HTTPRequest].Access_Control_Request_Headers.decode(),
        access_control_request_method = packet[HTTPRequest].Access_Control_Request_Method.decode(),
        authorization = packet[HTTPRequest].Authorization.decode(),
        cache_control = packet[HTTPRequest].Cache_Control.decode(),
        connection = packet[HTTPRequest].Connection.decode(),
        content_length = packet[HTTPRequest].Content_Length.decode(),
        content_md5 = packet[HTTPRequest].Content_MD5.decode(),
        content_type = packet[HTTPRequest].Content_Type.decode(),
        cookie = packet[HTTPRequest].Cookie.decode(),
        dnt = packet[HTTPRequest].DNT.decode(),
        date = packet[HTTPRequest].Date.decode(),
        expect = packet[HTTPRequest].Expect.decode(),
        forwarded = packet[HTTPRequest].Forwarded.decode(),
        user_email = packet[HTTPRequest].From.decode(),
        front_end_https = packet[HTTPRequest].Front_End_Https.decode(),
        http2_settings = packet[HTTPRequest].HTTP2_Settings.decode(),
        host = packet[HTTPRequest].Host.decode(),
        if_match = packet[HTTPRequest].If_Match.decode(),
        if_modified_since = packet[HTTPRequest].If_Modified_Since.decode(),
        if_none_match = packet[HTTPRequest].If_None_Match.decode(),
        if_range = packet[HTTPRequest].If_Range.decode(),
        if_unmodified_since = packet[HTTPRequest].If_Unmodified_Since.decode(),
        keep_alive = packet[HTTPRequest].Keep_Alive.decode(),
        max_forwards = packet[HTTPRequest].Max_Forwards.decode(),
        origin = packet[HTTPRequest].Origin.decode(),
        permanent = packet[HTTPRequest].Permanent.decode(),
        pragma = packet[HTTPRequest].Pragma.decode(),
        proxy_authorization = packet[HTTPRequest].Proxy_Authorization.decode(),
        proxy_connection = packet[HTTPRequest].Proxy_Connection.decode(),
        range = packet[HTTPRequest].Range.decode(),
        referer = packet[HTTPRequest].Referer.decode(),
        save_data = packet[HTTPRequest].Save_Data.decode(),
        te = packet[HTTPRequest].TE.decode(),
        upgrade = packet[HTTPRequest].Upgrade.decode(),
        upgrade_insecure_requests = packet[HTTPRequest].Upgrade_Insecure_Requests.decode(),
        user_agent = packet[HTTPRequest].User_Agent.decode(),
        via = packet[HTTPRequest].Via.decode(),
        warning = packet[HTTPRequest].Warning.decode(),
        x_att_deviceid = packet[HTTPRequest].X_ATT_DeviceId.decode(),
        x_correlation_id = packet[HTTPRequest].X_Correlation_ID.decode(),
        x_csrf_token = packet[HTTPRequest].X_Csrf_Token.decode(),
        x_forwarded_for = packet[HTTPRequest].X_Forwarded_For.decode(),
        x_forwarded_host = packet[HTTPRequest].X_Forwarded_Host.decode(),
        x_forwarded_proto = packet[HTTPRequest].X_Forwarded_Proto.decode(),
        x_http_method_override = packet[HTTPRequest].X_Http_Method_Override.decode(),
        x_request_id = packet[HTTPRequest].X_Request_ID.decode(),
        x_requested_with = packet[HTTPRequest].X_Requested_With.decode(),
        x_uidh = packet[HTTPRequest].X_UIDH.decode(),
        x_wap_profile = packet[HTTPRequest].X_Wap_Profile.decode(),
        unknown_headers = packet[HTTPRequest].Unknown_Headers.decode(),

        source = packet[IP].src,
        """

    def process(self):
        print("this does something")