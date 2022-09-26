"""file name/structure not finalised. will be consolidated/adjusted"""

import re

CASE_INSENSITIVE = "(?i)"

#ELLEN ADDITION http methods
#check if method is allowed
# https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
#bad_methods = "(PUT|MERGE|PATCH|DELETE|CONNECT|TRACE)"

#Special Element Injections
# ellen note - this seems super general , probably covered by other items?

#Command and OS Command Injections
#just check if any special chars are in packet url or body text
#https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
#special_chars = ['!', '\"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`', '{', '|', '}', '~', '–', '‘']

#XSS Attempts
#reflected xss
#xss = ["<", ">", "javascript", ".js", "<script", "script>", "alert", "bot", "\.", "\\", "\/", "//"]

#stored xss

#SQL Injection
# stored in database
#sqli = "(?i)"
#sqli = ["insert", "select", "union", "alter", "create", "delete", "drop", "execute", "exec", "merge", "update", "*", "<", ">", "1=1", "'1'", "--", "1'1", " = ", ";" ]
# for < > need to filter out expected tags

#XML and CRLF Injections
#xml = ""

# Status Code Injections
#status_code_injections = ""

# path traversal
# in URL
traversal = "(?i)((((\.|%(25)?2e)+(\\|%(25)?5C)*(\\?\/|%((25)?2f|c0|af))+)+)|(\.|%(25)?2e){2,}|\\+)"

#IN URL
lfi = "(?i)((.+((http|php|zip|data|expect):))|(%00)+)"
#["<not https or http>:", "file=", "php:", "zip:", "data:", "expect:" "<directory traversal>", "%00"]

#PHP File inclusions (literally just lfi)
php_lfi = "(?i)((\.php)+)"

#remote file includsion
# IN URL
#rfi = ["file"]
## ALSO = http more than once, <- captured in lfi blacklist

#Resource injection
#resource_injection = ""

#HTTP Response splitting
#http_response_splitting = ""

#Xpath and xquery injections
#xpath_xquery_injection = ""

#scripted http headers and expression language injections
#header = "<script>"

#encoding injections



#http request smuggling

#ip blocking

#ip parsing

blacklists = [traversal, lfi, php_lfi] #array of blacklists

#can/should be further focused on specific parts of the packet... or regex can be specified (e.g. COOKIE:)
def check(pkt):
    output = ""
    for i in blacklists:
        output = re.search(i, pkt) #check the packet against each of the blacklists
        if output is not None: # if there is a regex match
            return "403" #return Forbidden status code
    return "200" #return OK status code