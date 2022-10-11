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
"""
reflected xss
#xss = ["<", ">", "javascript", ".js", "<script", "script>", "alert", "bot", "\.", "\\", "\/", "//", onerror, onload, on<anything>]
"""
xss = "(?i)(<|&lt|%3C)*script(>|&gt;|%3E)*"
# < &lt; > &gt;
"""
&  "&amp;"
<  "&lt;"
>  "&gt;"
" "&quot;"
'  "&#039;"
\n "<br>"
"""

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

# FILE INCLUSION
"""
PATH TRAVERSAL

What to check for:
- IN REQUEST URL
    - \..\
    - \..\ but encoded
"""
traversal = "(?i)((((\.|%(25)?2e)+(\\|%(25)?5C)*(\\?\/|%((25)?2f|c0|af))+)+)|(\.|%(25)?2e){2,}|\\+)"
 # can be expanded, add further encoding


"""
LOCAL FILE INCLUSION

What to check for:
- IN REQUEST URL
    - ["<not https or http>:", "file=", "php:", "zip:", "data:", "expect:" "<directory traversal>", "%00"]

"""
lfi = "(?i)((.+((http|php|zip|data|expect):))|(%00)+)"
#include list of internal/restricted files?

"""
PHP FILE INCLUSIONS

What to check for:
- IN REQUEST URL
   - (.php)
   - include(), require()
"""
php_lfi = "(?i)((\.php)+)"


"""
REMOTE FILE INCLUSION

What to check for:
- IN REQUEST URL
   - URL (http(s), ftp(s), file)
   - IP - "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
   - Include functions (include(s), include_once, etc)
"""
rfi = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"


# Resource injection
# resource_injection = ""

# HTTP Response splitting
# http_response_splitting = ""

# Xpath and xquery injections
# xpath_xquery_injection = ""

# scripted http headers and expression language injections
# header = "<script>"

# encoding injections

# http request smuggling


blacklists = [traversal, lfi, php_lfi, rfi] #array of blacklists


def check(pkt): # can/should be further focused on specific parts of the packet... or regex can be specified (e.g. COOKIE:)
    output = ""
    for i in blacklists:
        output = re.search(i, pkt) # check the packet against each of the blacklists
        if output is not None: # if there is a regex match
            return "403" # return Forbidden status code
    return "200" # return OK status code