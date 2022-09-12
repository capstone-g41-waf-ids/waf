"""file name/structure not finalised. will be consolidated/adjusted"""

import ipaddress

#ELLEN ADDITION http methods
#check if method is allowed
# https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
bad_methods = ['PUT', 'MERGE', 'PATCH', 'DELETE', 'CONNECT', 'TRACE']
if packet.method in bad_methods, block packet
if packet.x_http_method_override <> "", block packet

#Special Element Injections
# ellen note - this seems super general , probably covered by other items?

#Command and OS Command Injections
#just check if any special chars are in packet url or body text
#https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
special_chars = ['!', '\"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`', '{', '|', '}', '~', '–', '‘']
#need to work out how to parse these properly so it wont block legit urls - look into it more
if [i for i in special_chars if i in packet.url], block #obvs not sufficient
if [i for i in special_chars if i in packet.body], block

#XXS Attempts

#SQL Injection

#XML and CRLF Injections

# Status Code Injections

#PHP File inclusions

#Resource injection

#HTTP Response splitting

#Xpath and xquery injections

#scripted http headers and expression language injections

#encoding injections

#improper local and remote file inclusions

#http request smuggling

#ip blocking

#ip parsing


def check(pkt):
