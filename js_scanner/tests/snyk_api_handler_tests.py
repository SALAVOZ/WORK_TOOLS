from app.snyk_api_handler import snyk_api_handler
import unittest


class snyk_handler_test(unittest.TestCase):
    def setUp(self) -> None:
        self.snyk_handler = snyk_api_handler()

    def test_snyk_api__parse_snyk(self):
        jquery = [{
            'framework': 'jQuery', 'version': '1.5.2'
        }]
        result = self.snyk_handler.parse_snyk(jquery)
        print(result)
        self.assertNotEqual(len(result), 0)

    def test_wappalyzer__parse_nginx_success(self):
        result = self.snyk_handler.parse_nginx_site('1.21.0')
        self.assertNotEqual(result, [])

    def test_wappalyzer__parse_nginx_fail(self):
        result = self.snyk_handler.parse_nginx_site('wadawdwad')
        self.assertEqual(result, [])

    def test_wappalyzer__parse_apache_success(self):
        result = self.snyk_handler.parse_apache_site('2.4.25')
        self.assertNotEqual(result, [])

    def test_wappalyzer__parse_apache_fail(self):
        result = self.snyk_handler.parse_apache_site('awdwad')
        self.assertEqual(result, [])
