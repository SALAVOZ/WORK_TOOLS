from app.requester import Requester
from socket import gaierror
import unittest


class RequesterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.host = 'scanme.nmap.org'

    def test_requester__validate_host__success(self):
        ip_address_v4 = '1.1.1.1'
        requester = Requester()
        result = requester.validate_host(ip_address_v4)
        self.assertEqual(result, ip_address_v4)

    def test_requester__validate_host__fail(self):
        ip_addresses_v4 = ['1.1.1.1.1', 'awdad', '123123', 'daw,e12eda']
        requester = Requester()
        for ip_address_v4 in ip_addresses_v4:
            with self.assertRaises(gaierror):
                requester.validate_host(ip_address_v4)

    def test_requester__check_connection_success(self):
        requester = Requester(self.host)
        requester.check_connection()
        self.assertNotEqual(requester.response_http, None)
        self.assertEqual(requester.response_https, None)

    def test_requester__check_connection_fail(self):
        requester = Requester('chebupel.ru')
        requester.check_connection()
        self.assertEqual(requester.response_http, None)
        self.assertEqual(requester.response_https, None)

    def test_make_request__success(self):
        requester = Requester(self.host)
        requester.check_connection()
        response_http, response_https = requester.make_request(directory='ewadawdawdadax')
        self.assertEqual(response_http.status_code, 404)
        self.assertEqual(response_https, None)

    def test_make_request__fail(self):
        requester = Requester('chebupel.ru') # у данного хоста не открыты 80 и 443 порты
        requester.check_connection()
        requester.make_request(directory='dawdwadad')
        with self.assertRaises(AttributeError):
            self.assertEqual(requester.response_https.status_code, 404)

    def test_get_html__success(self):
        requester = Requester(self.host)
        requester.check_connection()
        html = requester.get_html('http')
        self.assertNotEqual(html, None)

    def test_get_html__fail(self):
        requester = Requester(self.host)
        requester.check_connection()
        with self.assertRaises(ValueError):
            html = requester.get_html('213213213213')

    def test_get_header_server__success(self):
        requester = Requester(self.host)
        requester.check_connection()
        header = requester.get_header_server('http')
        self.assertNotEqual(header, None)

    def test_get_header_server__fail(self):
        requester = Requester(self.host)
        requester.check_connection()
        with self.assertRaises(ValueError):
            header = requester.get_header_server('123123')

    def test_get_response_by_protocol__success(self):
        requester = Requester(self.host)
        requester.check_connection()
        response_http = requester.get_response_by_protocol('http')
        response_https = requester.get_response_by_protocol('https')
        self.assertEqual(type(response_http.status_code), int)
        self.assertEqual(response_https, None)

    def test_get_response_by_protocol__fail(self):
        requester = Requester(self.host)
        requester.check_connection()
        with self.assertRaises(ValueError):
            response = requester.get_response_by_protocol('gfedaw223213')

    def test_get_host__success(self):
        requester = Requester()
        host = requester.get_host()
        self.assertEqual(host, None)
        requester = Requester('1.1.1.1')
        host = requester.get_host()
        self.assertEqual(host, '1.1.1.1')