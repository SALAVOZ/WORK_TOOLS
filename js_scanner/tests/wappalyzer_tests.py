import requests
import unittest
from app.wappalyzer import Wappalyzer
from app.requester import Requester


class wappalyzer_test(unittest.TestCase):
    def setUp(self) -> None:
        r = Requester('apache.org')
        r.check_connection()
        response_http = r.response_http
        response_https = r.response_https
        self.wappalyzer = Wappalyzer(html_text='None', requester=r)
        print(self.wappalyzer.frameworks_and_version)

    def test_wappalyzer__parse_js_success(self):
        url: str = 'https://code.jquery.com/jquery-3.6.4.min.js'
        framework, version = self.wappalyzer.parse_js(url)
        self.assertEqual(framework, 'jQuery')
        self.assertEqual(version, '3.6.4')

    def test_wappalyzer__parse_js_fail(self):
        url: str = 'https://code.jquery.com/jquery-3.6.4.min.js1'
        framework, version = self.wappalyzer.parse_js(url)
        self.assertEqual(framework, '')
        self.assertEqual(version, '')
        url: str = 'https://dadwadwadwadaw.ru'
        framework, version = self.wappalyzer.parse_js(url)
        self.assertEqual(framework, '')
        self.assertEqual(version, '')

    def test_wappalyzer_parse_js_file__get_comments_success(self):
        url: str = 'https://code.jquery.com/jquery-3.6.4.min.js'
        try:
            html_text: str = requests.get(url, verify=False).text
        except AttributeError:
            print('Error while connecting to url')
            raise ValueError
        comments = self.wappalyzer.parse_js_file__get_comments(html_text)
        self.assertNotEqual(len(comments), 0)

    def test_wappalyzer_parse_js_file__get_comments_fail(self):
        url: str = 'https://code.jquery.com/jquery-3.6.4.min.js1'
        try:
            html_text: str = requests.get(url, verify=False).text
        except AttributeError:
            print('Error while connecting to url')
            raise ValueError
        comments = self.wappalyzer.parse_js_file__get_comments(html_text)
        self.assertNotEqual(len(comments), 0)
        html_text: str = ''
        comments = self.wappalyzer.parse_js_file__get_comments(html_text)
        self.assertEqual(len(comments), 0)

    def test_wappalyzer_parse_js_file__get_framework_and_version_success(self):
        url: str = 'https://code.jquery.com/jquery-3.6.4.min.js'
        try:
            html_text: str = requests.get(url, verify=False).text
        except AttributeError:
            print('Error while connecting to url')
            raise ValueError
        first_comment = self.wappalyzer.parse_js_file__get_comments(html_text)[0]
        framework, version = self.wappalyzer.parse_js_file__get_framework_and_version(first_comment)
        self.assertEqual(framework, 'jQuery')
        self.assertEqual(version, '3.6.4')

    def test_wappalyzer_parse_js_file__get_framework_and_version_fail(self):
        url: str = 'https://code.jquery.com/jquery-3.6.4.min.js1'
        try:
            html_text: str = requests.get(url, verify=False).text
        except AttributeError:
            print('Error while connecting to url')
            raise ValueError
        first_comment = self.wappalyzer.parse_js_file__get_comments(html_text)[0]
        framework, version = self.wappalyzer.parse_js_file__get_framework_and_version(first_comment)
        self.assertEqual(framework, '')
        self.assertEqual(version, '')
