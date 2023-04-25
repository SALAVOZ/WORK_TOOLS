from bs4 import BeautifulSoup
from app.constants import LXML_STR
from app.requester import Requester
import app.requester
import app.constants
import re
import requests

'''
Класс, свой ваппалайзер. Определяет версии и технологии, находит cve веб серверов исходя из версии, полученной из http-заголовка Server
'''


class Wappalyzer:
    def __init__(self, requester: Requester) -> None:
        self.requester: Requester = requester
        self.frameworks_and_version_http = []
        self.frameworks_and_version_https = []
        for protocol in [app.constants.HTTP_STR, app.constants.HTTPS_STR]:
            html = self.requester.get_html(protocol)
            if html is not None:
                self.parse_html(html, protocol)

    def parse_html(self, html: str, protocol: str) -> None:
        soup = BeautifulSoup(html, app.constants.LXML_STR)
        scripts = [script['src'] for script in
                        soup.findAll('script', src=True)]
        meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                    'meta', attrs=dict(name=True, content=True))
        }
        for script_src in scripts:
            framework, version = self.parse_js(script_src)
            if protocol == app.constants.HTTP_STR:
                self.frameworks_and_version_http.append({'framework': framework, 'version': version})
            if protocol == app.constants.HTTPS_STR:
                self.frameworks_and_version_https.append({'framework': framework, 'version': version})

    def parse_js(self, url: str) -> tuple[str, str]:
        if 'http://' in url or 'https://' in url:
            try:
                response: requests.Response = requests.get(url=url)
            except requests.exceptions.ConnectionError:
                response = None
            return self.parse_js__get_comments_and_get_framework_and_version_from_response(response)
        else:
            response_http, response_https = self.requester.make_request(directory=url)
            for response in [response_http, response_https]:
                return self.parse_js__get_comments_and_get_framework_and_version_from_response(response)

    def parse_js__get_comments_and_get_framework_and_version_from_response(self, response: requests.Response) -> tuple[str, str]:
        html_text = response.text if response is not None else ''
        comments = self.parse_js_file__get_comments(html_text)
        for comment in comments:
            framework, version = self.parse_js_file__get_framework_and_version(comment)
            return framework, version
        return '', ''

    @staticmethod
    def parse_js_file__get_comments(html_text: str) -> list:
        pattern = re.compile(app.constants.REGEX_TO_GET_COMMENTS)
        found_comments = pattern.findall(html_text)
        return found_comments

    @staticmethod
    def parse_js_file__get_framework_and_version(string: str) -> tuple[str, str]:
        pattern = re.compile(app.constants.REGEX_TO_GET_FRAMEWORK_AND_VERSION)
        found_string = pattern.search(string)
        if found_string is not None:
            framework_and_version = re.sub(r'[-*!/]', '', found_string.group(0)).strip()
            framework, version = framework_and_version.split()
            version = version.replace('v', '')
            return framework, version
        return '', ''

    @staticmethod
    def comparing_version(version, comparing):
        '''Сравнивает версии.'''
        version_splited = version.split('.')
        comparing_splited = comparing.split('.')
        if len(version_splited) == len(comparing_splited):
            for i in range(len(version_splited)):
                try:
                    if int(version_splited[i]) > int(comparing_splited[i]):
                        return True
                    if int(version_splited[i]) == int(comparing_splited[i]):
                        continue
                    if int(version_splited[i]) < int(comparing_splited[i]):
                        return False
                except Exception:
                    print('Error in comparing version')
        print('Error in comparing. Not equal length of args')
        return False
