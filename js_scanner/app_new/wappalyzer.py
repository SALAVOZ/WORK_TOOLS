import bs4

import app_new.utils
from app.constants import LXML_STR
from app_new.models import Technology
import app.requester
import app.constants
import re
import requests


'''
Класс, свой ваппалайзер. Определяет версии и технологии, находит cve веб серверов исходя из версии, полученной из http-заголовка Server
'''
class Wappalyzer:
    def __init__(self, response: requests.Response):
        self.bs = bs4.BeautifulSoup(response.text, app.constants.LXML_STR)
        if 'Server' in response.headers:
            self.server_header = response.headers['Server']
        if 'Via' in response.headers:
            self.via_header = response.headers['Via']

    def parse_js(self):
        scripts = [script['src'] for script in self.bs.findAll('script', src=True)]
        meta = {
            meta['name'].lower():
                meta['content'] for meta in self.bs.findAll(
                    'meta', attrs=dict(name=True, content=True))
        }
        for script_src in scripts:
            framework, version = self.parse_src(script_src)

    def parse_src(self, url: str) -> tuple[str, str]:
        if 'http://' in url or 'https://' in url:
            response: requests.Response = app_new.utils.make_get_request(url)
            html_text = response.text if response is not None else ''
            pattern = re.compile(app.constants.REGEX_TO_GET_COMMENTS)
            found_comments = pattern.findall(html_text)

            for comment in found_comments:
                pattern = re.compile(app.constants.REGEX_TO_GET_FRAMEWORK_AND_VERSION)
                found_string = pattern.search(comment[:200])
                if found_string is not None:
                    try:
                        framework_and_version = re.sub(r'[-*!/]', '', found_string.group(0)).strip()
                        framework, version = framework_and_version.split()
                        version = version.replace('v', '')
                        return framework, version
                    except:
                        pass
                return '', ''
            return '', ''
        else:
            response = app_new.utils.make_get_request(url)
            html_text = response.text if response is not None else ''
            pattern = re.compile(app.constants.REGEX_TO_GET_COMMENTS)
            found_comments = pattern.findall(html_text)
            for comment in found_comments:
                framework, version = self.parse_js_file__get_framework_and_version(comment)
                return framework, version
            return '', ''
            #return self.parse_js__get_comments_and_get_framework_and_version_from_response(response)


class Wappalyzer:
    def __init__(self) -> None:
        self.frameworks_and_version_http = []
        self.frameworks_and_version_https = []
        self.web_server_version = {}
        self.server_header = {}
        for protocol in [app.constants.HTTP_STR, app.constants.HTTPS_STR]:
            server_header = requester.get_header_server(protocol)
            if server_header is not None:
                self.server_header = self.parse_web_server(server_header)
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
            framework, version = self.parse_js(script_src, protocol)
            if protocol == app.constants.HTTP_STR:
                self.frameworks_and_version_http.append({'framework': framework, 'version': version})
            if protocol == app.constants.HTTPS_STR:
                self.frameworks_and_version_https.append({'framework': framework, 'version': version})

    def parse_js(self, url: str, protocol: str) -> tuple[str, str]:
        if 'http://' in url or 'https://' in url:
            try:
                response: requests.Response = requests.get(url=url)
            except requests.exceptions.ConnectionError:
                response = None
            return self.parse_js__get_comments_and_get_framework_and_version_from_response(response)
        else:
            response = self.requester.make_request_on_one_protocol(directory=url, protocol=protocol)
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
        found_string = pattern.search(string[:200])
        if found_string is not None:
            try:
                framework_and_version = re.sub(r'[-*!/]', '', found_string.group(0)).strip()
                framework, version = framework_and_version.split()
                version = version.replace('v', '')
                return framework, version
            except:
                pass
        return '', ''

    @staticmethod
    def parse_web_server(server_header: str) -> dict | None:
        to_return = {}
        server_header_uppercase = server_header.upper()
        if 'nginx'.upper() in server_header_uppercase:
            to_return['name'] = 'nginx'
        if 'apache'.upper() in server_header_uppercase:
            to_return['name'] = 'apache'
        version = re.search(r'\d+?.\d+?.\d+?', server_header_uppercase)
        if version == '' or version is None:
            return None
        to_return['version'] = version.group(0)
        try:
            a = to_return['name']
            return to_return
        except KeyError:
            pass
        return None

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
