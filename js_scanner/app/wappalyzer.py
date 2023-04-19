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
    def __init__(self, html_text: str, requester: Requester) -> None:
        self.html: str = html_text
        self.requester: Requester = requester
        if self.html is not None:
            self.parse_html()

    def parse_html(self) -> None:
        soup = BeautifulSoup(self.html, app.constants.LXML_STR)
        self.scripts = [script['src'] for script in
                        soup.findAll('script', src=True)]
        self.meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                    'meta', attrs=dict(name=True, content=True))
        }
        self.frameworks_and_version = []
        for script_src in self.scripts:
            framework, version = self.parse_js(script_src)
            self.frameworks_and_version.append({'framework': framework, 'version': version})

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
            framework_and_version = re.sub(r'[*!/]', '', found_string.group(0)).strip()
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











'''

            try:
                technologie = self.get_js_technologie(path)
                version = self.get_js_through_url(path)
            except requests.exceptions.ConnectionError:
                print('=' * 10)
                print('Error to connect to ' + path)
                print('=' * 10)
        else:
            technologie = self.get_js_technologie(path)
            version = self.get_js_through_path(path, schema, technologie)# ДОРАБОТАТЬ ФУНКЦИЮ
        self.js_frameworks.append({
            'path': path,
            'version': version,
            'technologie': technologie
            })
















































    def get_js_through_path(self, path, schema, technologie):
        try:
            url = f'{self.host}/{path}'.replace('//', '/')
            url = schema + '://' + url
            res = requests.get(url, verify=False)
            if res.status_code == 404 and self.dir is not None:
                url = f'{self.host}/{self.dir}/{path}'.replace('//', '/')
                url = schema + '://' + url
                res = requests.get(url, verify=False)
            if res.request.url != url:
                res = requests.get(res.request.url, verify=False, allow_redirects=True)
            if res.status_code == 200:
                re_result = re.search(r'v(\d+\.\d+\.\d+)', res.request.url, re.IGNORECASE)

                if re_result is not None:
                    return re_result.group(1)

                re_result = re.search(r'\d+\.\d+\.\d+', res.text)
                if re_result is not None:
                    return re_result.group(0)

                re_result = re.search(r'VERSION\s*=\s*[\"\']?(\d+\.\d\.\d+)[\"\']?', res.text, re.IGNORECASE)
                if re_result is not None:
                    return re_result.group(1)

                re_result = re.search(fr'{technologie}\s*[=:]\s*[\"\']?(\d+\.\d\.\d+)[\"\']?', res.text, re.IGNORECASE)
                if re_result is not None:
                    return re_result.group(1)
                return None
        except requests.exceptions.ConnectionError:
            print('=' * 10)
            print('Connection error: ' + schema + '://' + self.requester.host + path)
            print('=' * 10)

    @staticmethod
    def get_js_through_url(url):
        try:
            res = requests.get(url, verify=False)
            re_result = re.search(r'\d+?.\d+?.\d+?', res.request.url)
            if re_result is not None:
                return re_result.group()
            re_result = re.search(r'v\d+?.\d+?.\d+?', res.text)
            if re_result is not None:
                return re_result.group()
        except requests.exceptions.ConnectionError:
            print('=' * 10)
            print('No Server header found')
            print('=' * 10)


    @staticmethod
    def get_js_technologie(path):
        try:
            if 'http://' in path or 'https://' in path:
                re_result = re.search(r'([-a-zA-Z]+)[-.@]+', path)
                if re_result is None:
                    re_result = re.search(r'/([a-z-A-Z]+)\?', path)
                if re_result.group()[-1] == '-':
                    return re_result.group().replace('/', '').replace('?', '').replace('.', '').replace('-', '')
                return re_result.group().replace('/', '').replace('?', '').replace('.', '')
            else:
                re_result = re.search(r'([-a-zA-Z]+)[-.@]+', path)
                if re_result is None:
                    re_result = re.search(r'/([a-z-A-Z]+)\?', path)
                if re_result.group()[-1] == '-':
                    return re_result.group().replace('/', '').replace('?', '').replace('.', '').replace('-', '')
                return re_result.group().replace('/', '').replace('?', '').replace('.', '')
        except AttributeError:
            print('Error in get_js_technologie')

'''