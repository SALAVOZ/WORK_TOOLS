from openpyxl import load_workbook
from socket import gethostbyname, gaierror
from bs4 import  BeautifulSoup
import argparse
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

all_vulnerable_js = []
all_vulnerable_web_servers = []

HTTP_STR: str = 'http'
HTTPS_STR: str = 'https'
LXML_STR: str = 'lxml'
USER_AGENT: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0'
#REGEX_TO_GET_COMMENTS: str = '/\*.*?\*/|\/{2}.*?\n|\s'
REGEX_TO_GET_COMMENTS: str = '/\*[\w\W]+\*/'
REGEX_TO_GET_FRAMEWORK_AND_VERSION: str = '.+?v\d+.\d+.\d+'



'''
Класс для работы с запросами.
Методы:
check_connection - проверяет соединения с помощью make_request на протоколы http и https.
make_request - делает get-запрос.
validate_host - валидирует ip или dns-имя.
get_html - возвращает html-код в зависимости от значения входной переменной.
get_header_server - возвращает значение http-заголовка Server в зависимости от значения входной переменной.
get_response_by_protocol - получает строку ('http' или 'https') и возвращает responnse протокола.
СДЕЛАТЬ ФУНКЦИЮ ДЛЯ ПОЛУЧЕНИЯ VIA ЗАГОЛОВКА.
СДЕЛАТЬ ПРОВЕРКИ НА ЗАГОЛОВКИ: SCP, XSS-PROTECTION И Т.Д.
'''


class Requester:
    def __init__(self, host: str =None) -> None:
        '''Объект для работы с запросами. Собирает js запросы и проверяет протоколы http и https на открытость.'''
        port = None
        if ":" in host:
            self.host, self.port = host.split(":")
        else:
            self.host: str = self.validate_host(host=host)
            self.port = None
        self.response_http: requests.Response = None
        self.response_https: requests.Response = None

    def check_connection(self, directory: str = '') -> None:
        '''Проверяет соединение и сохраняет объект Response в переменные класса.'''
        if self.host is not None:
            self.response_http, self.response_https = self.make_request_on_all_protocols(directory=directory)
        else:
            raise ValueError

    def make_request_on_all_protocols(self, directory: str = ''):
        '''Делает get запросы на http и https, в зависимости от того, прошло ли подключение в функции check_connection.'''
        if self.host is not None:
            for schema in [HTTP_STR, HTTPS_STR]:
                if schema is not None:
                    response = self.make_request_on_one_protocol(schema, directory)
                    yield response
        else:
            raise ValueError

    def make_request_on_one_protocol(self, protocol: str, directory: str = '') -> requests.Response | None:
        response = None
        try:
            while directory.startswith('/'):
                directory = directory[1:]
            host = self.host
            if self.port is not None:
                host = self.host + ":" + self.port
            print('=' * 50 + '\n' + 'Making request to ' + protocol + '://' + host + '/' + directory)
            response = requests.get(protocol + '://' + host + '/' + directory, verify=False, timeout=2, headers={
                'User-Agent': USER_AGENT
            }, allow_redirects=True)
            print('Response: ' + str(response) + '\n' + '=' * 50 + '\n')
            if response is not None:
                print(host, response.status_code, directory)
        except:
            response = None
        return response

    def get_html(self, protocol: str) -> str | None:
        response: requests.Response = self.get_response_by_protocol(protocol=protocol)
        try:
            return response.text
        except AttributeError:
            print('No attribute text in variable response because response is not requests.Response type.')
            return None

    def get_header_server(self, protocol: str) -> str | None:
        response: requests.Response = self.get_response_by_protocol(protocol=protocol)
        try:
            return response.headers['Server']
        except AttributeError:
            print('No attribute headers in variable response because response is not requests.Response type.')
        except KeyError:
            print('No header \'Server\' in http response')
        return None

    def get_response_by_protocol(self, protocol: str) -> requests.Response | None:
        response: requests.Response
        match protocol:
            case 'http':
                response = self.response_http
            case 'https':
                response = self.response_https
            case _:
                raise ValueError
        if response is not None:
            return response
        else:
            return None

    def get_host(self):
        if self.host is not None:
            return self.host

    @staticmethod
    def validate_host(host: str) -> str:
        '''Проверяет имя или ip на валидность'''
        try:
            ip = gethostbyname(host)
            return host
        except gaierror:
            raise gaierror('Cannot resolve name or ip. Valid host')
        except TypeError:
            print('Host is None; Error')

'''
Класс, свой ваппалайзер. Определяет версии и технологии, находит cve веб серверов исходя из версии, полученной из http-заголовка Server
'''


class Wappalyzer:
    def __init__(self, requester: Requester) -> None:
        self.requester: Requester = requester
        self.frameworks_and_version_http = []
        self.frameworks_and_version_https = []
        self.web_server_version = {}
        self.server_header = {}
        for protocol in [HTTP_STR, HTTPS_STR]:
            server_header = requester.get_header_server(protocol)
            if server_header is not None:
                self.server_header = self.parse_web_server(server_header)
            html = self.requester.get_html(protocol)
            if html is not None:
                self.parse_html(html, protocol)

    def parse_html(self, html: str, protocol: str) -> None:
        soup = BeautifulSoup(html, LXML_STR)
        scripts = [script['src'] for script in
                        soup.findAll('script', src=True)]
        meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                    'meta', attrs=dict(name=True, content=True))
        }
        for script_src in scripts:
            framework, version = self.parse_js(script_src, protocol)
            if protocol == HTTP_STR:
                self.frameworks_and_version_http.append({'framework': framework, 'version': version})
            if protocol == HTTPS_STR:
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
        pattern = re.compile(REGEX_TO_GET_COMMENTS)
        found_comments = pattern.findall(html_text)
        return found_comments

    @staticmethod
    def parse_js_file__get_framework_and_version(string: str) -> tuple[str, str]:
        pattern = re.compile(REGEX_TO_GET_FRAMEWORK_AND_VERSION)
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


class snyk_api_handler:
    def __init__(self):
        pass

    def parse_snyk(self, framework_version_dict: list[dict]):
        '''список типа [{'framework': framework, 'version': version}, ...].'''
        vulnerable = []
        for fram in framework_version_dict:
            if fram['framework'] is not None and fram['version'] is not None:
                tech: str = fram['framework']
                res = requests.get(f'https://security.snyk.io/package/npm/{tech.lower()}', verify=False)
                soup = BeautifulSoup(res.text, 'lxml')
                table = soup.find('table', {'id': 'sortable-table'})
                if table is None:
                    continue
                trs = table.find_all('tr', class_='vue--table__row')
                #spans = table.find_all('span',class_='vue--chip__value')
                for tr in trs:
                    spans = tr.find_all('span', class_='vue--chip__value')
                    result = self.snyk_condition(fram['version'].replace('v', ''), spans)
                    if result:
                        vuln_obj = {
                            'version': fram['version'],
                            'technologie': fram['framework'],
                            'vuln': [],
                            'cvss': 0,
                            'url': ''
                        }
                        a = tr.find('a')['href']
                        url = f'https://security.snyk.io/{a}'
                        vuln_obj['url'] = url
                        res = requests.get(url)
                        soup = BeautifulSoup(res.text, LXML_STR)
                        vuln_obj['cvss'] = soup.find('div', class_='severity-widget__score severity-medium big').attrs['data-snyk-test-score']
                        div = soup.find('div', class_='vuln-info-block')
                        spans = div.find_all('span')
                        for span in spans:
                            try:
                                vuln = span.find('span').find('a').text
                                vuln = re.search('([-WCVE0-9]+?\s*?\n)', vuln).group().replace('\n', '')
                                vuln_obj['vuln'].append(vuln)
                            except BaseException:
                                continue
                        vulnerable.append(vuln_obj)
        return vulnerable

    def snyk_condition(self, framework_version, spans):
        result_all_spans = False
        if framework_version is None:
            return None
        for span in spans:
            result_one_span = True
            version = span.text
            condition = re.findall(r'[<>=]{1,2}\d+.\d+.\d+', version)
            for condition in condition:
                if '>=' in condition:
                    result_one_span = result_one_span and (self.comparing_version(framework_version, condition.replace('>=', '')) or framework_version == condition.replace('>=', ''))
                    continue
                if '>' in condition:
                    result_one_span = result_one_span and self.comparing_version(framework_version, condition.replace('>', ''))
                    continue
                if '<=' in condition:
                    result_one_span = result_one_span and (not self.comparing_version(framework_version, condition.replace('<=','')) or framework_version == condition.replace('>=', ''))
                    continue
                if '<' in condition:
                    result_one_span = result_one_span and not self.comparing_version(framework_version, condition.replace('<',''))
                    continue
                if '=' in condition:
                    result_one_span = result_one_span and framework_version == condition.replace('=', '')
            result_all_spans = result_all_spans or result_one_span
        return result_all_spans

    @staticmethod
    def comparing_version(version, comparing):
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

    def parse_nginx_site(self, version_from_response: str) -> list:
        try:
            self.validate_version(version=version_from_response)
        except ValueError:
            print('Invalid Nginx version')
            return []
        vulnerable = []
        url = 'http://nginx.org/en/security_advisories.html'
        res = requests.get(url, verify=False)
        soup = BeautifulSoup(res.text, 'lxml')
        div = soup.find('div', {'id': 'content'})
        all_li = div.find_all('li')
        for li in all_li:
            text = li.find(text=re.compile(r'Vulnerable:[\w\W]+'))
            conditions = re.findall(r'\d+.\d+.\d+\s*-\s*\d+.\d+.\d+', text)
            for condition in conditions:
                conds = condition.replace(' ', '').split('-')
                if not(self.comparing_version(conds[0], version_from_response)) and self.comparing_version(conds[1], version_from_response):
                    try:
                        cve = li.find('a', text=re.compile(r'CVE-\d+-\d+')).text
                        vulnerable.append({
                            'name': f'Nginx {version_from_response}',
                            'vuln': cve
                        })
                    except Exception:
                        print('Vuln at parsing nginx site')
        return vulnerable

    def parse_apache_site(self, version_from_response: str) -> list:
        vulnerable = []
        try:
            self.validate_version(version=version_from_response)
        except ValueError:
            print('Invalid Apache version')
            return []
        for i in range(11, 25, 1):
            url = f'https://httpd.apache.org/security/vulnerabilities_{i}.html'
            res = requests.get(url, verify=False)
            if res.status_code != 404:
                soup = BeautifulSoup(res.text, 'lxml')
                dls = soup.findAll('dl')
                for dl in dls:
                    dt = dl.findNext('dt')
                    dd = dl.findNext('dd')
                    cve = dt.find(text=re.compile(r'CVE-\d+-\d+'))
                    table = dd.find('table')
                    last_row = table('tr')[-1]
                    conditions = re.findall(r'\d+.\d+.\d+', last_row('td')[-1].text)
                    for condition in conditions:
                        if '>' in condition:
                            if '=' in condition and version_from_response == condition:
                                vulnerable.append({
                                    'name': f'Apache {version_from_response}',
                                    'vuln': cve})
                            if self.comparing_version(version_from_response, condition):
                                vulnerable.append({
                                    'name': f'Apache {version_from_response}',
                                    'vuln': cve})
                            continue
                        if '<' in condition:
                            if '=' in condition and version_from_response == condition:
                                vulnerable.append({
                                    'name': f'Apache {version_from_response}',
                                    'vuln': cve})
                            if not(self.comparing_version(version_from_response, condition)):
                                vulnerable.append({
                                    'name': f'Apache {version_from_response}',
                                    'vuln': cve})
                            continue
                        if version_from_response == condition:
                            vulnerable.append({
                                'name': f'Apache {version_from_response}',
                                'vuln': cve
                            })
        return vulnerable

    @staticmethod
    def validate_version(version):
        '''Производит валидацию версии с помощью regex.'''
        try:
            re.search(r'\d+?.\d+?.\d+?', version).group(0)
        except:
            raise ValueError


def read_excel(path_to_file: str) -> list[str]:
    wb = load_workbook(path_to_file)
    sheet = wb.get_sheet_by_name('Список IP')
    result = []
    for row in range(2, 74):
        try:
            host = sheet[f'B{row}'].value
            port = sheet[f'A{row}'].value
            if int(port) == 0:
                continue
            result.append(str(host) + ":" + str(port))
        except Exception as ex:
            print(ex)
            return result
    wb.close()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    parser.add_argument('-H', '--host', type=str, required=True, help='Write host ip')
    parser.add_argument('-d', '--directory', type=str, required=False, default='', help='Write directory; default=\'\'')
    args = parser.parse_args()
    #hosts = read_excel('C:\\Users\\Салават\\Documents\\report_08_06_2023__21_57_36.xlsx')
    #hosts = read_excel('C:\\Users\\Салават\\Documents\\report.xlsx')
    #report = Report(file_name='salavat1.xlsx')
    #index = 0
    #for host in hosts:
    requester = Requester(args.host)
    requester.check_connection(directory="/")
    wappalyzer = Wappalyzer(requester)
    snyk_api = snyk_api_handler()
    for d in [wappalyzer.frameworks_and_version_http, wappalyzer.frameworks_and_version_https]:
        result = snyk_api.parse_snyk(d)
        print(result)
        if len(result) > 0:
            all_vulnerable_js.append({'result': result,
                                      'requester': requester
                                      })
    webserver_vulnerable = []
    try:
        match wappalyzer.server_header['name']:
            case 'nginx':
                if wappalyzer.server_header['version']:
                    webserver_vulnerable = snyk_api.parse_nginx_site(wappalyzer.server_header['version'])
            case 'apache':
                if wappalyzer.server_header['version']:
                    webserver_vulnerable = snyk_api.parse_apache_site(wappalyzer.server_header['version'])
            case _:
                pass
        if len(webserver_vulnerable) > 0:
            all_vulnerable_web_servers.append({'result': webserver_vulnerable,
                                               'requester': requester
                                               })
        print(webserver_vulnerable)
    except KeyError:
        pass
    except TypeError:
        print('laka')
