from socket import gethostbyname, gaierror
import requests
import urllib3
import app.constants
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
            for schema in [app.constants.HTTP_STR, app.constants.HTTPS_STR]:
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
                'User-Agent': app.constants.USER_AGENT
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
            case app.constants.HTTP_STR:
                response = self.response_http
            case app.constants.HTTPS_STR:
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
