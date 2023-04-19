from bs4 import BeautifulSoup
from app.requester import Requester
from requests import Response
import app.constants

'''
Main класс. Используются классы requester, wappalyzer, snyk_api_handler
Методы:
make_requests_to_get_js_files - получает все js файлы на всех протоколах и сохраняет словарь типа { [path]: [requests.Response], ... }
get_technologies - получает на вход словари типа [ {'path': [requests.Response]}, ... ],
                    проводит анализ и возвращает [ '' ]
'''

class main:
    def __init__(self):
        self.requester: Requester = Requester()

    def make_requests_to_get_js_files(self) -> list[Response]:
        '''Собирает пути на js файлы. Возвращает список [ { 'path': requests.Response }, ... ].'''
        for response in [self.requester.response_http, self.requester.response_https]:
            if response is not None:
                try:
                    bs_obj = BeautifulSoup(self.requester.get_html_http_protocol(), app.constants.LXML_STR)
                    js_files = [i.get('src') for i in bs_obj.find_all('script') if i.get('src')] \
                               + [i.get('href') for i in bs_obj.find_all('link')
                                  if i.get('as') == 'script' and (i.get('rel') == ['preload'] or i.get('rel') == 'preload')]
                    for js_file in js_files:
                        yield {f'{self.requester.host}': }
                except ValueError:
                    print('requester returned ValueError because response_http is None')
                except Exception as ex:
                    print(ex)
                    print('Some exception in beautiful soap. Bad documentation, thanks(((')
                    return []
            else:
                print(f'')
