'''
try:
    if 'window.location.href' in r.text:
        href = re.search(r'[\'\"]([\w\W]+)[\'\"]', r.text).group(1)
        url = f'{self.host}/{href}'.replace('//', '/')
        r = requests.get(schema + '://' + url, verify=False, allow_redirects=True)
except Exception:
    pass
'''

import argparse
import app.constants
from app.requester import Requester
from app.wappalyzer import Wappalyzer
from app.snyk_api_handler import snyk_api_handler

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    parser.add_argument('-H', '--host', type=str, required=True, help='Write host')
    parser.add_argument('-d', '--dir', type=str, required=False, help='Write dir/file')
    parser.add_argument('-t', '--technologie', type=str, required=False)
    parser.add_argument('-v', '--version', type=str, required=False)
    parser.add_argument('-s', '--server', type=str, required=False)
    args = parser.parse_args()
    requester = Requester(args.host)
    requester.check_connection()
    response_http, response_https = requester.make_request(args.dir)
    for protocol in [app.constants.HTTP_STR, app.constants.HTTPS_STR]:
        wappalyzer = Wappalyzer(requester.get_html(protocol), requester)
        snyk_api = snyk_api_handler()
        snyk_api.parse_snyk(wappalyzer.frameworks_and_version)
