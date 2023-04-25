from app.requester import Requester
from app.wappalyzer import Wappalyzer
from app.snyk_api_handler import snyk_api_handler
import app.constants
import argparse



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    parser.add_argument('-H', '--host', type=str, required=True, help='Write host ip')
    parser.add_argument('-d', '--directory', type=str, required=False, default='', help='Write directory; default=\'\'')
    args = parser.parse_args()
    requester = Requester(args.host)
    requester.check_connection(directory=args.directory)
    wappalyzer = Wappalyzer(requester)
    snyk_api = snyk_api_handler()
    for d in [wappalyzer.frameworks_and_version_http, wappalyzer.frameworks_and_version_https]:
        result = snyk_api.parse_snyk(d)
        print(result)