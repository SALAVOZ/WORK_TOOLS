from app.requester import Requester
from app.wappalyzer import Wappalyzer
from app.snyk_api_handler import snyk_api_handler
from app.report import Report
from openpyxl import load_workbook
import time


import argparse
all_vulnerable_js = []
all_vulnerable_web_servers = []


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
    """
    report = Report(file_name=f'{requester.host}1.xlsx')
    time.sleep(3)
    index += 1
    print('Index', index)
for d in all_vulnerable_js:
    for row in d['result']:
        report.write_row_js(row=row, requester=d['requester'])
for d in all_vulnerable_web_servers:
    for row in d['result']:
        report.write_row_web_server(row=row, requester=d['requester'])
report.close_wordbook()
    """