from bs4 import BeautifulSoup
import requests
import re

import app.constants


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
                        soup = BeautifulSoup(res.text, app.constants.LXML_STR)
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
