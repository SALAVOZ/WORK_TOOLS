from app.report import Report
import unittest

from app.requester import Requester


class ReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.file_name = 'test.xlsx'
        self.requester = Requester(host='1.1.1.1')
        self.rows = [{'version': '1.11.1', 'technologie': 'jQuery', 'vuln': ['CVE-2020-11022', 'CWE-79'], 'cvss': '6.5', 'url': 'https://security.snyk.io/vuln/SNYK-JS-JQUERY-567880'}, {'version': '1.11.1', 'technologie': 'jQuery', 'vuln': ['CVE-2020-11023', 'CWE-79'], 'cvss': '6.3', 'url': 'https://security.snyk.io/vuln/SNYK-JS-JQUERY-565129'}, {'version': '1.11.1', 'technologie': 'jQuery', 'vuln': ['CVE-2019-11358', 'CWE-1321'], 'cvss': '5.6', 'url': 'https://security.snyk.io/vuln/SNYK-JS-JQUERY-174006'}, {'version': '1.11.1', 'technologie': 'jQuery', 'vuln': ['CVE-2015-9251', 'CWE-79'], 'cvss': '5.4', 'url': 'https://security.snyk.io/vuln/npm:jquery:20150627'}, {'version': '3.2.0', 'technologie': 'Bootstrap', 'vuln': ['CVE-2019-8331', 'CWE-79'], 'cvss': '6.5', 'url': 'https://security.snyk.io/vuln/SNYK-JS-BOOTSTRAP-173700'}, {'version': '3.2.0', 'technologie': 'Bootstrap', 'vuln': ['CVE-2018-20677', 'CWE-79'], 'cvss': '6.5', 'url': 'https://security.snyk.io/vuln/SNYK-JS-BOOTSTRAP-72890'}, {'version': '3.2.0', 'technologie': 'Bootstrap', 'vuln': ['CVE-2018-20676', 'CWE-79'], 'cvss': '6.5', 'url': 'https://security.snyk.io/vuln/SNYK-JS-BOOTSTRAP-72889'}, {'version': '3.2.0', 'technologie': 'Bootstrap', 'vuln': ['CVE-2018-14040', 'CVE-2018-14042', 'CWE-79'], 'cvss': '6.5', 'url': 'https://security.snyk.io/vuln/npm:bootstrap:20180529'}, {'version': '3.2.0', 'technologie': 'Bootstrap', 'vuln': ['CVE-2016-10735', 'CWE-79'], 'cvss': '6.5', 'url': 'https://security.snyk.io/vuln/npm:bootstrap:20160627'}]

    def test_requester__validate_host__success(self):
        report = Report(file_name=self.file_name, requester=self.requester)
        report.write_row(self.rows[0])
        report.write_row(self.rows[1])
        report.close_wordbook()
