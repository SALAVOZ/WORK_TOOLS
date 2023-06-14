from datetime import datetime
from app.requester import Requester
import xlsxwriter

APLHABET = 'ABCDEFGHIJ'
HEADER_DICT = {
               '0': 'IP',
               '1': 'Уязвимость',
               '2': 'Уровень критичности',
               '3': 'CVSS',
               '4': 'Описание уязвимости',
               '5': 'CVE',
               '6': 'Рекомендации',
               '7': 'Ссылки',
               '8': 'Порт',
               '9': 'Очередь устранения'
               }

#now = datetime.now()
#file_name = f'{host}_{now}.xlsx'.replace(':', '_').replace(' ', '_')


class Report:
    def __init__(self, file_name: str):
        self.workbook = xlsxwriter.Workbook(file_name)
        self.worksheet = self.workbook.add_worksheet()
        self.current_row_number = 1
        self.write_header()

    def increment_current_row_number(self):
        self.current_row_number += 1

    def write_header(self):
        for key, spell in enumerate(APLHABET):
            self.worksheet.write(f'{spell}1', HEADER_DICT[str(key)])
        self.increment_current_row_number()

    def write_row_js(self, row: dict, requester: Requester) -> bool:
        self.worksheet.write(f'A{self.current_row_number}', requester.host)
        self.worksheet.write(f'B{self.current_row_number}', row['technologie'])
        self.worksheet.write(f'D{self.current_row_number}', row['cvss'])
        self.worksheet.write(f'F{self.current_row_number}', '\n'.join(row['vuln']))
        self.worksheet.write(f'G{self.current_row_number}', row['version'])
        self.worksheet.write(f'H{self.current_row_number}', row['url'])
        self.worksheet.write(f'I{self.current_row_number}', requester.port)
        self.increment_current_row_number()
        return True

    def write_row_web_server(self, row: dict, requester: Requester) -> bool:
        self.worksheet.write(f'A{self.current_row_number}', requester.host)
        self.worksheet.write(f'B{self.current_row_number}', row['name'])
        self.worksheet.write(f'I{self.current_row_number}', requester.port)
        self.worksheet.write(f'F{self.current_row_number}', row['vuln'])
        self.increment_current_row_number()
        return True

    def close_wordbook(self):
        self.workbook.close()
