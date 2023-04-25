from datetime import datetime
import pandas
import xlsxwriter


class Report:
    def __init__(self):
        pass

    @staticmethod
    def write_excel(host: str, d: list[dict]) -> None:
        now = datetime.now()
        file_name = f'{host}_{now}.xlsx'.replace(':', '_').replace(' ', '_')
        writer = pandas.ExcelWriter(file_name, engine='xlsxwriter')
        data_frame = pandas.DataFrame(d)
        data_frame.to_excel(writer, 'Result')
        writer.close()
