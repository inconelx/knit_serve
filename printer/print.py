import win32com.client
from printer.generateExcel import generateExcel
import os


wpsCom = win32com.client.Dispatch('Ket.Application')
wpsCom.Visible = False
wpsCom.DisplayAlerts = False
wpsCom.PrintCommunication = False
def _printExcel(excel_file):
    try:
        workbook = wpsCom.Workbooks.Open(excel_file)
        active_sheet = workbook.ActiveSheet
        
        active_sheet.PageSetup.Orientation = 1
        active_sheet.PageSetup.Zoom = False
        active_sheet.PageSetup.FitToPagesWide = 1
        active_sheet.PageSetup.FitToPagesTall = 1
        active_sheet.PrintOut(
            Copies=1,
            Collate=True,
            IgnorePrintAreas=False,
            PrintToFile=True,
            PrToFileName=rf'E:\1.pdf'
        )
        
    finally:
        workbook.Close(False)

'''
    printExcel
    功能： 通过传入的数据打印Excel
    参数： data => 字段 - 数值 对应的json结构
    返回： 无
'''
def printExcel(data):
    excelPath = generateExcel(data)
    _printExcel(excelPath)
    os.remove(os.path.abspath(excelPath))


if __name__ == '__main__':
    printExcel({'cja': '1', 'jzh': '2'})