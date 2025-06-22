import win32com.client
import win32print


wpsCom = win32com.client.Dispatch('Ket.Application')
wpsCom.Visible = False
wpsCom.DisplayAlerts = False
wpsCom.PrintCommunication = False
def printExcel(excel_file):
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


if __name__ == '__main__':
    printExcel(rf"C:\Users\cja\Downloads\个人产品-复盘专项_2025-06-10_20_05_14.xlsx")