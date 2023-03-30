from PyQt5.QtWidgets import QApplication,QMainWindow
from scapy.all import *
import sniff_ui
import sys

ifaces_str = ifaces.show(print_result=False)
ifaces_str = ifaces_str.split('\n')
l = ifaces_str[0].find("Name")
r = ifaces_str[0].find("MAC")
ifaces_list = list()
for iface in ifaces_str[1:]:
    ifaces_list.append(iface[l:r].strip())
ifaces_list = list(filter(None, ifaces_list))
filter = None
iface = ifaces_list[10]
print(iface)

# packet = sniff(filter=filter, iface=iface, count=0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainwindow = QMainWindow()
    ui = sniff_ui.Ui_MainWindow()
    ui.setupUi(mainwindow)
    mainwindow.show()
    sys.exit(app.exec_())