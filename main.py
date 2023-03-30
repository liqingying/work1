from PyQt5.QtWidgets import *
from scapy.all import *
from sniff_ui import Ui_MainWindow
import sys
import socket


class Sniff_Mainwindow(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        # 设置ui初始值
        self.setui_init()
        self.dev = self.comboBox.currentText()  # 记录当前选择的网卡
        self.is_sniff = False  # 记录是否在抓包，初始值为否
        self.filter = ""  # 记录筛选条件
        self.start_time = None  # 记录开始抓包的时候的时间戳
        self.saved_pkt = []  # 要保存的pkt
        # 设置信号处理函数
        self.setui_sign()
        # 生成协议号和协议名称的字典
        prefix = "IPPROTO_"
        self.table = {num: name[len(prefix):]
                      for name, num in vars(socket).items()
                      if name.startswith(prefix)}
        # pkt1 = sniff(filter=self.filter, prn=self.handle_pkt, iface=self.dev, count=10)
        # pkt2 = sniff(filter=self.filter, prn=self.handle_pkt, iface=self.dev, count=1)
        # pkts = pkt1 + pkt2
        # print(pkts)

    def setui_init(self):
        # 查看所有网卡
        ifaces_str = ifaces.show(print_result=False)
        ifaces_str = ifaces_str.split('\n')
        l = ifaces_str[0].find("Name")
        r = ifaces_str[0].find("MAC")
        ifaces_list = list()
        for iface in ifaces_str[1:]:
            ifaces_list.append(iface[l:r].strip())
        ifaces_list = list(filter(None, ifaces_list))
        self.comboBox.addItems(ifaces_list)

    def setui_sign(self):
        self.comboBox.activated.connect(self.select_dev)
        self.pushButton.clicked.connect(self.start_sniff)
        self.pushButton_2.clicked.connect(self.stop_sniff)
        self.pushButton_3.clicked.connect(self.sniff_filter)
        self.pushButton_4.clicked.connect(self.save_data)

    def select_dev(self):
        # 记录当前选择的网卡
        self.dev = self.comboBox.currentText()
        # print(self.dev)

    def start_sniff(self):
        self.is_sniff = True
        t = threading.Thread(target=self.capture)
        t.start()

    def capture(self):
        while self.is_sniff:
            sniff(filter=self.filter, prn=self.handle_pkt, iface=self.dev, count=1)

    def handle_pkt(self, pkt):
        # pkt.show()
        # print(pkt.time)
        # print(type(pkt.src))
        # print(pkt.dst)
        # print(pkt.load)

        # 保存 pkt
        self.saved_pkt.append(pkt)
        number = self.tableWidget.rowCount()
        self.tableWidget.insertRow(number)
        # No.
        tmp_item = QTableWidgetItem(str(number + 1))
        self.tableWidget.setItem(number, 0, tmp_item)
        # Time
        if number == 0:
            self.start_time = pkt.time
        capture_time = pkt.time - self.start_time
        tmp_item = QTableWidgetItem(str(capture_time))
        self.tableWidget.setItem(number, 1, tmp_item)
        # Source
        tmp_item = QTableWidgetItem(pkt.src)
        self.tableWidget.setItem(number, 2, tmp_item)
        # Destination
        tmp_item = QTableWidgetItem(pkt.dst)
        self.tableWidget.setItem(number, 3, tmp_item)
        # Protocol
        if hasattr(pkt, "proto"):
            # print(table[pkt.proto])
            # print(type(table[pkt.proto]))
            if pkt.proto in self.table:
                tmp_item = QTableWidgetItem(str(self.table[pkt.proto]))
                self.tableWidget.setItem(number, 4, tmp_item)
        # Length
        if hasattr(pkt, "len"):
            # print(pkt.len)
            # print(type(pkt.len))
            tmp_item = QTableWidgetItem(str(pkt.len))
            self.tableWidget.setItem(number, 5, tmp_item)
        # info
        if hasattr(pkt, "sport"):
            # print("################123123")
            if hasattr(pkt, "dport"):
                tmp_item = QTableWidgetItem(str(pkt.sport) + "->" + str(pkt.dport))
                self.tableWidget.setItem(number, 6, tmp_item)

    def stop_sniff(self):
        self.is_sniff = False
        return

    # 关闭窗口时停止抓包
    def closeEvent(self, qcloseevent):
        reply = QMessageBox.question(self, '消息', "确定退出吗?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.stop_sniff()
            qcloseevent.accept()
        else:
            qcloseevent.ignore()

    def sniff_filter(self):
        self.filter = self.lineEdit_2.text()

    def save_data(self):
        file, ok = QFileDialog.getSaveFileName(self, caption="选择保存路径", filter="*.pcap")
        print(ok)
        print(file)
        if file == '':
            QMessageBox.warning(self, "注意", "文件内容不能为空")
            return
        wrpcap(file, self.saved_pkt)
        QMessageBox.information(self, "消息", "文件已保存")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainwindow = Sniff_Mainwindow()
    mainwindow.show()
    sys.exit(app.exec_())
