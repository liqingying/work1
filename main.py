from io import StringIO
from PyQt5.QtWidgets import *
from scapy.all import *
from sniff_ui import Ui_MainWindow
import sys


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
        self.display_pkt = []  # 要展示的pkt
        # 设置信号处理函数
        self.setui_sign()

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
        self.pushButton_5.clicked.connect(self.read_data)
        self.pushButton_6.clicked.connect(self.clear_data)
        self.tableWidget.clicked.connect(self.table_display)

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
            pkt = sniff(filter=self.filter, prn=self.handle_pkt, iface=self.dev, count=1)

    def handle_pkt(self, pkt):
        # 保存 pkt
        self.saved_pkt.append(pkt)
        self.display_pkt.append(pkt)
        number = self.tableWidget.rowCount()
        self.tableWidget.insertRow(number)
        self.tableWidget.setItem(number, 0, QTableWidgetItem(str(number + 1)))  # No.
        if number == 0:
            self.start_time = pkt.time
        capture_time = "%.6f" % (pkt.time - self.start_time)
        self.tableWidget.setItem(number, 1, QTableWidgetItem(str(capture_time)))  # Time
        self.tableWidget.setItem(number, 5, QTableWidgetItem(str(len(pkt))))  # Length
        if pkt.haslayer("Loopback"):
            self.tableWidget.setItem(number, 2, QTableWidgetItem("127.0.0.1"))  # Source
            self.tableWidget.setItem(number, 3, QTableWidgetItem("127.0.0.1"))  # Destination
            self.tableWidget.setItem(number, 4, QTableWidgetItem("None"))  # Protocol
            self.tableWidget.setItem(number, 6, QTableWidgetItem("Loopback"))  # Info
            return
        if pkt.haslayer("Ether"):
            if pkt.haslayer("ARP"):
                self.tableWidget.setItem(number, 2, QTableWidgetItem(pkt["Ether"].src))  # Source
                self.tableWidget.setItem(number, 3, QTableWidgetItem(pkt["Ether"].dst))  # Destination
                self.tableWidget.setItem(number, 4, QTableWidgetItem("ARP"))  # Protocol
                if pkt["ARP"].psrc == pkt["ARP"].pdst:
                    self.tableWidget.setItem(number, 6, QTableWidgetItem("ARP Announcement for " +
                                                                         str(pkt["ARP"].pdst)))  # Info
                    return
                else:
                    self.tableWidget.setItem(number, 6, QTableWidgetItem("Who has " + str(pkt["ARP"].pdst) +
                                                                         "? Tell " + str(pkt["ARP"].psrc)))  # Info
                    return
            if pkt.haslayer("IP"):
                self.tableWidget.setItem(number, 2, QTableWidgetItem(pkt["IP"].src))  # Source
                self.tableWidget.setItem(number, 3, QTableWidgetItem(pkt["IP"].dst))  # Destination
                if pkt["IP"].proto == 2:
                    self.tableWidget.setItem(number, 4, QTableWidgetItem("IGMP"))
                    return
                if pkt.haslayer("UDP"):
                    if pkt["UDP"].dport == 1900:
                        self.tableWidget.setItem(number, 4, QTableWidgetItem("SSDP"))  # Protocol
                        self.tableWidget.setItem(number, 6,
                                                 QTableWidgetItem(
                                                     pkt["Raw"].load.decode('utf-8').split('\r', 1)[0]))  # Info
                        return
                    if pkt.haslayer("DNS"):
                        if pkt["IP"].dst == "224.0.0.251" and pkt["UDP"].dport == 5353 and pkt["UDP"].sport == 5353:
                            self.tableWidget.setItem(number, 4, QTableWidgetItem("MDNS"))  # Protocol
                            # self.tableWidget.setItem(number, 6, QTableWidgetItem()
                            return
                        self.tableWidget.setItem(number, 4, QTableWidgetItem("DNS"))  # Protocol
                        # self.tableWidget.setItem(number, 6, QTableWidgetItem()
                        return
                    self.tableWidget.setItem(number, 4, QTableWidgetItem("UDP"))  # Protocol
                    self.tableWidget.setItem(number, 6, QTableWidgetItem(str(pkt["UDP"].sport) + "->" +
                                                                         str(pkt["UDP"].dport) + " Len=" +
                                                                         str(pkt["UDP"].len - 8)))  # Info
                    return
                if pkt.haslayer("TCP"):
                    self.tableWidget.setItem(number, 4, QTableWidgetItem("TCP"))  # Protocol
                    self.tableWidget.setItem(number, 6, QTableWidgetItem(str(pkt["TCP"].sport) + "->" +
                                                                         str(pkt["TCP"].dport)))
                    return
            if pkt.haslayer("IPv6"):
                self.tableWidget.setItem(number, 2, QTableWidgetItem(pkt["IPv6"].src))  # Source
                self.tableWidget.setItem(number, 3, QTableWidgetItem(pkt["IPv6"].dst))  # Destination
                if pkt["IPv6"].nh == 58 or pkt["IPv6"].nh == 0 and pkt["IPv6ExtHdrHopByHop"].nh == 58:
                    self.tableWidget.setItem(number, 4, QTableWidgetItem("ICMPv6"))  # Protocol
                    b = ''
                    if pkt.haslayer("ICMPv6NDOptSrcLLAddr"):
                        b = pkt["ICMPv6NDOptSrcLLAddr"].lladdr
                    if pkt.haslayer("ICMPv6ND_NS"):
                        a = pkt["ICMPv6ND_NS"].tgt
                        if pkt["ICMPv6ND_NS"].type == 135:  # ICMPv6ND_NS type=Neighbor Solicitation = 135
                            if b != '':
                                self.tableWidget.setItem(number, 6, QTableWidgetItem("Neighbor Solicitation for " +
                                                                                     str(a) + " from " + str(b)))
                                return
                            self.tableWidget.setItem(number, 6, QTableWidgetItem("Neighbor Solicitation for " + str(a)))
                            return
                    if pkt.haslayer("ICMPv6MLReport"):
                        self.tableWidget.setItem(number, 6, QTableWidgetItem("Multicast Report"))
                        return
                    return
                if pkt.haslayer("UDP"):
                    if pkt.haslayer("DNS"):
                        if pkt["IPv6"].dst == "ff02::fb" and pkt["UDP"].dport == 5353 and pkt["UDP"].sport == 5353:
                            self.tableWidget.setItem(number, 4, QTableWidgetItem("MDNS"))  # Protocol
                            # self.tableWidget.setItem(number, 6, QTableWidgetItem()
                            return
                        self.tableWidget.setItem(number, 4, QTableWidgetItem("DNS"))
                    if pkt["UDP"].sport == 546 and pkt["UDP"].dport == 547:
                        self.tableWidget.setItem(number, 4, QTableWidgetItem("DHCPv6"))  # Protocol
                        if pkt.haslayer("DHCP6_Request"):
                            self.tableWidget.setItem(number, 6, QTableWidgetItem("REQUEST"))
                            return
                        if pkt.haslayer("DHCP6_Solicit"):
                            self.tableWidget.setItem(number, 6, QTableWidgetItem("SOLICIT"))
                            return
                    if pkt["UDP"].dport == 5355:
                        self.tableWidget.setItem(number, 4, QTableWidgetItem("LLMNR"))
                        # self.tableWidget.setItem(number, 6, QTableWidgetItem()
                        return
                    self.tableWidget.setItem(number, 4, QTableWidgetItem("UDP"))
                    self.tableWidget.setItem(number, 6, QTableWidgetItem(str(pkt["UDP"].sport) + "->" +
                                                                         str(pkt["UDP"].dport) + " Len=" +
                                                                         str(pkt["UDP"].len - 8)))  # Info
                    return
                if pkt["IPv6"].nh == 89:
                    self.tableWidget.setItem(number, 4, QTableWidgetItem("OSPF"))  # Protocol
                    # self.tableWidget.setItem(number, 6, QTableWidgetItem(""))
                    return
            self.tableWidget.setItem(number, 2, QTableWidgetItem(pkt["Ether"].src))  # Source
            self.tableWidget.setItem(number, 3, QTableWidgetItem(pkt["Ether"].dst))  # Destination
            if pkt["Ether"].type == 0x893a:
                self.tableWidget.setItem(number, 4, QTableWidgetItem("ieee1905"))  # Protocol
                # self.tableWidget.setItem(number, 6, QTableWidgetItem(""))
                return
            self.tableWidget.setItem(number, 4, QTableWidgetItem("Ethernet"))
        if pkt.haslayer("Dot3"):
            self.tableWidget.setItem(number, 2, QTableWidgetItem(pkt["Dot3"].src))  # Source
            self.tableWidget.setItem(number, 3, QTableWidgetItem(pkt["Dot3"].dst))  # Destination
            self.tableWidget.setItem(number, 4, QTableWidgetItem("Ethernet"))

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
        sniff_start = False
        if self.is_sniff:
            sniff_start = True
            self.is_sniff = False
        self.recover_table()
        proto = self.lineEdit_5.text()
        src_ip = self.lineEdit.text()
        dst_ip = self.lineEdit_2.text()
        src_port = self.lineEdit_3.text()
        dst_port = self.lineEdit_4.text()
        # self.filter =
        self.display_pkt = []

        number = self.tableWidget.rowCount()
        for i in range(number):
            if proto != '':
                if self.tableWidget.item(i, 4) is None:
                    continue
                if self.tableWidget.item(i, 4).text() == "":
                    continue
                p = self.tableWidget.item(i, 4).text().strip()
                # print("protocol:" + p)
                if p.lower() != proto.lower():
                    continue
            if src_ip != '':
                if self.tableWidget.item(i, 2) is None:
                    continue
                if self.tableWidget.item(i, 2).text() == "":
                    continue
                s_ip = self.tableWidget.item(i, 2).text().strip()
                # print("s_ip:" + s_ip)
                if s_ip != src_ip:
                    continue
            if dst_ip != '':
                if self.tableWidget.item(i, 3) is None:
                    continue
                if self.tableWidget.item(i, 3).text() == "":
                    continue
                d_ip = self.tableWidget.item(i, 3).text().strip()
                # print("d_ip:" + d_ip)
                if d_ip != dst_ip:
                    continue
            if src_port != '':
                pkt = self.saved_pkt[i]
                s_port = -1
                if pkt.haslayer("UDP"):
                    s_port = pkt["UDP"].sport
                if pkt.haslayer("TCP"):
                    s_port = pkt["TCP"].sport
                # print("s_port:" + str(s_port))
                if str(s_port) != str(src_port):
                    continue
            if dst_port != '':
                pkt = self.saved_pkt[i]
                d_port = -1
                if pkt.haslayer("UDP"):
                    d_port = pkt["UDP"].dport
                if pkt.haslayer("TCP"):
                    d_port = pkt["TCP"].dport
                # print("d_port:" + str(d_port))
                if str(d_port) != str(dst_port):
                    continue
            self.display_pkt.append(self.saved_pkt[i])
        # self.clear_data()
        number = self.tableWidget.rowCount()
        for i in range(number - 1, -1, -1):
            self.tableWidget.removeRow(i)
        self.textEdit.clear()
        self.textEdit_2.clear()
        ll = len(self.saved_pkt)  # 保留原本的长度，在handle时会改变saved_pkt的长度
        lll = len(self.display_pkt)
        for i in range(len(self.display_pkt)):
            self.handle_pkt(self.display_pkt[i])
        self.saved_pkt = self.saved_pkt[0:ll]
        self.display_pkt = self.display_pkt[0:lll]
        if sniff_start:
            self.is_sniff = True

    def recover_table(self):
        number = self.tableWidget.rowCount()
        for i in range(number - 1, -1, -1):
            self.tableWidget.removeRow(i)
        self.textEdit.clear()
        self.textEdit_2.clear()
        ll = len(self.saved_pkt)  # 保留原本的长度，在handle时会改变saved_pkt的长度
        lll = len(self.display_pkt)
        for i in range(len(self.saved_pkt)):
            self.handle_pkt(self.saved_pkt[i])
        self.saved_pkt = self.saved_pkt[0:ll]
        self.display_pkt = self.display_pkt[0:lll]

    def save_data(self):
        file, file_type = QFileDialog.getSaveFileName(self, caption="选择保存路径", filter="*.pcap")
        if file == '':
            QMessageBox.warning(self, "注意", "文件内容不能为空")
            return
        wrpcap(file, self.saved_pkt)
        QMessageBox.information(self, "消息", "文件已保存")

    def read_data(self):
        file, file_type = QFileDialog.getOpenFileName(self, caption="选择保存路径", filter="*.pcap")
        if file == '':
            QMessageBox.warning(self, "注意", "文件内容不能为空")
            return
        self.clear_data()
        pkts = rdpcap(file)
        for i in range(len(pkts)):
            self.handle_pkt(pkts[i])

    def clear_data(self):
        # self.stop_sniff()
        self.saved_pkt = []
        self.display_pkt = []
        number = self.tableWidget.rowCount()
        for i in range(number - 1, -1, -1):
            self.tableWidget.removeRow(i)
        self.textEdit.clear()
        self.textEdit_2.clear()

    def table_display(self, index):
        self.textEdit.clear()
        self.textEdit_2.clear()
        number = index.row()
        pkt = self.display_pkt[number]

        tmp = "包序号： %d: \n网卡名称: %s" % (number + 1, self.dev)
        self.textEdit.setText(tmp)
        self.textEdit.append("包长度: %d bytes" % len(pkt))
        self.textEdit.append("包的层次： " + str(pkt))
        # self.textEdit.append(str(pkt.layers))
        # self.textEdit.append(str(dir(pkt)))
        # self.textEdit.append(str(pkt.firstlayer()))
        # self.textEdit.append(str(type(pkt.firstlayer())))
        if pkt.haslayer("Ether"):
            self.textEdit.append("包的具体内容:")
            output = StringIO()
            sys.stdout = output
            pkt.display()
            self.textEdit.append(output.getvalue())
            sys.stdout = sys.__stdout__

        hex_data = ' '.join([f'{x:02X}' for x in bytes(pkt)])
        lines = [hex_data[i:i + 48] for i in range(0, len(hex_data), 48)]
        self.textEdit_2.setPlainText('\n'.join(lines))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainwindow = Sniff_Mainwindow()
    mainwindow.show()
    sys.exit(app.exec_())
