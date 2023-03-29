from scapy.all import *


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

# def CallBack(packet):
#     print(packet.show())
#
#     if packet.haslayer('TCP'):
#         print(packet['TCP'].sport)
#         print(packet['TCP'].dport)
#         print(packet['TCP'].seq)
#         print(packet['TCP'].dataofs)
#
#
# filter = "tcp"
# 1313221
packet = sniff(filter=filter, iface=iface, count=0)
