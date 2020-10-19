# Client tao ket noi gia khong phan hoi
import scapy.all as scapy
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
import time
dst = '10.10.10.2'
dstPort = 8080
src = '10.10.10.5'
srcPort = 1200
seq = 900001
ack = 0
ttl = 64
flagsIP = "DF"
id = 32711
chksum = 0 # để 0 rồi del đi để scapy tự tính
# TCP
flagsTCP = "S"
# msg ="0123456789"
pak = IP(dst=dst, src = src, ttl=ttl, flags=flagsIP,len=40, chksum = 0)/TCP(flags=flagsTCP, sport=srcPort, dport=int(dstPort), chksum = 0, seq=seq, ack=ack, window=65535)
del pak[IP].chksum
del pak[TCP].chksum
print("Packet 1 SYN: " + src + " --> " + dst)
# pak[TCP].flags |= 0x10  # set the ACK flag
pak = pak.__class__(bytes(pak)) # Tự động tính chksum | show2() chỉ tính và in ra, không lưu lại vào packet
pak = pak
pak.show()

# "VMware Network Adapter VMnet8"
iface = "Ethernet"
scapy.send(pak, iface=iface)
filterd = "tcp && port " + str(dstPort)

syn_ack = scapy.sniff(filter=filterd, count=1, iface=iface)[0]
# ACK reply in handshake
ack = IP(dst=dst, src = src, ttl=ttl, flags=flagsIP,len=40, chksum = 0)/TCP(flags="A", sport=srcPort, dport=dstPort, chksum = 0, seq=syn_ack.ack, ack=syn_ack.seq + 1, window=65535)
del ack[IP].chksum
del ack[TCP].chksum
print("Packet 1 ACK: " + src + " --> " + dst)
ack = ack.__class__(bytes(ack)) # Tự động tính chksum | show2() chỉ tính và in ra, không lưu lại vào packet
ack.show()
scapy.send(ack, iface=iface)
# # FIN-ACK
# fin_ack = IP(dst=dst, src = src, ttl=ttl, flags=flagsIP,len=40, chksum = 0)/TCP(flags="FA", sport=srcPort, dport=dstPort, chksum = 0, seq=ack.seq, ack=ack.ack, window=65535)
# del fin_ack[IP].chksum
# del fin_ack[TCP].chksum
# print("Packet 1 ACK: " + src + " --> " + dst)
# fin_ack = fin_ack.__class__(bytes(fin_ack)) # Tự động tính chksum | show2() chỉ tính và in ra, không lưu lại vào packet
# fin_ack.show()

# # fake ACK2
# ack2 = IP(dst=dst, src = src, ttl=ttl, flags=flagsIP,len=40, chksum = 0)/TCP(flags="A", sport=srcPort, dport=dstPort, chksum = 0, seq=ack.ack, ack=ack.seq + 1 , window=65535)
# del ack2[IP].chksum
# del ack2[TCP].chksum
# print("Packet 1 ACK: " + src + " --> " + dst)
# ack2 = ack2.__class__(bytes(ack2)) # Tự động tính chksum | show2() chỉ tính và in ra, không lưu lại vào packet
# ack2.show()
# scapy.send(fin_ack, iface=iface)
# scapy.send(ack2, iface=iface)
# while True:
#     time.sleep(1)
#     scapy.send(ack2, iface=iface)