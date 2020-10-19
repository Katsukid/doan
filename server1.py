# Server voi tinh nang ngat ket noi khi timeout
import socket
import threading
import time
from collections import Counter
from scapy.all import sniff
from scapy.layers.inet import TCP



c = threading.Condition()
flag = -1      #shared between Thread_A and Thread_B - Co kiem tra: 0 - count cur_time, -1: reach Timeout, break all while, 1: reset cur_time
cur_time = 0
timeout = 10
src = ""
sport = ""
count = 0
class Thread_Socket(threading.Thread):
    def __init__(self, name):
        threading.Thread.__init__(self)
        self.name = name
        HOST = '192.168.46.1'  # Địa chỉ IP
        PORT = 4100      # Địa chỉ cổng
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
        self.s.bind((HOST, PORT))
    def run(self):
        global flag # Co
        global cur_time # Thoi gian hien tai
        global src
        global sport
        while True:
            self.s.listen(1) # Mo cong doi ket noi
            self.conn, self.addr = self.s.accept() # Nhan ket noi
            src = self.addr[0] 
            sport = str(self.addr[1])
            print('Connected by', self.addr)
            flag = 0 # Dat co kiem tra
            while True:
                data = self.conn.recv(65535) # Doc du lieu
                packet = data.decode()
                print(packet)
                if(flag == 1):
                    cur_time = 0
                    flag = 0
                elif flag == -1:
                    # self.conn.close()
                    break;
    def stopConn(self):
        self.conn.close()
class Thread_Timer(threading.Thread):
    def __init__(self, name, thread_socket): # Khởi tạo luồng
        threading.Thread.__init__(self)
        self.name = name
        self.thread_socket = thread_socket
    def run(self):
        global flag
        global cur_time    #made global here
        while True:
            if flag == 0:
                cur_time += 1
                time.sleep(1)
                print ("Current wait time = " + str(cur_time) + " flag-"+ str(flag))
                if(cur_time == timeout):                    
                    flag = -1
                    # self.thread_socket.stopConn()
                    break
            if flag == 1:
                flag = 0
                cur_time = 0

## Define our Custom Action function
def custom_action(packet):
    global flag
    global src
    global sport
    global count
    count += 1
    if src == packet[0][1].src and sport == packet[0][1].sport:
        flag = 1
    return f"Packet #{count}: {packet[0][1].src}:{packet[0][1].sport} ==> {packet[0][1].dst}:{packet[0][1].dport} -- SEQ:{packet[0][1].seq}"

class Thread_Checker(threading.Thread):
    def __init__(self, name, thread_socket): # Khởi tạo luồng
        threading.Thread.__init__(self)
        self.name = name
        self.thread_socket = thread_socket
    def run(self):
        #made global here
        global flag
        while True:
            if src != "" and sport != "":
                ## Setup sniff, filtering for IP traffic
                sniff(filter="tcp and host "+ src +" and port " + sport, prn=custom_action)
            if flag == -1:
                break

a = Thread_Socket("Thread server")
b = Thread_Timer("Thread timer", a)

b.start()
a.start()

a.join()
b.join()