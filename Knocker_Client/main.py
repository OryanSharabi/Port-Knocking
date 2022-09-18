import socket
import struct
import scapy.all


D_IP = "10.1.2.108"
P_LIST = [277, 166, 278, 74]


def send_SYN(port):
    ip = scapy.all.IP(dst=D_IP)
    tcp = scapy.all.TCP(dport=port, flags="S")
    scapy.all.send((ip/tcp))


if __name__ == '__main__':
    for port in P_LIST:
        send_SYN(port)
        print(port)

    """s = socket.socket()
    s.connect(("10.1.2.202", 8080))
    s.send(struct.pack("<L", len("ipconfig\r\n")))
    s.send(b"ipconfig\r\n")
    bbb = s.recv(10000)
    print(bbb.decode())"""

