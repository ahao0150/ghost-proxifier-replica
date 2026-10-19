import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(6)
try:
    s.sendto(b'hello-udp', ('1.1.1.1', 9999))
    data, addr = s.recvfrom(2048)
    print('UDP_OK', data.decode(errors='replace'), addr)
except Exception as e:
    print('UDP_ERR', repr(e))
