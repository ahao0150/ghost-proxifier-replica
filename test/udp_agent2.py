import socket, sys
mode = sys.argv[1] if len(sys.argv) > 1 else 'sendto'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(6)
try:
    if mode == 'connected':
        s.connect(('1.1.1.1', 9999))
        s.send(b'connected-udp')
        data, addr = s.recvfrom(2048)
        print('CONNECTED_OK', data.decode(errors='replace'), addr, 'peer=', s.getpeername())
    else:
        s.sendto(b'sendto-udp', ('1.1.1.1', 9999))
        data, addr = s.recvfrom(2048)
        print('SENDTO_OK', data.decode(errors='replace'), addr)
except Exception as e:
    print('UDP_ERR', repr(e))
