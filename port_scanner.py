import socket
from datetime import datetime

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def main():
    target_ip = input('Enter target IP address: ').strip()
    ports_input = input('Enter ports (comma-separated, e.g. 21,22,80): ')
    ports = [int(p.strip()) for p in ports_input.split(',')]

    print(f'\n--- Port Scan Report for {target_ip} ---')
    print(f'Scan started: {datetime.now()}\n')

    open_ports = []
    for port in ports:
        is_open = scan_port(target_ip, port)
        status = 'OPEN  [!]' if is_open else 'CLOSED'
        print(f' Port {port:5d}  →  {status}')
        if is_open:
            open_ports.append(port)

    print(f'\nTotal open ports: {len(open_ports)}')
    print(f'Scan completed: {datetime.now()}')

if __name__ == '__main__':
    main()
