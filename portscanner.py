import socket
import argparse

parser = argparse.ArgumentParser(description='A simple portscanner')
parser.add_argument('host', help='Specify the host to scan')
parser.add_argument('--portrange', '-p', type=str, help='Specify a port range to scan')
parser.add_argument('--service', '-s', type=str, help='Specify a service name to scan the underlying port')
parser.add_argument('--timeout', '-t', type=int, help='Set the timeout for the tcp connections')
parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
arguments = parser.parse_args()


def printv(*args, **kwargs):
    if arguments.verbose:
        print(*args, **kwargs)


def tcp_connect_port(host: str, port: int, timeout: int):
    ip_address = socket.gethostbyname(host)
    status = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    printv("Timeout set to {}".format(timeout))
    try:
        connection = s.connect((ip_address, port))
        if connection is None:
            printv('Connection to port {} successful'.format(port))
            status = 'open'
    except ConnectionRefusedError:
        printv('Connection to port {} refused'.format(port))
        status = 'closed'
    except socket.timeout:
        printv('Connection to port {} timed out'.format(port))
        status = 'firewalled'
    finally:
        s.close()
        return tuple((port, status))


def tcp_connect_scan(host: str = 'localhost', portrange: str = '22', timeout: int = 2):
    printv("Host: {}, Portrange: {}, Timeout: {}".format(host, portrange, timeout))
    ports = parse_portstring(portrange)
    if ports[1]:
        for i in range(ports[0][0], ports[0][1]):
            yield tcp_connect_port(host, i, timeout)
    else:
        for port in ports[0]:
            yield tcp_connect_port(host, port, timeout)


def parse_portstring(portrange: str):
    is_portrange = False
    if '-' in portrange:
        is_portrange = True
        ports = portrange.split('-')
        for i in range(len(ports)):
            ports[i] = int(ports[i].strip())
    elif ',' in portrange:
        ports = portrange.split(',')
        for i in range(len(ports)):
            ports[i] = int(ports[i].strip())
    else:
        ports = [int(portrange)]

    ports = list(dict.fromkeys(ports))  # remove duplicate entries
    return (ports, is_portrange)


def parse_service_to_port(service):
    if ',' in service:
        services = service.split(',')
        ports = [socket.getservbyname(service.strip()) for service in services]
    else:
        ports = socket.getservbyname(service)
    return ports


def main():
    if arguments.host and arguments.portrange and arguments.timeout is not None:
        for result in tcp_connect_scan(arguments.host, arguments.portrange, arguments.timeout):
            print(result)
    elif arguments.host and arguments.portrange is not None:
        for result in tcp_connect_scan(arguments.host, arguments.portrange):
            print(result)
    elif arguments.host is not None:
        for result in tcp_connect_scan(arguments.host):
            print(result)
    else:
        for result in tcp_connect_scan():
            print(result)


if __name__ == '__main__':
    main()
