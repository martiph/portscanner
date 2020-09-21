import time
import socket
import argparse

parser = argparse.ArgumentParser(description='A simple portscanner')
parser.add_argument('host', help='Specify the host to scan')
parser.add_argument('--portrange', '-p', type=str, help='Specify a port range to scan')
parser.add_argument('--service', '-s', type=str, help='Specify a service name to scan the associated port')
parser.add_argument('--timeout', '-t', type=int, help='Set the timeout for the tcp connections')
parser.add_argument('--fingerprint', '-f', action='store_true', help='Try to perform service fingerprinting')
parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
arguments = parser.parse_args()


def printv(*args, **kwargs):
    if arguments.verbose:
        print(*args, **kwargs)


def parse_portstring(portrange: str):
    ports = list()
    if ',' in portrange and '-' in portrange:
        portrange_list = portrange.split(',')
        for port in portrange_list:
            if '-' in port:
                portsubrange = port.split('-')
                for p in range(int(portsubrange[0]), int(portsubrange[1])):
                    ports.append(p)
            else:
                ports.append(int(port))
    elif ',' in portrange:
        portrange_list = portrange.split(',')
        for port in portrange_list:
            ports.append(int(port))
    elif "-" in portrange:
        portrange_list = portrange.split('-')
        for i in range(int(portrange_list[0]), int(portrange_list[1])):
            ports.append(i)
    else:
        ports.append(int(portrange))

    ports = list(dict.fromkeys(ports))  # remove duplicate entries
    return ports


def parse_service_to_port(service):
    ports = list()
    printv("Translating service to port number for service(s): {}".format(service))
    if ',' in service:
        services = service.split(',')
        [ports.append(socket.getservbyname(service.strip())) for service in services]
    else:
        ports.append(socket.getservbyname(service))
    printv("The following ports were extracted from the provided services: {}".format(
        ', '.join([str(port) for port in ports])))
    return ports


def tcp_connect_port(host: str, port: int, timeout: int):
    ip_address = socket.gethostbyname(host)
    status = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    printv("Timeout set to {}".format(timeout))
    try:
        s.connect((ip_address, port))
        if arguments.fingerprint:
            try:
                data = s.recv(4096).decode('utf8')
                printv("Performing service detection on port {}".format(port))
                service_name = socket.getservbyport(port)
                printv("Service {} is in version {}".format(service_name, data))
            except socket.timeout:
                printv("")
        printv('Connection to port {} successful'.format(port))
        status = 'open'
    except ConnectionRefusedError:
        printv('Connection to port {} refused'.format(port))
        status = 'closed'
    except socket.timeout:
        printv('Connection to port {} timed out'.format(port))
        status = 'firewalled'
    except Exception as e:
        printv(e)
    finally:
        printv("closing connection")
        s.close()
        return tuple((port, status))


def tcp_connect_scan(hosts: str = 'localhost', portrange: str = '22', timeout: int = 2):
    printv("Host: {}, Portrange: {}, Timeout: {}".format(hosts, portrange, timeout))
    ports = parse_portstring(portrange)
    hosts = [host.strip() for host in hosts.split(',')]
    for host in hosts:
        for port in ports:
            yield tcp_connect_port(host, port, timeout)


def main():
    printv("Arguments are: {}".format(str(arguments)))
    if arguments.service is not None:
        service_port_list = parse_service_to_port(arguments.service)
        service_port_list = ','.join([str(item) for item in service_port_list])
        if arguments.portrange is not None:
            portrange = arguments.portrange + ',' + service_port_list
        else:
            portrange = service_port_list
    else:
        portrange = arguments.portrange
    if arguments.host and portrange and arguments.timeout is not None:
        for result in tcp_connect_scan(arguments.host, portrange, arguments.timeout):
            print(result)
    elif arguments.host and portrange is not None:
        for result in tcp_connect_scan(arguments.host, portrange):
            print(result)
    elif arguments.host is not None:
        for result in tcp_connect_scan(arguments.host):
            print(result)
    else:
        for result in tcp_connect_scan():
            print(result)


if __name__ == '__main__':
    main()
