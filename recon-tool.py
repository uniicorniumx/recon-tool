import socket
import requests
import whois
import dnslib

def port_scanner(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((host, port))
    if result == 0:
        return (f"Port {port} is open")
    sock.close()

def service_identifier(host, port):
    try:
        service = socket.getservbyport(port)
        return (f"Port {port} is running {service}")
    except:
        return (f"Port {port} is not running a recognized service")

def http_request(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    response = requests.get(url, headers=headers)
    return response.status_code

def dns_lookup(host):
    result = dnslib.DNSRecord.parse(dnslib.DNSRecord.question(host).send(host, 53, timeout=5))
    return result

def gather_info(host):
    results = []
    for port in range(1, 65535):
        result = port_scanner(host, port)
        if result:
            results.append(result)
            results.append(service_identifier(host, port))
    results.append(f"HTTP response code: {http_request(f'http://{host}')}")
    results.append(f"DNS lookup: {dns_lookup(host)}")
    return results

def save_to_file(file, results):
    with open(file, 'w') as f:
        for result in results:
            f.write(f"{result}\n")

def main(host, file):
    results = gather_info(host)
    save_to_file(file, results)

if __name__ == '__main__':
    host = input("Enter the target host: ")
    file = input("Enter the output file name: ")
    main(host, file)
