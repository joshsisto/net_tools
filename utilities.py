import os
import socket
import ipaddress
import requests
import dns.resolver

def get_dns_name(ip_address):
    try:
        dns_name = socket.gethostbyaddr(ip_address)[0]
        return dns_name
    except (socket.herror, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return None

def record_ip(ip_address):
    try:
        # Append the IP address to the file
        with open('./logs/ip_addresses.txt', 'a') as f:
            f.write(ip_address + '\n')
        return True
    except Exception as e:
        # Log the error message
        print(f"An error occurred while recording IP address: {e}")
        return False

def port_scan(target_ip, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set a timeout for the connection attempt
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)  # Port is open
        except Exception as e:
            pass  # Ignore errors during scanning
        finally:
            sock.close()
    return open_ports

def is_private_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def get_ip_info(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        return data
    except Exception as e:
        return None
