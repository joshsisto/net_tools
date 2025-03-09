import os
import socket
import ipaddress
import requests
import dns.resolver
import dns.zone
import whois  # pip install python-whois
import subprocess
import ssl
import datetime

def get_dns_name(ip_address):
    try:
        dns_name = socket.gethostbyaddr(ip_address)[0]
        return dns_name
    except (socket.herror, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return None

def record_ip(ip_address):
    try:
        with open('./logs/ip_addresses.txt', 'a') as f:
            f.write(ip_address + '\n')
        return True
    except Exception as e:
        print(f"An error occurred while recording IP address: {e}")
        return False


def port_scan(target_ip, ports, udp=False, service_detection=False):
    open_ports = {}
    for port in ports:
        try:
            if udp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports[port] = "Unknown"  # Default to unknown

                if service_detection and not udp:
                    try:
                        banner = ""
                        # Protocol-specific probes and banner extraction
                        if port in [80, 443, 8080, 8443]:  # HTTP(S) ports
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            for line in response.splitlines():
                                if line.lower().startswith("server:"):
                                    banner = line.split(":", 1)[1].strip()
                                    break
                        elif port in [25, 110, 143, 465, 587, 993, 995]: # Email
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            banner = response.splitlines()[0].strip() # First Line
                        elif port == 21:
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            banner = response.splitlines()[0].strip() # First Line
                        elif port == 22:
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            banner = response.strip()
                        else: # Other
                            sock.send(b"Hello\r\n") # Send a basic probe
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            open_ports[port] = banner

                    except Exception as e:
                        pass # Ignore errors during service detection
        except Exception as e:
            pass
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
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        return None

def perform_dns_lookup(target, record_type):
    results = []
    try:
        if record_type == 'AXFR':
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(target, target))
                for name, ttl, rdata in zone.iterate_rdatas():
                    results.append(f"{name} {ttl} {rdata.rdtype} {rdata}")
            except Exception as e:
                results.append(f"Zone transfer failed: {e}")

        else:
            answers = dns.resolver.resolve(target, record_type)
            for rdata in answers:
                results.append(str(rdata))
    except dns.resolver.NXDOMAIN:
        results.append(f"No {record_type} record found for {target}")
    except dns.resolver.NoAnswer:
        results.append(f"No answer for {record_type} query for {target}")
    except Exception as e:
        results.append(f"Error during DNS lookup: {str(e)}")
    return results

def perform_whois_lookup(target):
    try:
        w = whois.whois(target)
        return str(w)  # Convert to string for easy display
    except Exception as e:
        return f"Error during WHOIS lookup: {str(e)}"

def perform_traceroute(target):
    try:
        if os.name == 'nt':
            command = ['tracert', target]
        else:
            command = ['traceroute', target]  # Correct command for Linux/macOS

        # Use subprocess.run with shell=False (more secure)
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=True) # check=True raises exception on error
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Traceroute failed with error code {e.returncode}:\n{e.stderr}" # Show stderr
    except subprocess.TimeoutExpired:
        return "Traceroute timed out."
    except FileNotFoundError:  # Catch the specific FileNotFoundError
        return "Traceroute command ('traceroute' or 'tracert') not found.  Please ensure it is installed and in your system's PATH."
    except Exception as e:
        return f"Error during traceroute: {str(e)}"

def analyze_http_headers(target):
    try:
        response = requests.get(f'http://{target}', timeout=5)
        response.raise_for_status()
        headers = response.headers
        analysis = {}

        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'XFO',
            'X-XSS-Protection': 'X-XSS',
            'X-Content-Type-Options': 'X-CTO'
        }
        for header, name in security_headers.items():
            if header in headers:
                analysis[name] = headers[header]
            else:
                analysis[name] = "Not Present"

        # Check for server version disclosure
        if 'Server' in headers:
            analysis['Server'] = headers['Server']
        else:
            analysis['Server'] = "Not Disclosed"

        return analysis

    except requests.exceptions.RequestException as e:
        return f"Error analyzing headers: {str(e)}"


def get_certificate_details(target_ip):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                cert = ssock.getpeercert()

                # Extract relevant information
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                sans = [x[1] for x in cert.get('subjectAltName', [])]
                serial_number = cert.get('serialNumber', 'N/A')


                cert_details = {
                    'subject': subject.get('commonName', 'N/A'),
                    'issuer': issuer.get('commonName', 'N/A'),
                    'valid_from': not_before.isoformat(),
                    'valid_to': not_after.isoformat(),
                    'expired': datetime.datetime.utcnow() > not_after,
                    'sans': sans,
                    'serial_number': serial_number,
                }


                return cert_details

    except Exception as e:
        print(f"Error getting certificate details: {str(e)}")
        return None
