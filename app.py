from flask import Flask, request, render_template, jsonify
from utilities import record_ip, port_scan, is_private_ip, get_ip_info, get_dns_name
import requests
import ssl

app = Flask(__name__)

@app.route('/')
def index():
    global visitor_ip
    http_headers = request.headers
    x_real_ip = http_headers.get("X-Real-Ip", None)
    visitor_ip = x_real_ip
    # Record the visitor's IP address
    record_ip(visitor_ip)
    # Check if the IP address is private or public
    ip_info = None
    dns_name = None
    if not is_private_ip(visitor_ip):
        # Get additional IP information
        ip_info = get_ip_info(visitor_ip)
        # Get DNS name (reverse DNS lookup)
        dns_name = get_dns_name(visitor_ip)
    # Get HTTP headers

    return render_template('index.html', ip_address=visitor_ip, ip_info=ip_info, dns_name=dns_name, http_headers=http_headers)

@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    # visitor_ip = request.remote_addr
    # Ports to scan
    ports_to_scan = [22, 25, 80, 443, 445, 135, 139]
    # Perform the port scan
    open_ports = port_scan(visitor_ip, ports_to_scan)
    return jsonify({'open_ports': open_ports})

@app.route('/check_robots_txt', methods=['POST'])
def check_robots_txt():
    data = request.get_json()
    target_ip = data.get('target_ip')
    try:
        response = requests.get(f'http://{target_ip}/robots.txt')
        return {'status': 'success', 'content': response.text}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


@app.route('/curl_ip', methods=['POST'])
def curl_ip():
    target_ip = request.json.get('target_ip')
    port = request.json.get('port')
    protocol = 'https' if port == 443 else 'http'
    try:
        response = requests.get(f'{protocol}://{target_ip}', timeout=3)
        return {'status': 'success', 'content': response.text}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

@app.route('/get_certificate', methods=['POST'])
def get_certificate():
    target_ip = request.json.get('target_ip')
    try:
        # Get SSL certificate information
        cert_info = ssl.get_server_certificate((target_ip, 443))
        return {'status': 'success', 'content': cert_info}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    
@app.route('/tools')
def tools():
    global visitor_ip
    return render_template('tools.html', ip_address=visitor_ip)

if __name__ == '__main__':
    # Set the host parameter to '0.0.0.0' to make the application accessible from any IP address
    app.run(host='0.0.0.0', debug=True)
