from flask import Flask, request, render_template, jsonify, send_from_directory
from markupsafe import Markup  # Correct import
from utilities import record_ip, port_scan, is_private_ip, get_ip_info, get_dns_name, perform_dns_lookup, perform_whois_lookup, perform_traceroute, analyze_http_headers, get_certificate_details
import requests
import subprocess
import os
import json
import datetime

app = Flask(__name__)

logs_dir = './logs'
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

def create_copy_button(text):
    """Creates the HTML for a copy button."""
    # Use Markup to prevent auto-escaping of HTML.
    return Markup(f'<button class="copy-button" onclick="copyToClipboard(\'{text}\')">Copy</button>')


@app.route('/')
def index():
    http_headers = request.headers
    x_real_ip = http_headers.get("X-Real-Ip", None)
    visitor_ip = x_real_ip or request.remote_addr
    record_ip(visitor_ip)
    ip_info = None
    dns_name = None
    if not is_private_ip(visitor_ip):
        ip_info = get_ip_info(visitor_ip)
        dns_name = get_dns_name(visitor_ip)

    # Create HTML with copy buttons *here*
    ip_address_html = f"{visitor_ip} {create_copy_button(visitor_ip)}"
    hostname_html = ip_info.get('query', 'N/A') + " " +  create_copy_button(ip_info.get('query', 'N/A')) if ip_info else 'N/A'
    dns_name_html = (dns_name or 'N/A') + " " + create_copy_button(dns_name or 'N/A') if dns_name else 'N/A'

    # Prepare headers with copy buttons
    headers_with_buttons = {}
    for header, value in http_headers.items():
      headers_with_buttons[header] = f"{value} {create_copy_button(value)}"


    return render_template('index.html', ip_address=ip_address_html, ip_info=ip_info,
                           dns_name=dns_name_html, http_headers=headers_with_buttons, hostname = hostname_html)

# --- Other routes remain unchanged ---
@app.route('/tools')
def tools():
    http_headers = request.headers  # Get headers here too
    x_real_ip = http_headers.get("X-Real-Ip", None) # Or request.remote_addr as a fallback
    visitor_ip = x_real_ip or request.remote_addr  # Use x_real_ip if available, otherwise use remote_addr
    return render_template('tools.html', ip_address=visitor_ip)

@app.route('/dns_lookup', methods=['POST'])
def dns_lookup():
    data = request.get_json()
    target = data.get('target')
    record_type = data.get('record_type')
    try:
        results = perform_dns_lookup(target, record_type)
        return jsonify({'status': 'success', 'results': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/whois', methods=['POST'])
def whois():
    data = request.get_json()
    target = data.get('target')
    try:
        whois_info = perform_whois_lookup(target)
        return jsonify({'status': 'success', 'results': whois_info})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/traceroute', methods=['POST'])
def traceroute():
    data = request.get_json()
    target = data.get('target')
    try:
        traceroute_output = perform_traceroute(target)
        return jsonify({'status': 'success', 'results': traceroute_output})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/analyze_headers', methods=['POST'])
def analyze_headers():
    data = request.get_json()
    target = data.get('target')
    try:
        analysis = analyze_http_headers(target)
        return jsonify({'status': 'success', 'results': analysis})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    data = request.get_json()
    target_ip = data.get('target_ip')
    scan_type = data.get('scan_type')
    ports_to_scan = []

    if scan_type == 'top_100':
        ports_to_scan = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443] + list(range(1000, 1101)) # Example top 100
    elif scan_type == 'all_tcp':
        ports_to_scan = list(range(1, 65536))
    elif scan_type == 'custom':
        ports_to_scan = [int(p) for p in data.get('ports').split(',') if p.strip().isdigit()]
    elif scan_type == 'udp':
        ports_to_scan = [53, 67, 68, 123, 137, 138, 161, 162, 500, 514, 520, 631, 1900, 4500, 5353] # Common UDP ports

    open_ports = port_scan(target_ip, ports_to_scan, scan_type == 'udp')
    results = {}
    for port in open_ports:
        service_info = port_scan(target_ip, [port], scan_type == 'udp', service_detection=True) # Attempt service detection
        results[port] = service_info.get(port, "Unknown") # Get the service name, default to "Unknown"

    return jsonify({'open_ports': results, 'target_ip': target_ip})


@app.route('/check_robots_txt', methods=['POST'])
def check_robots_txt():
    data = request.get_json()
    target_ip = data.get('target_ip')
    try:
        response = requests.get(f'http://{target_ip}/robots.txt', timeout=5)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        return {'status': 'success', 'content': response.text}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': str(e)}



@app.route('/curl_ip', methods=['POST'])
def curl_ip():
    data = request.get_json()
    target_ip = data.get('target_ip')
    port = data.get('port')
    protocol = 'https' if int(port) == 443 else 'http'
    try:
        response = requests.get(f'{protocol}://{target_ip}:{port}', timeout=5)
        response.raise_for_status()
        return {'status': 'success', 'content': response.text}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': str(e)}


@app.route('/get_certificate', methods=['POST'])
def get_certificate():
    data = request.get_json()
    target_ip = data.get('target_ip')
    try:
        cert_info = get_certificate_details(target_ip)
        if cert_info:
            return {'status': 'success', 'content': cert_info}
        else:
            return {'status': 'error', 'message': 'Could not retrieve certificate details.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target = request.form['target']
        scan_type = request.form.get('scan_type', 'custom')

        if scan_type == 'custom':
            # Your original custom script
            command = f"/home/josh/dns_abuse.sh {target}"
            try:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                returncode = process.returncode
                if returncode == 0:
                    result = output.decode('utf-8').strip()  # Decode and strip
                else:
                    result = f"Custom script error (code {returncode}):\n{error.decode('utf-8').strip()}" # Include error

            except Exception as e:
                result = f"Error running custom script: {str(e)}"
                returncode = 1  # Indicate an error

        elif scan_type == 'nmap':
            # Nmap scan (using the safer subprocess.run)
            command = ["nmap", "-sV", "-Pn", target]
            try:
                process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
                result = process.stdout.strip()  # Decode happens automatically with text=True
                returncode = 0

            except subprocess.CalledProcessError as e:
                result = f"Nmap error (code {e.returncode}):\n{e.stderr}"
                returncode = e.returncode
            except subprocess.TimeoutExpired:
                result = "Nmap scan timed out."
                returncode = 1
            except Exception as e:
                result = f"Error running nmap: {str(e)}"
                returncode = 1

        else:
            return "Invalid scan type selected."


        if returncode == 0:
            # Ensure logs/scans directory exists
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir)
            # Save output to a file in logs/scans
            filename = f"scan_results_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
            filepath = os.path.join(logs_dir, filename)
            with open(filepath, 'w') as file:
                file.write(result) # This will now work reliably
            # Provide path for downloading
            return render_template('scan_result.html', result=result, filename=filename)
        else:
            return result  # Directly return the error message

    return render_template('scan.html')

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(logs_dir, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)