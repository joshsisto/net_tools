# Network Tools

Network Tools is a Flask-based web application that provides various networking utilities. It can be used to gather information about a client's public IP address, scan certain ports, check a server's `robots.txt` file, make a curl-like request to a given IP address, and fetch SSL certificate information for a given IP address.

## Features

Network Tools offers the following features:

- **Public IP Information**: When a client visits the web application, the application retrieves information about the client's public IP address, including location, organization, and more.

- **Port Scanning**: The application scans certain ports (22, 25, 80, 443, 445, 135, 139) on the client's IP address and displays which ones are open.

- **HTTP Headers**: The application displays the HTTP headers sent by the client.

- **Client Properties**: Using JavaScript, the application gathers and displays various properties of the client, including the user agent, browser, operating system, screen resolution, color depth, language, and more.

- **Check Robots.txt**: Users can enter an IP address or domain to retrieve the `robots.txt` file for that address or domain.

- **CURL IP**: Users can enter an IP address and port to send a GET request to that address and port, similar to making a curl request in a terminal.

- **Get Certificate**: Users can enter an IP address to retrieve SSL certificate information for that address.

## Setup and Usage

### Dependencies

The application requires the following dependencies:

- Python 3.6 or later
- Flask
- requests
- ssl

### Running the Application

To run the application, navigate to the directory containing `app.py` and use the following command:


The application will start a server that listens on all interfaces (0.0.0.0) and serves the web application.

Open a web browser and navigate to `http://localhost:5000` (or `http://<your_server_ip>:5000` if you're running the server on a different machine) to use the application.

### Using the Application

Upon visiting the application in a web browser, you'll see information about your public IP address, the results of a port scan, your HTTP headers, and properties of your client.

You can enter an IP address or domain and click "Check Robots.txt" to retrieve the `robots.txt` file for that address or domain.

You can enter an IP address and port and click "CURL IP" to send a GET request to that address and port.

You can enter an IP address and click "Get Certificate" to retrieve SSL certificate information for that address.

## Contributing

Contributions to Network Tools are welcome. Please fork the repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss the proposed change.

## License

Network Tools is licensed under the MIT License. See the LICENSE file for details.
