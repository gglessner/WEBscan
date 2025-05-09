# WEBscan - HACKtiveMQ Suite

**WEBscan** is a component of the **HACKtiveMQ Suite**, designed to scan hosts for Apache ActiveMQ admin web interfaces. It checks for open ports, detects whether authentication is required, and tests default credentials to identify potential security vulnerabilities. Built with a user-friendly GUI using PySide6, WEBscan provides a robust tool for network administrators and security professionals to assess ActiveMQ deployments.

**Version**: 1.0.0  
**Author**: Garland Glessner (gglesner@gmail.com)  
**Copyright**: © 2025 Garland Glessner  
**License**: GNU General Public License v3.0 or later (see [LICENSE](#license) for details)

---

## Features

- **Host Scanning**: Scan multiple hosts for ActiveMQ admin web interfaces on specified ports (default: 8161).
- **Protocol Support**: Supports both TCP and SSL protocols for flexible scanning.
- **Authentication Testing**: Checks for unauthenticated access and tests default credentials from a `web-defaults.txt` file.
- **GUI Interface**: Intuitive PySide6-based interface with input fields, buttons, and a sortable output table.
- **Host Management**: Load, save, sort, and deduplicate host lists.
- **Output Handling**: Display scan results in a table and save them as CSV files.
- **Status Logging**: Real-time status updates in a dedicated text box.

---

## Requirements

To run WEBscan, you need the following:

- **Python**: Version 3.8 or higher
- **Dependencies** (listed in `requirements.txt`):
  ```plaintext
  PySide6
  websocket-client
```

* **Operating System**: Compatible with Windows, macOS, or Linux
* **Credentials File**: A `web-defaults.txt` file in the `modules` directory, containing username\:password pairs for authentication testing (e.g., `admin:admin`).

---

## Installation

### Clone the Repository:

```bash
git clone https://github.com/yourusername/hacktivemq-suite.git
cd hacktivemq-suite/webscan
```

### Create a Virtual Environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Install Dependencies:

```bash
pip install -r requirements.txt
```

### Prepare the Credentials File:

1. Create a `modules` directory in the project root.
2. Create a `web-defaults.txt` file inside `modules` with username\:password pairs, one per line:

   ```plaintext
   admin:admin
   guest:guest
   ```

---

## Usage

### Run the Application:

```bash
python webscan.py
```

### Interface Overview:

* **Port Input**: Enter the port to scan (default: 8161 for ActiveMQ admin interfaces).
* **Protocol Toggle**: Switch between TCP and SSL using the "TCP/SSL" button.
* **Hosts Text Box**: Input hostnames or IP addresses (one per line) or load from a file using the "Load" button.

#### Hosts Controls:

* **Clear**: Clear the hosts list.
* **Save**: Save the hosts list to a text file.
* **Sort+Dedup**: Sort hosts (numerically for IPs, alphabetically for hostnames) and remove duplicates.

#### Output Table:

Displays scan results with columns for Timestamp, Hostname, Port, Defaults, Auth Status, and Info.

#### Output Controls:

* **Clear**: Clear the output table.
* **Save**: Save the output table as a CSV file.
* **Scan Button**: Initiate the scan for all listed hosts.
* **Status Text Box**: Shows real-time scan progress and errors.

### Example Workflow:

1. Enter `192.168.1.100` and `example.com` in the Hosts Text Box.
2. Set the port to 8161 and select TCP or SSL.
3. Click "Scan" to check for ActiveMQ admin interfaces.
4. View results in the Output Table, including whether authentication is disabled, bypassed with default credentials, or enabled.
5. Save results to a CSV file for further analysis.

---

## Output Table Columns

| Column          | Description                                                                                                                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Timestamp**   | Time the scan was performed (YYYY-MM-DD HH\:MM\:SS).                                                                             |
| **Hostname**    | The scanned host (IP or hostname).                                                                                               |
| **Port**        | The port and protocol (e.g., 8161/tcp or 8161/ssl).                                                                              |
| **Defaults**    | Credentials used if authentication was bypassed (e.g., "admin\:admin") or "None".                                                |
| **Auth Status** | Authentication state: "disabled" (no auth required), "bypassed" (default creds worked), "enabled" (auth required), or "unknown". |
| **Info**        | Additional details, such as the server header or error messages (e.g., "port not open").                                         |

---

## Development

### Code Structure:

* **webscan.py**: Main application file containing the GUI and scanning logic.
* **Ui\_TabContent**: Defines the UI layout using PySide6 widgets.
* **TabContent**: Implements the functionality, including host scanning, credential testing, and table management.
* **modules/web-defaults.txt**: Stores default credentials for testing.

### Customization:

* Modify `web-defaults.txt` to add or update credentials.
* Adjust the `VERSION` constant in `webscan.py` to track releases.
* Extend the `scan_host` method to support additional protocols or checks.

### Dependencies:

* Ensure **PySide6** is installed for the GUI.
* **websocket-client** is included for potential future WebSocket-based scanning (not used in v1.0.0).

---

## Troubleshooting

* **"Credentials file not found"**: Ensure `modules/web-defaults.txt` exists and contains valid username\:password pairs.
* **Connection Errors**: Verify that the target hosts are reachable and the specified port is open.
* **GUI Issues**: Check that **PySide6** is installed correctly (`pip show PySide6`).
* **Scan Failures**: Ensure the correct protocol (TCP or SSL) is selected for the target service.

For additional support, contact the author at [gglesner@gmail.com](mailto:gglesner@gmail.com) or open an issue on the GitHub repository.

---

## License

WEBscan - part of the HACKtiveMQ Suite
Copyright (C) 2025 Garland Glessner - [gglesner@gmail.com](mailto:gglesner@gmail.com)
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.
