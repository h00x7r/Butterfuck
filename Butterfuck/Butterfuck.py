import sys
import os
import re
import psutil
import requests
from ftplib import FTP
import socket
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QMessageBox, QInputDialog
from PyQt5.QtGui import QIcon

class NetworkScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner")
        self.setGeometry(100, 100, 600, 400)

        # Set the window icon
        self.setWindowIcon(QIcon("C:/Users/Monster PC/Desktop/hacker.ico"))

        # Create layout
        layout = QVBoxLayout()

        # Create a button to scan devices
        self.scan_button = QPushButton("Scan Devices")
        self.scan_button.clicked.connect(self.scan_devices_on_network)
        layout.addWidget(self.scan_button)

        # Create a button to show network settings
        self.settings_button = QPushButton("Show Network Settings")
        self.settings_button.clicked.connect(self.show_network_settings)
        layout.addWidget(self.settings_button)

        # Create a button to access devices
        self.access_button = QPushButton("Access Devices")
        self.access_button.clicked.connect(self.access_devices)
        layout.addWidget(self.access_button)

        # Create a text area to display results
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

        self.setLayout(layout)

        # Store scanned devices
        self.scanned_devices = []

    def scan_devices_on_network(self):
        self.text_area.clear()
        try:
            devices = os.popen("arp -a").read()  # Use ARP to list devices
            filtered_devices = self.filter_devices(devices)
            if filtered_devices:
                self.scanned_devices = filtered_devices.split('\n')
                self.text_area.setPlainText("\n".join(self.scanned_devices))
            else:
                self.text_area.setPlainText("No devices found in the 192.168.1.0/24 range.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error scanning devices: {e}")

    def filter_devices(self, devices):
        # Regular expression to match IP addresses in the 192.168.1.0/24 range
        pattern = r'192\.168\.1\.\d{1,3}'
        matches = re.findall(pattern, devices)
        return '\n'.join(matches) if matches else None

    def show_network_settings(self):
        self.text_area.clear()
        try:
            # Get network interfaces and their addresses
            interfaces = psutil.net_if_addrs()
            settings_info = []

            for interface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        settings_info.append(f"{interface} (IPv4): {addr.address}")
                    elif addr.family == socket.AF_INET6:  # IPv6
                        settings_info.append(f"{interface} (IPv6): {addr.address}")

            if settings_info:
                self.text_area.setPlainText("\n".join(settings_info))
            else:
                self.text_area.setPlainText("No network settings found.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error retrieving network settings: {e}")

    def access_devices(self):
        if not self.scanned_devices:
            QMessageBox.warning(self, "Warning", "No devices found. Please scan the network first.")
            return

        # Prompt user to select a device
        device, ok = QInputDialog.getItem(self, "Select Device", "Choose a device to access:", self.scanned_devices, 0, False)
        if ok and device:
            device_type = self.check_device_type(device.strip())
            QMessageBox.information(self, "Device Type", f"The selected device ({device}) is of type: {device_type}")

    def check_device_type(self, ip):
        # Attempt to determine the device type based on HTTP headers
        try:
            response = requests.get(f"http://{ip}", timeout=5)
            server_header = response.headers.get('Server', '')
            if 'Windows' in server_header:
                return "Windows"
            elif 'Linux' in server_header:
                return "Linux"
            elif 'Darwin' in server_header:  # macOS/iOS
                return "iOS/macOS"
            elif 'Android' in server_header:
                return "Android"
            else:
                return "Unknown Device Type"
        except Exception as e:
            return "Unable to determine device type"

    def check_device(self, ip):
        results = []

        # Check HTTP
        results.append(self.check_http(ip))
        # Check HTTPS
        results.append(self.check_https(ip))
        # Check FTP
        results.append(self.check_ftp(ip))
        # Check TCP (for a specific port, e.g., 8080)
        results.append(self.check_tcp(ip, 8080))  # Change port as needed

        return "\n".join(filter(None, results))  # Filter out None results

    def check_http(self, ip):
        try:
            response = requests.get(f"http://{ip}", timeout=5)
            if response.status_code == 200:
                return f"Device at {ip} is accessible via HTTP."
            else:
                return f"Device at {ip} returned HTTP status code: {response.status_code}"
        except requests.ConnectionError:
            return f"Device at {ip} is not accessible."
        except requests.Timeout:
            return f"Device at {ip} timed out."
        except Exception as e:
            return f"Error accessing {ip}: {e}"

    def check_https(self, ip):
        try:
            response = requests.get(f"https://{ip}", timeout=5)
            if response.status_code == 200:
                return f"Device at {ip} is accessible via HTTPS."
            else:
                return f"Device at {ip} returned HTTPS status code: {response.status_code}"
        except requests.ConnectionError:
            return f"Device at {ip} is not accessible via HTTPS."
        except requests.Timeout:
            return f"Device at {ip} timed out."
        except Exception as e:
            return f"Error accessing {ip}: {e}"

    def check_ftp(self, ip):
        try:
            ftp = FTP(ip)
            ftp.login()  # You may need to provide credentials
            ftp.quit()
            return f"Device at {ip} is accessible via FTP."
        except Exception as e:
            return f"Error accessing {ip} via FTP: {e}"

    def check_tcp(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.close()
            return f"Device at {ip} is accessible via TCP on port {port}."
        except socket.error:
            return f"Device at {ip} is not accessible via TCP on port {port}."
        except Exception as e:
            return f"Error accessing {ip} via TCP on port {port}: {e}"

def main():
    app = QApplication(sys.argv)
    window = NetworkScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
