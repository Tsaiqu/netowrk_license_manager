import json
import socket
import threading
import time
from datetime import datetime, timedelta
import hashlib


class LicenseServer:
    def __init__(self):
        self.licenses = []
        self.tcp_port = 0
        self.discover_thread = None
        self.tcp_thread = None
        self.tcp_socket = None
        self.shutdown_event = threading.Event()

    def load_licenses(self, filename):
        with open(filename, 'r') as file:
            data = json.load(file)
            licenses_data = data['payload']
            for license_data in licenses_data:
                username = license_data['LicenceUserName']
                count = license_data['Licence']
                ip_addresses = license_data['IPadresses']
                validation_time = license_data['ValidationTime']
                license = {
                    'LicenceUserName': username,
                    'Licence': count,
                    'IPadresses': ip_addresses,
                    'ValidationTime': validation_time,
                    'Token': None,
                    'ExpirationTime': None,
                    'UsedIPs': []
                }
                self.licenses.append(license)

    def generate_license_key(self, username):
        md5_hash = hashlib.md5()
        md5_hash.update(username.encode('utf-8'))
        return md5_hash.hexdigest()

    def start(self):
        self.tcp_port = int(input("Enter the TCP listening port: "))
        self.tcp_thread = threading.Thread(target=self._start_tcp_server)
        self.discover_thread = threading.Thread(target=self._start_discover_server)
        self.tcp_thread.start()
        self.discover_thread.start()
        self._monitor_licenses()

    def stop(self):
        self.shutdown_event.set()
        self.tcp_socket.close()

    def _start_tcp_server(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.bind(('', self.tcp_port))
        self.tcp_socket.listen(5)
        print(f"MLS server is listening on TCP port {self.tcp_port}")
        while not self.shutdown_event.is_set():
            client_socket, _ = self.tcp_socket.accept()
            threading.Thread(target=self._handle_client_request, args=(client_socket,)).start()

    def _handle_client_request(self, client_socket):
        request_data = client_socket.recv(1024).decode('utf-8')
        request_json = json.loads(request_data)
        username = request_json['LicenceUserName']
        license_key = request_json['LicenceKey']
        response = self._verify_license(username, license_key)
        client_socket.send(json.dumps(response).encode('utf-8'))
        client_socket.close()

    def _verify_license(self, username, license_key):
        response = {
            'LicenceUserName': username,
            'Licence': False,
            'Description': ''
        }
        for license in self.licenses:
            if license['LicenceUserName'] == username:
                generated_key = self.generate_license_key(username)
                if generated_key == license_key:
                    if self._is_license_valid(license):
                        license['UsedIPs'].append(self._get_client_ip())
                        response['Licence'] = True
                        response['Expired'] = license['ExpirationTime'].isoformat()
                        break
                    else:
                        response['Description'] = 'No available licenses for the user or IP restriction'
                else:
                    response['Description'] = 'Invalid license key'
                break
        else:
            response['Description'] = 'No license found for the user'
        return response

    def _is_license_valid(self, license):
        if license['Licence'] == 0 or license['Licence'] > len(license['UsedIPs']):
            if 'any' in license['IPadresses'] or self._get_client_ip() in license['IPadresses']:
                return True
        return False

    def _monitor_licenses(self):
        while not self.shutdown_event.is_set():
            for license in self.licenses:
                if license['ExpirationTime'] and datetime.now() > license['ExpirationTime']:
                    license['UsedIPs'] = []
                    license['Token'] = None
                    license['ExpirationTime'] = None
            time.sleep(1)

    def _start_discover_server(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind(('', 50000))
        mcast_group = '224.0.0.1'
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(mcast_group) + socket.inet_aton('0.0.0.0'))
        while not self.shutdown_event.is_set():
            data, address = udp_socket.recvfrom(1024)
            if data.decode('utf-8') == 'DISCOVER':
                response = f'OFFER:{self.tcp_port}'
                udp_socket.sendto(response.encode('utf-8'), address)

    @staticmethod
    def _get_client_ip():
        return '127.0.0.1'  # Placeholder, implement real logic to get the client's IP


if __name__ == '__main__':
    server = LicenseServer()
    server.load_licenses('licenses.json')
    server.start()
