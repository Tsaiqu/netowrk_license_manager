import json
import socket
import threading
from datetime import datetime, timedelta


class LicenseClient:
    def __init__(self):
        self.tcp_socket = None
        self.server_address = None
        self.tcp_thread = None
        self.shutdown_event = threading.Event()
        self.license_username = None
        self.license_key = None
        self.token = None
        self.expiration_time = None

    def start(self):
        self.tcp_thread = threading.Thread(target=self._start_tcp_client)
        self.tcp_thread.start()

    def stop(self):
        self.shutdown_event.set()
        self.tcp_socket.close()

    def set_license(self, username, license_key):
        self.license_username = username
        self.license_key = license_key

    def get_license_token(self):
        if self.token and self.expiration_time and datetime.now() < self.expiration_time:
            return self.token

        if not self.server_address:
            self._discover_server()
        if self.server_address:
            response = self._send_request({
                'LicenceUserName': self.license_username,
                'LicenceKey': self.license_key
            })
            if response and response['Licence']:
                self.token = response['Expired']
                self.expiration_time = datetime.fromisoformat(response['Expired'])
                self._schedule_token_renewal()
                return self.token
            else:
                return response['Description']
        return 'Server discovery failed'

    def _start_tcp_client(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.settimeout(5.0)
        self.tcp_socket.bind(('', 0))
        self.tcp_socket.listen(1)
        while not self.shutdown_event.is_set():
            try:
                connection, client_address = self.tcp_socket.accept()
                data = connection.recv(1024)
                if data.decode('utf-8') == 'RENEW':
                    token = self.get_license_token()
                    connection.sendall(token.encode('utf-8'))
                connection.close()
            except socket.timeout:
                continue

    def _discover_server(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind(('', 0))
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.settimeout(5.0)
        udp_socket.sendto('DISCOVER'.encode('utf-8'), ('<broadcast>', 50000))
        while not self.shutdown_event.is_set():
            try:
                data, address = udp_socket.recvfrom(1024)
                if data.decode('utf-8').startswith('OFFER:'):
                    self.server_address = (address[0], int(data.decode('utf-8')[6:]))
                    break
            except socket.timeout:
                continue

    def _send_request(self, request):
        try:
            tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_client.connect(self.server_address)
            tcp_client.sendall(json.dumps(request).encode('utf-8'))
            response = tcp_client.recv(1024)
            tcp_client.close()
            return json.loads(response.decode('utf-8'))
        except socket.error:
            return None

    def _schedule_token_renewal(self):
        expiration_delta = self.expiration_time - datetime.now()
        renewal_time = max(expiration_delta.total_seconds() - 60, 0)
        threading.Timer(renewal_time, self._renew_token).start()

    def _renew_token(self):
        if self.server_address:
            response = self._send_request({'RenewToken': self.token})
            if response and response['Licence']:
                self.token = response['Expired']
                self.expiration_time = datetime.fromisoformat(response['Expired'])
                self._schedule_token_renewal()
            else:
                self.token = None
                self.expiration_time = None
