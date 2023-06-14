from license_server import LicenseServer
from license_client import LicenseClient

if __name__ == '__main__':
    license_server = LicenseServer()
    license_client = LicenseClient()
    license_server.start()
    license_client.start()
