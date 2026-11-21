import unittest
import ipaddress
from network_audit import infer_subnet, COMMON_PORTS

class AuditTests(unittest.TestCase):
    def test_infer_subnet(self):
        self.assertEqual(infer_subnet("192.168.1.25"), "192.168.1.0/24")

    def test_common_ports_are_limited(self):
        self.assertIn(80, COMMON_PORTS)
        self.assertIn(443, COMMON_PORTS)
        self.assertLessEqual(len(COMMON_PORTS), 12)

    def test_subnet_limit(self):
        self.assertGreater(ipaddress.ip_network("192.168.1.0/24").num_addresses, 1)
        self.assertEqual(ipaddress.ip_network("192.168.1.0/24").num_addresses, 256)

if __name__ == "__main__":
    unittest.main()
