import importlib.util
import ipaddress
import unittest

class DnsTests(unittest.TestCase):
    def test_a_record_points_to_configured_address(self):
        self.assertIsNotNone(importlib.util.find_spec('app'), 'DNS application is not implemented')
        import app
        from dnslib import DNSRecord
        reply = app.dns_reply(DNSRecord.question('example.test'), '192.168.1.146', None)
        self.assertEqual(str(reply.rr[0].rdata), '192.168.1.146')
        self.assertEqual(reply.rr[0].ttl, 0)

if __name__ == '__main__':
    unittest.main()
