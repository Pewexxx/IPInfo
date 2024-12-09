import unittest
from ip import (
    convert_to_cidr,
    parse_ip_and_mask,
    validate_netmask,
    ipaddress
)


class TestIPProgram(unittest.TestCase):

    # Testy konwersji maski na CIDR
    def test_convert_to_cidr_valid(self):
        # Test poprawnej konwersji IP + maska na CIDR
        self.assertEqual(convert_to_cidr("192.168.1.0 255.255.255.0"), "192.168.1.0/24")
        self.assertEqual(convert_to_cidr("10.0.0.0 255.0.0.0"), "10.0.0.0/8")

    def test_convert_to_cidr_invalid(self):
        # Test błędnej konwersji IP + maska na CIDR (nieprawidłowa maska)
        with self.assertRaises(ValueError):
            convert_to_cidr("192.168.1.0 255.300.255.0")

    # Testy sprawdzenia poprawności maski
    def test_validate_netmask_valid(self):
        # Test poprawnej walidacji masek sieciowych
        self.assertEqual(validate_netmask("255.255.255.0"), 24)
        self.assertEqual(validate_netmask("255.255.0.0"), 16)

    def test_validate_netmask_invalid(self):
        # Test błędnej walidacji maski sieciowej
        with self.assertRaises(ValueError):
            validate_netmask("255.255.300.0")

    # Testy parsowania adresów IP i maski sieci
    def test_parse_ip_and_mask_valid(self):
        # Test poprawnego parsowania IP + maska
        ip_obj, ip_class, is_private = parse_ip_and_mask("192.168.1.100", "255.255.255.0")
        self.assertEqual(str(ip_obj), "192.168.1.100/24")
        self.assertEqual(ip_class, "CIDR")
        self.assertTrue(is_private)

        ip_obj, ip_class, is_private = parse_ip_and_mask("10.0.0.1")
        self.assertEqual(str(ip_obj), "10.0.0.1/8")
        self.assertEqual(ip_class, "Klasa A")
        self.assertTrue(is_private)

    def test_parse_ip_and_mask_invalid(self):
        # Test błędnego parsowania IP + maska
        with self.assertRaises(ValueError):
            parse_ip_and_mask("192.168.1.100", "255.255.300.0")
        with self.assertRaises(ValueError):
            parse_ip_and_mask("300.300.300.300")

    # Test przynależności do sieci
    def test_ip_in_network(self):
        # Test sprawdzania, czy IP należy do sieci
        network = ipaddress.ip_network("192.168.1.0/24", strict=False)
        ip = ipaddress.IPv4Address("192.168.1.100")
        self.assertTrue(ip in network)

    def test_ip_not_in_network(self):
        # Test sprawdzania, czy IP NIE należy do sieci
        network = ipaddress.ip_network("10.0.0.0/8", strict=False)
        ip = ipaddress.IPv4Address("192.168.1.100")
        self.assertFalse(ip in network)


if __name__ == "__main__":
    unittest.main(verbosity=2)
