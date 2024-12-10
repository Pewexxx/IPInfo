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
        self.assertEqual(convert_to_cidr("192.168.1.0 255.255.255.0"), "192.168.1.0/24")
        self.assertEqual(convert_to_cidr("10.0.0.0 255.0.0.0"), "10.0.0.0/8")


    def test_convert_to_cidr_edge_cases(self):
        self.assertEqual(convert_to_cidr("0.0.0.0 0.0.0.0"), "0.0.0.0/0")
        self.assertEqual(convert_to_cidr("192.168.1.1 255.255.255.255"), "192.168.1.1/32")


    def test_convert_to_cidr_invalid(self):
        with self.assertRaises(ValueError):
            convert_to_cidr("192.168.1.0 255.300.255.0")
        with self.assertRaises(ValueError):
            convert_to_cidr("192.168.1.0 abc.def.ghi.jkl")


    # Testy sprawdzenia poprawności maski
    def test_validate_netmask_valid(self):
        self.assertEqual(validate_netmask("255.255.255.0"), 24)
        self.assertEqual(validate_netmask("255.255.0.0"), 16)
        self.assertEqual(validate_netmask("255.255.255.255"), 32)


    def test_validate_netmask_invalid(self):
        with self.assertRaises(ValueError):
            validate_netmask("255.255.300.0")
        with self.assertRaises(ValueError):
            validate_netmask("invalid_mask")


    # Testy parsowania adresów IP i maski sieci
    def test_parse_ip_and_mask_valid(self):
        ip_obj, ip_class, is_private = parse_ip_and_mask("192.168.1.100", "255.255.255.0")
        self.assertEqual(str(ip_obj), "192.168.1.100/24")
        self.assertEqual(ip_class, "Brak")
        self.assertTrue(is_private)

        ip_obj, ip_class, is_private = parse_ip_and_mask("10.0.0.1")
        self.assertEqual(str(ip_obj), "10.0.0.1/8")
        self.assertEqual(ip_class, "Klasa A")
        self.assertTrue(is_private)


    def test_parse_ip_and_mask_ipv6(self):
        ip_obj, ip_class, is_private = parse_ip_and_mask("2001:db8::1/64")
        self.assertEqual(str(ip_obj), "2001:db8::1/64")
        self.assertEqual(ip_class, "Brak")
        self.assertFalse(ip_obj.ip.is_multicast)


    def test_parse_ip_and_mask_invalid(self):
        with self.assertRaises(ValueError):
            parse_ip_and_mask("192.168.1.100", "255.255.300.0")
        with self.assertRaises(ValueError):
            parse_ip_and_mask("300.300.300.300")
        with self.assertRaises(ValueError):
            parse_ip_and_mask("invalid_ip_address")


    # Test przynależności do sieci
    def test_ip_in_network(self):
        network = ipaddress.ip_network("192.168.1.0/24", strict=False)
        ip = ipaddress.IPv4Address("192.168.1.100")
        self.assertTrue(ip in network)


    def test_ip_not_in_network(self):
        network = ipaddress.ip_network("10.0.0.0/8", strict=False)
        ip = ipaddress.IPv4Address("192.168.1.100")
        self.assertFalse(ip in network)


    # Testy kategorii adresów specjalnych
    def test_special_address_categories(self):
        ip_obj,null,null = parse_ip_and_mask("127.0.0.1")
        self.assertEqual(str(ip_obj.ip), "127.0.0.1")
        self.assertTrue(ip_obj.ip.is_loopback)

        ip_obj,null,null = parse_ip_and_mask("169.254.1.1")
        self.assertTrue(ip_obj.ip.is_link_local)

        ip_obj,null,null = parse_ip_and_mask("224.0.0.1")
        self.assertTrue(ip_obj.ip.is_multicast)


    # Testy błędnych formatów
    def test_empty_input(self):
        with self.assertRaises(ValueError):
            parse_ip_and_mask("")
        with self.assertRaises(ValueError):
            parse_ip_and_mask(" ")

    def test_incomplete_input(self):
        with self.assertRaises(ValueError):
            parse_ip_and_mask("192.168.1.1/")
        with self.assertRaises(ValueError):
            parse_ip_and_mask("192.168.1.1/33")  # Niepoprawny CIDR
        with self.assertRaises(ValueError):
            parse_ip_and_mask("::1/129")  # CIDR powyżej 128 dla IPv6

if __name__ == "__main__":
    unittest.main(verbosity=2)
