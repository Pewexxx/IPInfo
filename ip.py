import ipaddress
import argparse

# Predefiniowane sieci specjalne
special_networks = [
    ("Loopback", lambda ip: ip.is_loopback),
    ("Test-Net (192.0.2.0/24)", lambda ip: ip in ipaddress.IPv4Network("192.0.2.0/24")),
    ("Test-Net (198.51.100.0/24)", lambda ip: ip in ipaddress.IPv4Network("198.51.100.0/24")),
    ("Test-Net (203.0.113.0/24)", lambda ip: ip in ipaddress.IPv4Network("203.0.113.0/24")),
    ("Zarezerwowany (240.0.0.0/4)", lambda ip: ip in ipaddress.IPv4Network("240.0.0.0/4")),
    ("Documentation (2001:db8::/32)", lambda ip: ip in ipaddress.IPv6Network("2001:db8::/32")),
    ("Multicast", lambda ip: ip.is_multicast),
    ("APIPA (Link-local)", lambda ip: ip.is_link_local),
    ("Zarezerwowany (Reserved)", lambda ip: ip.is_reserved),
    ("Nieokreślony (Unspecified)", lambda ip: ip.is_unspecified),
    ("Prywatny (RFC1918)", lambda ip: ip.is_private),
]

# Predefiniowane kolory
COLORS = {
    "header": "\033[1;92m",   # Zielony pogrubiony
    "key": "\033[1;96m",      # Cyan pogrubiony
    "accent": "\033[1;93m",   # Żółty pogrubiony
    "error": "\033[1;91m",    # Czerwony pogrubiony
    "reset": "\033[0m"
}


def format_text(text, color="reset"): # Funkcja formatująca tekst wyjściowy
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def get_classful_mask(ip):
    """Zwraca domyślną maskę sieci i klasę adresu."""
    first_octet = int(ip.split('.')[0])

    if 1 <= first_octet <= 127:   # Klasa A
        is_private = ipaddress.IPv4Address(ip).is_private
        return "255.0.0.0", "Klasa A", is_private

    elif 128 <= first_octet <= 191:  # Klasa B
        is_private = ipaddress.IPv4Address(ip).is_private
        return "255.255.0.0", "Klasa B", is_private

    elif 192 <= first_octet <= 223:  # Klasa C
        is_private = ipaddress.IPv4Address(ip).is_private
        return "255.255.255.0", "Klasa C", is_private

    elif 224 <= first_octet <= 239:  # Klasa D (Multicast)
        return None, "Klasa D (Multicast - Brak maski)", False

    elif 240 <= first_octet <= 255:  # Klasa E (Eksperymentalne)
        return None, "Klasa E (Zarezerwowana - Brak maski)", False

    else:
        raise ValueError(f"Adres IP {ip} nie należy do standardowych klas.")


def validate_netmask(mask):  # Sprawdzenie poprawności maski sieci
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        return network.prefixlen
    except ValueError:
        raise ValueError(f"Nieprawidłowa maska sieci: {mask}")


def convert_to_cidr(network_str): # Konwersja IP + maska dziesiętna na CIDR
    try:
        ip, mask = network_str.split()
        prefixlen = validate_netmask(mask)
        return f"{ip}/{prefixlen}"
    except (ValueError, IndexError):
        raise ValueError(f"Nieprawidłowa sieć lub maska: {network_str}")


def parse_ip_and_mask(ip, mask=None):
    try:
        if mask and mask.startswith("/"):  # CIDR po spacji
            prefixlen = int(mask[1:])
            ip_obj = ipaddress.ip_interface(f"{ip}/{prefixlen}")
            ip_class = "Brak"
            is_private = ip_obj.ip.is_private
            return ip_obj, ip_class, is_private

        if mask is None:
            if "/" in ip:  # CIDR bez spacji
                ip_obj = ipaddress.ip_interface(ip.replace(" ", ""))
                ip_class = "Brak"
                is_private = ip_obj.ip.is_private
                return ip_obj, ip_class, is_private
            elif ":" not in ip:  # IPv4 bez maski
                mask, ip_class, is_private = get_classful_mask(ip)
                ip_obj = ipaddress.ip_interface(f"{ip}/{mask}")
                return ip_obj, ip_class, is_private
            else:
                raise ValueError("Adres IPv6 wymaga prefiksu CIDR(np. 2001:db8::1/64).")

        # Obsługa maski dziesiętnej
        prefixlen = validate_netmask(mask)
        ip_obj = ipaddress.ip_interface(f"{ip}/{prefixlen}")
        ip_class = "Brak"
        is_private = ip_obj.ip.is_private
        return ip_obj, ip_class, is_private

    except ipaddress.AddressValueError as e:
        raise ValueError(f"Nieprawidłowy adres IP: {e}")
    except ipaddress.NetmaskValueError as e:
        raise ValueError(f"Nieprawidłowa maska sieci: {e}")
    except ValueError as e:
        raise ValueError(f"Ogólny błąd: {e}")


def check_special_address(ip_obj):  # Sprawdzenie, czy adres należy do specjalnych kategorii
    ip = ip_obj.ip

    # Dopasowanie kategorii sieci
    for category, condition in special_networks:
        if condition(ip):
            return category

    return "Brak specjalnej kategorii"


def ip_info(ip_obj, ip_class, is_private):
    ip_version = ip_obj.version
    ip_address = ip_obj.ip

    netmask = str(ip_obj.network.netmask) if ip_version == 4 else f"/{ip_obj.network.prefixlen}"
    network_address = ip_obj.network.network_address if ip_version == 4 else "N/A [IPv6]"
    broadcast_address = ip_obj.network.broadcast_address if ip_version == 4 else "N/A [IPv6]"

    if ip_obj.network.prefixlen == ip_obj.network.max_prefixlen:
        num_hosts = "N/A"
    else:
        num_hosts = ip_obj.network.num_addresses - (2 if ip_version == 4 else 0)

    num_addresses = ip_obj.network.num_addresses
    hex_representation = hex(int(ip_address)) if ip_version == 4 else ip_address.exploded

    private_status = "Tak" if is_private else "Nie"

    print(format_text(f"============ Informacje o adresie {ip_address} ============", "header"))

    info_list = [
        ("Klasa adresu:", ip_class),
        ("Adres prywatny:", private_status),
        ("Typ adresu:", f"IPv{ip_version}"),
        ("Maska sieci:", netmask),
        ("Adres sieci:", network_address),
        ("Adres rozgłoszeniowy:", broadcast_address),
        ("Liczba hostów w sieci:", num_hosts),
        ("Liczba adresów w sieci:", num_addresses),
        ("Reprezentacja binarna:", ''.join(f'{int(octet):08b}' for octet in ip_address.packed)),
        ("Reprezentacja szesnastkowa:", hex_representation),
        ("Kategoria adresu:", check_special_address(ip_obj)),
    ]

    for key, value in info_list:
        print(f"{format_text(key.ljust(27), 'key')} {value}")

    print(format_text("==========================================================", "header"))


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Podręczne narzędzie sieciowe - sprawdzanie adresów IP i przynależności do sieci.\n"
            "Użycie: <ADRES IP SPRAWDZANY> <ADRES DOCELOWY/CIDR> lub <ADRES DOCELOWY> <MASKA>"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Argument IP
    parser.add_argument(
        "ip",
        help=(
            "Adres IP w jednym z formatów:\n"
            "  • CIDR:                  192.168.1.1/24\n"
            "  • IP + maska dziesiętna: 192.168.1.1 255.255.255.0"
        ),
        nargs='+'
    )

    # Argument -n / --network
    parser.add_argument(
        "-n", "--network",
        nargs="+",
        metavar=("ADRES", "MASKA"),
        help=(
            "Sprawdź przynależność podanego adresu IP do danej sieci:\n"
            "\n"
            "Sieć docelową można określić za pomocą:\n"
            "  • CIDR:               192.168.1.0/24\n"
            "  • ADRES + MASKA:      192.168.1.0 255.255.255.0\n"
            "\n"
            "Przykłady użycia:\n"
            "  python ip.py 192.168.1.100 -n 192.168.1.0/24\n"
            "  python ip.py 192.168.1.100 -n 192.168.1.0 255.255.255.0\n"
            "\n"
            "Jeśli adres sieci jest nieprawidłowy, zgłoszony zostanie błąd."
        )
    )

    args = parser.parse_args()
    args.ip = [ip.strip() for ip in args.ip]

    try:
        # Rozpoznanie formatu wejściowego
        if len(args.ip) == 1:
            ip_obj, ip_class, is_private = parse_ip_and_mask(args.ip[0])  # CIDR lub classful
        elif len(args.ip) == 2:
            ip_obj, ip_class, is_private = parse_ip_and_mask(args.ip[0], args.ip[1])  # IP + maska dziesiętna
        else:
            raise ValueError("Nieprawidłowy format wejściowy. Podaj adres w formacie CIDR lub z maską dziesiętną.")

        # Sprawdzanie przynależności do sieci
        if args.network:
            try:
                # Przechowujemy oryginalny format wejściowy
                original_network_format = " ".join(args.network)

                # Obsługa CIDR lub maski dziesiętnej
                if len(args.network) == 2:
                    network_cidr = convert_to_cidr(original_network_format)
                elif len(args.network) == 1:
                    network_cidr = args.network[0]
                else:
                    raise ValueError(f"Nieprawidłowa sieć: {original_network_format}")

                # Sprawdzenie przynależności do sieci
                network = ipaddress.ip_network(network_cidr, strict=False)

                # Wyświetlenie wyniku w oryginalnym formacie
                if ip_obj.ip in network:
                    print("Adres IP " +
                          format_text(f"{ip_obj.ip} ", "accent") +
                          format_text("należy", "header") +
                          " do sieci " +
                          format_text(f"{original_network_format}", "accent"))
                else:
                    print("Adres IP " +
                          format_text(f"{ip_obj.ip} ", "accent") +
                          format_text("NIE należy", "error") +
                          " do sieci " +
                          format_text(f"{original_network_format}", "accent"))
            except ValueError as e:
                print(format_text(f"Nieprawidłowa sieć: {original_network_format} ({e})", "error"))
        else:
            ip_info(ip_obj, ip_class, is_private)  # Wyświetlenie informacji o adresie IP

    except ValueError as e:
        print(f"Błąd: {e}")


if __name__ == "__main__":
    main()