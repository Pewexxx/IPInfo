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
    "header": "\033[1;92m",   # Cyan pogrubiony
    "key": "\033[1;36m",      # Pomarańczowy pogrubiony
    "reset": "\033[0m"
}


# Funkcja formatująca tekst wyjściowy
def format_text(text, color="reset"):
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


def parse_ip_and_mask(ip, mask=None): # Sprawdzenie formatu IP z obsługą klas IPv4 i adresów prywatnych
    try:
        if mask and mask.startswith("/"):  # Gdy podano CIDR po spacji
            prefixlen = int(mask[1:])
            ip_obj = ipaddress.ip_interface(f"{ip}/{prefixlen}")
            ip_class = "CIDR"
            is_private = ip_obj.ip.is_private
            return ip_obj, ip_class, is_private

        if mask is None:
            if "/" in ip:  # Gdy podano CIDR bez spacji
                ip = ip.replace(" ", "")
                ip_obj = ipaddress.ip_interface(ip)
                ip_class = "CIDR"
                is_private = ip_obj.ip.is_private
                return ip_obj, ip_class, is_private
            elif ":" not in ip:  # Gdy podano IPv4 (podejście klasowe)
                mask, ip_class, is_private = get_classful_mask(ip)
                ip_obj = ipaddress.ip_interface(f"{ip}/{mask}")
                return ip_obj, ip_class, is_private
            else:
                raise ValueError("Adres IPv6 wymaga prefiksu CIDR(np. 2001:db8::1/64).") # Gdy podano IPv6 bez prefiksu CIDR

        # Jeśli podano maskę dziesiętną, konwersja na prefiks CIDR
        prefixlen = validate_netmask(mask)
        ip_obj = ipaddress.ip_interface(f"{ip}/{prefixlen}")
        ip_class = "CIDR"
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
    parser = argparse.ArgumentParser(description="Podręczne narzędzie sieciowe.")
    parser.add_argument("ip",
                        help="Adres IP w formacie CIDR (np. 192.168.1.1/24) lub adres z maską dziesiętną (np. 192.168.1.1 255.255.255.0).",
                        nargs='+')
    parser.add_argument("-n", "--network", help="Adres podsieci do sprawdzenia przynależności IP.")

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
                network = ipaddress.ip_network(args.network, strict=False)
                if ip_obj.ip in network:
                    print(f"Adres IP {ip_obj.ip} należy do sieci {network}")
                else:
                    print(f"Adres IP {ip_obj.ip} NIE należy do sieci {network}")
            except ValueError:
                print(f"Nieprawidłowa sieć: {args.network}")

        # Wyświetlenie informacji
        ip_info(ip_obj, ip_class, is_private)

    except ValueError as e:
        print(f"Błąd: {e}")


if __name__ == "__main__":
    main()
