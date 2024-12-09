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



def validate_netmask(mask):  # Sprawdzenie poprawności maski sieci
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        return network.prefixlen
    except ValueError:
        raise ValueError(f"Nieprawidłowa maska sieci: {mask}")


def parse_ip_and_mask(ip, mask=None):  # Sprawdzenie, czy podano CIDR lub maskę dziesiętną
    try:
        # Jeśli maska zaczyna się od "/", traktujemy ją jako CIDR
        if mask and mask.startswith("/"):
            prefixlen = int(mask[1:])
            if ":" in ip and not (0 <= prefixlen <= 128):  # IPv6
                raise ValueError(f"Nieprawidłowa wartość prefiksu IPv6: {prefixlen}")
            elif "." in ip and not (0 <= prefixlen <= 32):  # IPv4
                raise ValueError(f"Nieprawidłowa wartość prefiksu IPv4: {prefixlen}")
            return ipaddress.ip_interface(f"{ip}/{prefixlen}")

        # Jeśli podano jeden parametr, sprawdzamy, czy jest w formacie CIDR
        if mask is None:
            if "/" in ip:
                ip = ip.replace(" ", "")  # Usunięcie potencjalnych spacji przed CIDR
                return ipaddress.ip_interface(ip)
            else:
                raise ValueError("Brak CIDR lub maski dziesiętnej.")

        # Jeśli podano maskę dziesiętną, konwersja jej na prefix
        prefixlen = validate_netmask(mask)
        return ipaddress.ip_interface(f"{ip}/{prefixlen}")

    except ValueError as e:
        raise ValueError(f"Błąd w przetwarzaniu adresu: {e}")


def check_special_address(ip_obj):  # Sprawdzenie, czy adres należy do specjalnych kategorii
    ip = ip_obj.ip

    # Dopasowanie kategorii sieci
    for category, condition in special_networks:
        if condition(ip):
            return category

    return "Brak specjalnej kategorii"


def ip_info(ip_obj):  # Wyświetlenie informacji o podanym adresie IP
    ip_version = ip_obj.version
    ip_address = ip_obj.ip

    # Prefiks sieci
    netmask = str(ip_obj.network.netmask) if ip_version == 4 else f"/{ip_obj.network.prefixlen}"

    # Obsługa adresu sieci i rozgłoszeniowego
    network_address = ip_obj.network.network_address if ip_version == 4 else "N/A [IPv6]"
    broadcast_address = ip_obj.network.broadcast_address if ip_version == 4 else "N/A [IPv6]"

    # Liczba hostów
    if ip_obj.network.prefixlen == ip_obj.network.max_prefixlen:
        num_hosts = "N/A"  # Prefiks pełny - brak hostów
    else:
        # IPv4: odjęcie adresu sieci i broadcast
        num_hosts = ip_obj.network.num_addresses - (2 if ip_version == 4 else 0)

    # Liczba adresów w sieci
    num_addresses = ip_obj.network.num_addresses

    # Reprezentacja szesnastkowa dla IPv4/IPv6
    hex_representation = hex(int(ip_address)) if ip_version == 4 else ip_address.exploded

    # Wyświetlenie informacji
    print(format_text(f"============ Informacje o adresie {ip_address} ============", "header"))

    # Tworzenie wyjścia jako lista krotek (klucz, wartość)
    info_list = [
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

    # Wydrukowane jako wyrównane w pionie
    for key, value in info_list:
        print(f"{format_text(key.ljust(25), 'key')} {value}")

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
            ip_obj = parse_ip_and_mask(args.ip[0])  # CIDR
        elif len(args.ip) == 2:
            ip_obj = parse_ip_and_mask(args.ip[0], args.ip[1])  # IP + maska dziesiętna lub CIDR z odstępem
        else:
            raise ValueError("Nieprawidłowy format wejściowy. Podaj adres w formacie CIDR lub z maską dziesiętną.")

        if args.network:
            try:
                network = ipaddress.ip_network(args.network, strict=False)
                if ip_obj.ip in network:
                    print(f"Adres IP {ip_obj.ip} należy do sieci {network}")
                else:
                    print(f"Adres IP {ip_obj.ip} NIE należy do sieci {network}")
            except ValueError:
                print(f"Nieprawidłowa sieć: {args.network}")

        ip_info(ip_obj)

    except ValueError as e:
        print(f"Błąd: {e}")


if __name__ == "__main__":
    main()
