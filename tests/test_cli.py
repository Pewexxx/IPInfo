import pytest
import sys
from unittest.mock import patch
from ip import main
import re

# Funkcja pomocnicza usuwająca znaki ANSI
def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


# Testy wyjścia funkcji main()
@pytest.mark.parametrize("cli_args, expected_lines", [
    # Testy standardowych adresów IP
    (["192.168.1.100"], [
        "Klasa adresu:               Klasa C",
        "Adres prywatny:             Tak",
        "Typ adresu:                 IPv4"
    ]),
    (["10.0.0.1"], [
        "Klasa adresu:               Klasa A",
        "Adres prywatny:             Tak"
    ]),
    (["127.0.0.1"], [
        "Klasa adresu:               Klasa A",
        "Adres prywatny:             Tak",
        "Kategoria adresu:           Loopback"
    ]),

    # Testy IP z CIDR i maską dziesiętną
    (["100.230.8.73/17"], [
        "Klasa adresu:               Brak",
        "Adres prywatny:             Nie"
    ]),
    (["74.125.200.100", "255.255.252.0"], [
        "Klasa adresu:               Brak",
        "Adres prywatny:             Nie"
    ]),

    # Testy adresów IPv6
    (["2001:db8::1/64"], [
        "Kategoria adresu:           Documentation (2001:db8::/32)"
    ]),
    (["ff02::1/128"], [
        "Kategoria adresu:           Multicast"
    ]),
    (["fe80::1/64"], [
        "Kategoria adresu:           APIPA (Link-local)"
    ]),

    # Testy przynależności do sieci
    (["192.168.1.100", "-n", "192.168.1.0/24"], ["należy do sieci"]),
    (["192.168.1.100", "-n", "10.0.0.0/8"], ["NIE należy do sieci"]),
])
def test_main_output(capsys, cli_args, expected_lines):
    """Testuje różne przypadki wywołania skryptu."""
    with patch.object(sys, 'argv', ["ip.py"] + cli_args):
        main()  # Uruchomienie funkcji głównej

    # Przechwycenie wyjścia i usunięcie znaków ANSI
    captured = capsys.readouterr()
    clean_output = strip_ansi(captured.out)

    # Sprawdzenie, czy wszystkie linie istnieją w wyjściu
    for expected_line in expected_lines:
        assert expected_line in clean_output, f"Brak oczekiwanej linii: {expected_line}"


# Testy dla błędnych adresów IP
@pytest.mark.parametrize("cli_args, expected_error", [
    (["300.300.300.300"], "Błąd: Nieprawidłowy adres IP"),  # Błędny adres
    (["192.168.1.100", "-n", "192.168.1.0", "255.300.255.0"], "Nieprawidłowa sieć"),  # Błędna maska
    (["192.168.1.100", "-n", "100.100.100.300 255.255.265.255"], "Nieprawidłowa sieć"),  # Nieistniejąca sieć
])
def test_main_invalid_input(capsys, cli_args, expected_error):
    """Testuje błędne dane wejściowe."""
    with patch.object(sys, 'argv', ["ip.py"] + cli_args):
        main()  # Uruchomienie funkcji głównej

    # Przechwycenie wyjścia i usunięcie znaków ANSI
    captured = capsys.readouterr()
    clean_output = strip_ansi(captured.out)

    # Sprawdzenie, czy błąd został wypisany
    assert expected_error in clean_output, f"Oczekiwany błąd: {expected_error} nie został znaleziony"
