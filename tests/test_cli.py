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
@pytest.mark.parametrize("cli_args, expected_line", [
    (["192.168.1.100"], "Klasa adresu:               Klasa C"),
    (["10.0.0.1"], "Klasa adresu:               Klasa A"),
    (["192.168.1.100", "-n", "192.168.1.0", "255.255.255.0"], "należy do sieci"),
    (["192.168.1.100", "-n", "10.0.0.0/8"], "NIE należy do sieci")
])
def test_main_output(capsys, cli_args, expected_line):
    # Symulowanie argumentów wiersza poleceń
    with patch.object(sys, 'argv', ["ip.py"] + cli_args):
        main()  # Wywołanie funkcji głównej

    # Przechwycenie wyjścia i usunięcie znaków ANSI
    captured = capsys.readouterr()
    clean_output = strip_ansi(captured.out)

    # Sprawdzenie, czy pełna linia istnieje w wyjściu
    assert expected_line in clean_output


# Test dla nieprawidłowego adresu IP
def test_main_invalid_input(capsys):
    # Symulowanie nieprawidłowego adresu IP
    with patch.object(sys, 'argv', ["ip.py", "300.300.300.300"]):
        main()  # Wywołanie funkcji głównej

    # Przechwycenie wyjścia i usunięcie znaków ANSI
    captured = capsys.readouterr()
    clean_output = strip_ansi(captured.out)

    # Sprawdzenie, czy błąd został wypisany
    assert "Błąd: Ogólny błąd" in clean_output
