# manual_tests.py - testy ręczne dla ip.py
import os
import subprocess
import sys
import locale

# Funkcja do uruchamiania poleceń i wyświetlania wyników
def run_command(command):
    print(f"\n{'='*60}")
    print(f"Uruchamianie: {' '.join(command)}")
    print('-'*60)
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
    if result.returncode != 0:
        print(f"Błąd:\n{result.stderr.strip()}")
    else:
        print(result.stdout.strip() or "Brak wyjścia")
    print(f"{'='*60}\n")


def main():
    # Ustawienie lokalizacji dla poprawnego wyświetlania polskich znaków
    locale.setlocale(locale.LC_ALL, 'pl_PL.UTF-8')

    # Ścieżka do interpretera Python
    python_exec = sys.executable
    # Ścieżka do ip.py
    ip_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ip.py"))

    # Poprawione testy adresów IP
    run_command([python_exec, ip_script, "192.168.1.100"])
    run_command([python_exec, ip_script, "10.0.0.1"])
    run_command([python_exec, ip_script, "169.254.0.1"])  # APIPA
    run_command([python_exec, ip_script, "127.0.0.1"])    # Loopback
    run_command([python_exec, ip_script, "100.230.8.73/17"])
    run_command([python_exec, ip_script, "74.125.200.100", "255.255.252.0"])
    run_command([python_exec, ip_script, "10.50.0.1/13"])
    run_command([python_exec, ip_script, "192.168.100.10", "255.255.255.248"])

    # Poprawione adresy IPv6
    run_command([python_exec, ip_script, "2001:db8::1/64"])  # IPv6 Documentation Address
    run_command([python_exec, ip_script, "ff02::1/128"])    # IPv6 Multicast
    run_command([python_exec, ip_script, "fe80::1/64"])     # IPv6 Link-Local

    # Testy przynależności do sieci
    run_command([python_exec, ip_script, "192.168.1.100", "-n", "192.168.1.0/24"])
    run_command([python_exec, ip_script, "192.168.1.100", "-n", "10.0.0.0/8"])
    run_command([python_exec, ip_script, "192.168.1.100", "-n", "192.168.1.0", "255.255.255.0"])
    run_command([python_exec, ip_script, "192.168.1.100", "-n", "192.168.0.0", "255.255.0.0"])

    # Testy błędnych adresów
    run_command([python_exec, ip_script, "300.300.300.300"])  # Błędny adres
    run_command([python_exec, ip_script, "192.168.1.100", "-n", "192.168.1.0", "255.300.255.0"])  # Błędna maska
    run_command([python_exec, ip_script, "192.168.1.100", "-n", "100.100.100.300 255.255.265.255"])  # Niepoprawna sieć

if __name__ == "__main__":
    main()
