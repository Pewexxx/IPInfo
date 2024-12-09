import subprocess
import sys
import pytest


def run_command(command, description):
     result = subprocess.run(command, text=True)

@pytest.mark.order(1)
def test_unittest():
    python_exec = sys.executable
    run_command([python_exec, "-m", "unittest", "discover", "-s", "tests", "-p", "test.py"], "Testy Jednostkowe")


@pytest.mark.order(2)
def test_pytest_cli():
    run_command(["pytest", "tests/test_cli.py"], "Test wyjścia programu")


@pytest.mark.order(3)
def test_manual_tests():
    python_exec = sys.executable
    run_command([python_exec, "tests/manual_tests.py"], "Testy Manualne")
