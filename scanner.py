import argparse
import concurrent.futures

from termcolor import colored
from rich.console import Console
from prompt_toolkit import prompt
from urllib.parse import urlparse
from alive_progress import alive_bar
from core.LFIChecker import LFIChecker
from core.DataChecker import DataChecker
from core.EnvironChecker import EnvironChecker
from prompt_toolkit.formatted_text import HTML
from core.PHPFilterChecker import PHPFilterChecker
from core.PHPInputExploiter import PHPInputExploiter
from core.PHPPearCmdChecker import PHPPearCmdChecker
from core.PHPFilterChainGenerator import PHPFilterChainGenerator

console = Console()

class Module:
    def __init__(self, url, checker_class, check_method, silent=True):
        self.url = url
        self.checker_class = checker_class
        self.check_method = check_method
        self.checker = self.checker_class(self.url, silent=silent)

    def run(self):
        result, param_name = getattr(self.checker, self.check_method)()
        if result == True:
            parsed_url = urlparse(self.url)
            clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            console.print(f"[bold red]Vulnerable URL: [bold white]{clean_url} | [bold yellow]Parameter: {param_name} | [bold green]Checker: {self.checker.__class__.__name__}")
            return f"Vulnerable URL: {self.url} | Parameter: {param_name} | Checker: {self.checker.__class__.__name__}"
        else:
            return None

def banner():
    banner = '''[bold yellow]
   __    ________                   _    
  / /   / __\_   \/\  /\_   _ _ __ | |_ 
 / /   / _\  / /\/ /_/ / | | | '_ \| __|
/ /___/ / /\/ /_/ __  /| |_| | | | | |_ 
\____/\/  \____/\/ /_/  \__,_|_| |_|\__|
                                        
    [cyan]Creator:[/cyan][green] Chocapikk[/green]
    '''
    console.print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="Perform vulnerability scans on a list of URLs.")
    parser.add_argument("-i", "--input", help="Path to the file containing the URLs", required=True)
    parser.add_argument("-o", "--output", help="Path to the output file", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads to use", type=int, default=50)

    args = parser.parse_args()

    urls_file = args.input
    output_file = args.output
    num_threads = args.threads

    with open(urls_file, 'r') as f:
        urls = [url.strip() for url in f.readlines()]

    threaded_classes = [
        PHPInputExploiter,
        PHPFilterChainGenerator,
        DataChecker,
        PHPFilterChecker,
        EnvironChecker
    ]

    non_threaded_classes = [
        PHPPearCmdChecker,
        LFIChecker
    ]

    check_methods = {
        PHPInputExploiter: "filter_check",
        PHPFilterChainGenerator: "filter_check",
        DataChecker: "data_check",
        PHPFilterChecker: "filter_check",
        EnvironChecker: "environ_check",
        PHPPearCmdChecker: "pearcmd_check",
        LFIChecker: "path_traversal_checker"
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        for checker_class in threaded_classes:
            print(colored(f"\nRunning {checker_class.__name__}...", 'green'))
            modules = [Module(url, checker_class, check_methods[checker_class]) for url in urls]
            with alive_bar(len(modules), title=colored(f"Running {checker_class.__name__}", 'green')) as bar:
                future_to_module = {executor.submit(module.run): module for module in modules}
                for future in concurrent.futures.as_completed(future_to_module):
                    result = future.result()
                    bar()
                    if result is not None:
                        with open(output_file, 'a') as f:
                            f.write(result + '\n')

    for checker_class in non_threaded_classes:
        proceed = prompt(HTML(f'<b><ansired>\nRunning {checker_class.__name__} can take a while. Do you want to proceed? </ansired></b>'), default='N')
        if proceed.lower() != 'y':
            continue
        console.print(f"[bold blue]Running {checker_class.__name__}...[/bold blue]")
        for url in urls:
            parsed_url = urlparse(url)
            clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            console.print(f"[bold blue]Scanning URL: {clean_url}[/bold blue]")
            module = Module(url, checker_class, check_methods[checker_class], silent=False)
            result = module.run()
            if result is not None:
                with open(output_file, 'a') as f:
                    f.write(result + '\n')

if __name__ == '__main__':
    main()
