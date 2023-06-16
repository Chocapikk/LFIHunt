from rich.console import Console

from core.LFIChecker import LFIChecker
from core.DataChecker import DataChecker
from core.EnvironChecker import EnvironChecker
from core.PHPFilterChecker import PHPFilterChecker
from core.PHPInputExploiter import PHPInputExploiter
from core.PHPFilterChainGenerator import PHPFilterChainGenerator

console = Console()

class Module:
    def __init__(self, url, checker_class, check_method, action):
        self.checker = checker_class(url, silent=False)
        self.check_method = check_method
        self.action = action

    def run(self):
        result, param_name = getattr(self.checker, self.check_method)()
        console.print(f"LFI detected ({self.checker.__class__.__name__}): {result}")
        
        if result == True and self.action:
            choice = console.input(f"[bold yellow]Select an action (1: [green]{self.action}[/green], 2: [red]Skip[/red]): ")
            if choice == "1":
                if self.action == "Run shell" or self.action == "Run web shell":
                    getattr(self.checker, self.action.lower().replace(" ", "_"))(param_name)
                elif self.action == "Exploit file":
                    filename = console.input('Enter filename to display: ')
                    getattr(self.checker, self.action.lower().replace(" ", "_"))(filename, param_name)



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
    url = console.input('[bold yellow]Enter site URL to test: [/bold yellow]')

    modules = [
        Module(url, PHPInputExploiter, "filter_check", "Run shell"),
        Module(url, PHPFilterChainGenerator, "filter_check", "Run shell"),
        Module(url, DataChecker, "data_check", "Run shell"),
        Module(url, PHPFilterChecker, "filter_check", "Exploit file"),
        Module(url, EnvironChecker, "environ_check", "Run web shell"),
        Module(url, LFIChecker, "path_traversal_checker", None)
    ]

    while True:
        try:
            console.print("\n[bold yellow]Select a module to run:[/bold yellow]")
            for i, module in enumerate(modules, 1):
                console.print(f"[bold cyan]{i}[/bold cyan]: [bold green]{module.checker.__class__.__name__}[/bold green]")

            console.print("[bold][red]>[/red][yellow]>[/yellow][green]>[/green] ", end="")
            choice = console.input()
            if choice.isdigit() and 1 <= int(choice) <= len(modules):
                modules[int(choice) - 1].run()
            else:
                break
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Bye Bye H4x0R !!![/bold yellow]") 
            break   

if __name__ == '__main__':
    main()
