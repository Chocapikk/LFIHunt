from rich.console import Console
from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.history import InMemoryHistory

from core.LFIChecker import LFIChecker
from core.DataChecker import DataChecker
from core.EnvironChecker import EnvironChecker
from core.PHPFilterChecker import PHPFilterChecker
from core.PHPInputExploiter import PHPInputExploiter
from core.PHPPearCmdChecker import PHPPearCmdChecker
from core.PHPFilterChainGenerator import PHPFilterChainGenerator

console = Console()

class Module:
    def __init__(self, url, checker_class, check_method, action):
        self.url = url
        self.checker_class = checker_class
        self.check_method = check_method
        self.action = action
        self.checker = self.checker_class(self.url, silent=False)

    def update_url(self, new_url):
        self.url = new_url
        self.checker = self.checker_class(self.url, silent=False)


    def run(self):
        result, param_name = getattr(self.checker, self.check_method)()
        console.print(f"[bold white]LFI detected ([magenta][/bold white]{self.checker.__class__.__name__}[/magenta][bold white]):[/bold white] {result}")
        
        if result == True and self.action:
            choice = console.input(f"[bold yellow]Select an action (1: [green]{self.action}[/green], 2: [red]Skip[/red]): ")
            if choice == "1":
                if self.action == "Run shell":
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

    url_session = PromptSession(history=InMemoryHistory())
    cmd_session = PromptSession(history=InMemoryHistory())

    url = url_session.prompt(HTML('<b><ansiyellow>Enter site URL to test: </ansiyellow></b>'))

    modules = [
        Module(url, PHPInputExploiter, "filter_check", "Run shell"),
        Module(url, PHPFilterChainGenerator, "filter_check", "Run shell"),
        Module(url, DataChecker, "data_check", "Run shell"),
        Module(url, PHPFilterChecker, "filter_check", "Exploit file"),
        Module(url, EnvironChecker, "environ_check", "Run shell"),
        Module(url, PHPPearCmdChecker, "pearcmd_check", "Run shell"),
        Module(url, LFIChecker, "path_traversal_checker", None)
    ]

    while True:
        try:
            console.print("\n[bold yellow]Select a module to run:[/bold yellow]")
            for i, module in enumerate(modules, 1):
                console.print(f"[bold cyan]{i}[/bold cyan]: [bold green]{module.checker.__class__.__name__}[/bold green]")
            
            console.print(f"[bold cyan]{len(modules) + 1}[/bold cyan]: [bold green]Change URL[/bold green]")

            while True:
                choice = cmd_session.prompt(HTML('<b><ansired>></ansired><ansiyellow>></ansiyellow><ansigreen>></ansigreen></b> '))
                if choice.isdigit():
                    if 1 <= int(choice) <= len(modules):
                        modules[int(choice) - 1].run()
                        break
                    elif int(choice) == len(modules) + 1:
                        url = url_session.prompt(HTML('<b><ansiyellow>Enter new site URL to test: </ansiyellow></b>'))
                        for module in modules:
                            module.update_url(url)
                        break
                    else:
                        console.print("[bold red]Invalid Option[/bold red]")
                elif choice == "":
                    continue
                else:
                    console.print("[bold red]Invalid Option[/bold red]")

        except KeyboardInterrupt:
            console.print("\n[bold yellow]Bye Bye H4x0R !!![/bold yellow]") 
            break 
 

if __name__ == '__main__':
    main()
