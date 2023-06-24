# LFIHunt 🕵️‍♂️

LFIHunt is a Python tool designed to streamline the process of exploiting Local File Inclusion (LFI) vulnerabilities. It employs a range of techniques to attempt to exploit these vulnerabilities and, if successful, offers automatic shell access or file reading.

Created by: Chocapikk

## 🚀 Getting Started

To install LFIHunt, start by cloning the repository, then install the required dependencies with pip:

```bash
$ git clone https://github.com/Chocapikk/LFIHunt.git
$ cd LFIHunt/
$ pip install -r requirements.txt
```

## 🛠️ Usage

To start LFIHunt, simply run the Python script from the command line:

```bash
$ python LFIHunt.py
```

Once launched, you will see the following prompt:

```
   __    ________                   _
  / /   / __\_   \/\  /\_   _ _ __ | |_
 / /   / _\  / /\/ /_/ / | | | '_ \| __|
/ /___/ / /\/ /_/ __  /| |_| | | | | |_
\____/\/  \____/\/ /_/  \__,_|_| |_|\__|

    Creator: Chocapikk

Enter site URL to test: http://example.com

Select a module to run:
1: PHPInputExploiter
2: PHPFilterChainGenerator
3: DataChecker
4: PHPFilterChecker
5: EnvironChecker
6: PHPPearCmdChecker
7: LFIChecker
8: Change URL
>>>
```

The tool provides several modules, each corresponding to a different LFI exploitation technique:

1. **PHPInputExploiter** - exploits vulnerability using the `php://input` technique.
2. **PHPFilterChainGenerator** - exploits vulnerability using `php://filter` chains.
3. **DataChecker** - exploits vulnerability using the `data://` technique.
4. **PHPFilterChecker** - exploits vulnerability using the `php://filter` technique.
5. **EnvironChecker** - exploits vulnerability using the `/proc/self/environ` technique.
6. **PHPPearCmdChecker** - exploits vulnerability using the PearCmd shell technique.
7. **LFIChecker** - uses a fuzzer to test for various LFI exploitation methods.
8. **Change URL** - allows you to change the site URL to test.

Upon finding a vulnerability, the tool will offer automatic shell access for exploitation or offer file reading.

## ⚠️ Disclaimer

Please note that this tool should be used ethically and responsibly. Do not use this tool on sites for which you do not have explicit permission to test security. The creator and contributors of LFIHunt are not responsible for any misuse or damage caused by this program. Always respect the laws and regulations concerning penetration testing.
