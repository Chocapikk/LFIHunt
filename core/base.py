"""Base class for all LFI checkers. Contains shared logic."""

import os
import re

import requests
import urllib3
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Project root for resolving wordlist paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wordlist_path(name):
    """Resolve a wordlist filename to its absolute path."""
    return os.path.join(PROJECT_ROOT, "wordlists", name)


class BaseChecker:
    """Shared functionality for all LFI checker modules."""

    def __init__(self, url, silent=False):
        self.console = Console()
        self.silent = silent
        self.url = self.ensure_correct_protocol(url)

    def ensure_correct_protocol(self, url):
        """Auto-detect http/https if no scheme is provided."""
        if not url.startswith(("http://", "https://")):
            try:
                requests.get("https://" + url, timeout=3, verify=False)
                return "https://" + url
            except requests.exceptions.RequestException:
                try:
                    requests.get("http://" + url, timeout=3, verify=False)
                    return "http://" + url
                except requests.exceptions.RequestException:
                    pass
        return url

    def _safe_get(self, url, **kwargs):
        """Make a GET request, return None on connection errors."""
        kwargs.setdefault("verify", False)
        kwargs.setdefault("timeout", 5)
        try:
            return requests.get(url, **kwargs)
        except requests.exceptions.ConnectionError:
            if not self.silent:
                self.console.print(
                    "[bold red]Request Failed (WAF or down host)...[/bold red]"
                )
            return None
        except requests.exceptions.RequestException:
            if not self.silent:
                self.console.print(
                    "[bold red]Request Timeout Error (WAF or down host)...[/bold red]"
                )
            return None

    def _safe_post(self, url, **kwargs):
        """Make a POST request, return None on connection errors."""
        kwargs.setdefault("verify", False)
        kwargs.setdefault("timeout", 5)
        try:
            return requests.post(url, **kwargs)
        except requests.exceptions.ConnectionError:
            if not self.silent:
                self.console.print(
                    "[bold red]Request Failed (WAF or down host)...[/bold red]"
                )
            return None
        except requests.exceptions.RequestException:
            if not self.silent:
                self.console.print(
                    "[bold red]Request Timeout Error (WAF or down host)...[/bold red]"
                )
            return None

    def run_shell(self, param_name):
        """Interactive shell loop. Subclasses must implement _build_shell_url."""
        raise NotImplementedError("Subclasses must implement _build_shell_url")

    def _interactive_shell(self, param_name, build_url_fn):
        """Generic interactive shell loop.

        build_url_fn(cmd, param_name) -> (url, method, kwargs)
        Returns the fuzzed URL and optional POST data for each command.
        """
        self.console.print(
            "[bold yellow]Interactive shell is ready. Type your commands.[/bold yellow]"
        )

        session = PromptSession(history=InMemoryHistory())
        while True:
            try:
                cmd = session.prompt(HTML("<ansired><b># </b></ansired>"))
                if not cmd:
                    continue
                if cmd.strip().lower() in ("exit", "quit"):
                    raise KeyboardInterrupt
                if cmd.strip().lower() in ("clear", "cls"):
                    os.system("cls" if os.name == "nt" else "clear")
                    continue

                url, method, kwargs = build_url_fn(cmd, param_name)

                if method == "POST":
                    response = self._safe_post(url, **kwargs)
                else:
                    response = self._safe_get(url)

                if response is None:
                    continue

                pattern = re.compile(r"\[S\](.*?)\[E\]", re.DOTALL)
                match = pattern.search(response.text)
                if match and match.group(1):
                    self.console.print(
                        f"[bold green]{match.group(1)}[/bold green]"
                    )
                else:
                    self.console.print("[bold red]No shell output.[/bold red]")

            except KeyboardInterrupt:
                self.console.print(
                    "[bold yellow][!] Exiting shell...[/bold yellow]"
                )
                break
