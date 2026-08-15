"""Subprocess orchestration with a live TUI view.

Every command runs inside a rich Live panel that shows:
  * an animated spinner + phase title + elapsed time
  * the tool's stdout/stderr streaming in real time (tail window)
  * final status on completion

All output is also captured to per-phase log files. The same class drives
external binaries and bundled python scripts.
"""

from __future__ import annotations

import os
import queue
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console, Group
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

TAIL_WINDOW = 30
REFRESH_SECONDS = 0.12


class CommandError(RuntimeError):
    """Raised when a tool exits non-zero."""

    def __init__(self, cmd: str, code: int, log: Optional[Path] = None):
        super().__init__(f"Command exited with code {code}: {cmd}")
        self.cmd = cmd
        self.code = code
        self.log = log


class ToolNotFound(RuntimeError):
    """Raised when a binary is missing from PATH."""


class CommandRunner:
    """Executes commands with a live streaming TUI panel."""

    def __init__(self, console: Console, log_dir: Optional[Path] = None):
        self.console = console
        self.log_dir = log_dir
        #: set by the pipeline while a parallel stage runs — phases then
        #: stream via plain status lines instead of overlapping Live panels
        self.parallel_mode = False

    # ------------------------------------------------------------------ #
    def _log_path(self, name: str) -> Optional[Path]:
        if not self.log_dir:
            return None
        self.log_dir.mkdir(parents=True, exist_ok=True)
        return self.log_dir / f"{name}.log"

    # ------------------------------------------------------------------ #
    @staticmethod
    def which(binary: str) -> Optional[str]:
        return shutil.which(binary)

    def require(self, binary: str) -> str:
        path = self.which(binary)
        if not path:
            raise ToolNotFound(
                f"Required tool '{binary}' was not found in PATH. "
                f"Install it or check your environment (see README)."
            )
        return path

    # ------------------------------------------------------------------ #
    def run(
        self,
        cmd: Sequence[str],
        *,
        name: Optional[str] = None,
        title: Optional[str] = None,
        check: bool = True,
        timeout: Optional[int] = None,
        quiet: bool = False,
        env: Optional[dict] = None,
    ) -> subprocess.CompletedProcess:
        """Run a command with a live TUI panel.

        Args:
            cmd: command + args as a sequence.
            name: log file name (default: first binary).
            title: panel title (default: `name`).
            check: raise CommandError on non-zero exit.
            timeout: kill after N seconds.
            quiet: no panel, no status line (log only).
        """
        cmd = [str(c) for c in cmd]
        label = name or Path(cmd[0]).name
        title = title or label
        display = " ".join(shlex.quote(c) for c in cmd)
        log = self._log_path(label)

        env_full = dict(os.environ)
        if env:
            env_full.update(env)

        if not quiet:
            self.console.print(f"  [bold cyan]▶ {title}[/bold cyan] [dim]{display[:120]}[/dim]")

        log_fh = None
        if log:
            log_fh = open(log, "w", encoding="utf-8", errors="replace")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env_full,
            text=True,
            errors="replace",
            bufsize=1,
        )

        started = time.monotonic()
        tail: deque = deque(maxlen=TAIL_WINDOW)
        out_lines: list = []
        line_q: "queue.Queue[Optional[str]]" = queue.Queue()
        kill_flag = threading.Event()

        def reader() -> None:
            try:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        line_q.put(line)
            finally:
                line_q.put(None)
                try:
                    proc.wait(timeout=60)
                except Exception:  # noqa: BLE001
                    pass

        threading.Thread(target=reader, daemon=True).start()

        def render(status: str, spinner: str = "dots", animated: bool = True) -> Panel:
            elapsed = time.monotonic() - started
            if animated:
                head = Spinner(spinner, text=f" {status}  {elapsed:5.1f}s", style="cyan")
            else:
                style = "bold green" if status.startswith("✔") else "bold red"
                head = Text(f"{status}  ({elapsed:.1f}s)", style=style)
            body: list = [head]
            for line in tail:
                body.append(Text(line, style="dim"))
            return Panel(
                Group(*body),
                title=f"[bold cyan]{title}[/bold cyan]",
                border_style="cyan",
                padding=(0, 1),
                subtitle=f"[dim]{label}[/dim]",
            )

        from rich.live import Live

        if quiet or self.parallel_mode:
            live = None
        else:
            live = Live(
                render("running..."),
                console=self.console,
                refresh_per_second=8,
                transient=False,
                vertical_overflow="ellipsis",
            )
            live.start()

        try:
            while True:
                if kill_flag.is_set():
                    break
                if timeout and time.monotonic() - started > timeout:
                    proc.kill()
                    try:
                        proc.wait(timeout=10)
                    except Exception:  # noqa: BLE001
                        pass
                    if live:
                        live.update(render(f"✗ timed out after {timeout}s — killed", animated=False))
                    if check:
                        raise CommandError(f"{display} (timeout {timeout}s)", -9, log)
                    return subprocess.CompletedProcess(cmd, -9, "\n".join(out_lines), "")
                try:
                    line = line_q.get(timeout=REFRESH_SECONDS)
                except queue.Empty:
                    if live:
                        live.update(render("running..."))
                    continue
                if line is None:
                    break
                line = line.rstrip("\r\n")
                out_lines.append(line)
                tail.append(line)
                if log_fh:
                    log_fh.write(line + "\n")
                    log_fh.flush()
                if live:
                    live.update(render("running..."))
        except KeyboardInterrupt:
            kill_flag.set()
            proc.kill()
            if live:
                live.update(render("✗ interrupted by user", animated=False))
            if check:
                raise CommandError(f"{display} (interrupted)", 130, log)
            return subprocess.CompletedProcess(cmd, 130, "", "")
        finally:
            if log_fh:
                try:
                    log_fh.close()
                except Exception:  # noqa: BLE001
                    pass

        # drain any remaining output / wait for process
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        # flush remaining queued lines into the log
        if log_fh and log is not None:
            try:
                with open(log, "a", encoding="utf-8", errors="replace") as f:
                    while True:
                        try:
                            line = line_q.get_nowait()
                        except queue.Empty:
                            break
                        if line is not None:
                            f.write(line)
            except Exception:  # noqa: BLE001
                pass

        elapsed = time.monotonic() - started
        rc = proc.returncode

        if live:
            if rc == 0:
                live.update(render(f"✔ completed in {elapsed:.1f}s", animated=False))
            else:
                live.update(render(f"✗ exited with code {rc}", animated=False))
            try:
                live.stop()
            except Exception:  # noqa: BLE001
                pass
        elif not quiet and self.parallel_mode:
            if rc == 0:
                self.console.print(f"  [green]✔ {label}[/green] completed in {elapsed:.1f}s")
            else:
                self.console.print(f"  [red]✗ {label}[/red] exited with code {rc}")

        if check and rc != 0:
            if not quiet:
                self.console.print(f"  [red]✗ {label}[/red] exited with code {rc}")
            raise CommandError(display, rc, log)

        return subprocess.CompletedProcess(cmd, rc, "\n".join(out_lines), "")

    # ------------------------------------------------------------------ #
    def run_pipe(
        self,
        inputs: Sequence[str],
        cmd: Sequence[str],
        *,
        name: Optional[str] = None,
        title: Optional[str] = None,
        check: bool = True,
        timeout: Optional[int] = None,
        quiet: bool = False,
        env: Optional[dict] = None,
    ) -> str:
        """Pipe input text into a command, return its stdout (no panel)."""
        cmd = [str(c) for c in cmd]
        label = name or Path(cmd[0]).name
        display = " ".join(shlex.quote(c) for c in cmd)
        log = self._log_path(label)

        if not quiet:
            self.console.print(
                f"  [bold cyan]▶ {title or label}[/bold cyan] [dim]« {len(inputs):,} lines[/dim]"
            )

        env_full = dict(os.environ)
        if env:
            env_full.update(env)

        try:
            proc = subprocess.run(
                cmd,
                input="\n".join(inputs) + ("\n" if inputs else ""),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                env=env_full,
                text=True,
                errors="replace",
            )
            out = proc.stdout or ""
            if log:
                with open(log, "w", encoding="utf-8", errors="replace") as f:
                    f.write(out)
            if check and proc.returncode != 0:
                if not quiet:
                    self.console.print(f"  [red]✗ {label}[/red] exited with code {proc.returncode}")
                raise CommandError(display, proc.returncode, log)
            return out
        except subprocess.TimeoutExpired:
            if not quiet:
                self.console.print(f"  [yellow]⚠ {label}[/yellow] timed out after {timeout}s")
            if check:
                raise CommandError(f"{display} (timeout {timeout}s)", -9, log)
            return ""

    # ------------------------------------------------------------------ #
    def run_python(
        self,
        script: Path,
        args: Sequence[str],
        *,
        name: Optional[str] = None,
        title: Optional[str] = None,
        check: bool = True,
        timeout: Optional[int] = None,
        quiet: bool = False,
        env: Optional[dict] = None,
    ) -> subprocess.CompletedProcess:
        """Run one of the bundled python tools."""
        if not script.exists():
            raise ToolNotFound(f"Bundled tool script not found: {script}")
        cmd = [sys.executable, str(script), *[str(a) for a in args]]
        return self.run(
            cmd,
            name=name or script.stem,
            title=title,
            check=check,
            timeout=timeout,
            quiet=quiet,
            env=env,
        )
