"""Subprocess orchestration with a live TUI view.

Every command runs inside a rich Live panel that shows:
  * an animated spinner + phase title + elapsed time
  * the tool's stdout/stderr streaming in real time (tail window)
  * final status on completion

While a *parallel* stage runs, all tools stream at once in a split-screen
view — every command gets its own panel ("agent"). Press 1-9 to focus a
panel directly, Tab / ↓ / → / n to cycle focus forward, ↑ / ← to cycle
back, Home/End to jump to the first/last panel: the focused tool is
enlarged and shows more of its stream, the others stay compact and keep
updating. `q`/`Esc` quits the view for the current stage and falls back
to plain status lines.

All output is also captured to per-phase log files when a ``log_dir`` is
configured (default: off — see ``output.save_tool_logs``). The same class
drives external binaries and bundled python scripts.
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
from rich.layout import Layout
from rich.live import Live
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


# --------------------------------------------------------------------------- #
# Parallel split-screen view
# --------------------------------------------------------------------------- #
class _Stream:
    """Live state of a single tool running inside the parallel view."""

    def __init__(self, title: str, label: str, quiet: bool = False):
        self.title = title
        self.label = label
        self.quiet = quiet
        self.tail: deque = deque(maxlen=TAIL_WINDOW)
        self.done = False
        self.ok = True
        self.elapsed = 0.0
        self.started = time.monotonic()


_CSI_ARROWS = {
    "A": "up", "B": "down", "C": "right", "D": "left",
    "H": "home", "F": "end",
}
_CSI_OTHER = {"1~": "home", "4~": "end"}


class _KeyReader(threading.Thread):
    """Reads keys (raw mode) from stdin into a queue as semantic tokens.

    Printable characters are queued as-is; control sequences are parsed
    into names ("escape", "up", "down", "left", "right", "home", "end",
    "tab"). Escape sequences are consumed whole, so an arrow key never
    produces a stray "escape" token (which would quit the view).
    """

    def __init__(self, keys: "queue.Queue[str]", stop: threading.Event):
        super().__init__(daemon=True)
        self.keys = keys
        self.stop = stop

    @staticmethod
    def _read(fd: int, timeout: float) -> Optional[bytes]:
        import select

        r, _, _ = select.select([fd], [], [], timeout)
        if not r:
            return None
        try:
            return os.read(fd, 1)
        except OSError:
            return None

    def run(self) -> None:
        if sys.platform == "win32":
            self._run_windows()
            return
        import termios
        import tty

        fd = sys.stdin.fileno()
        try:
            old = termios.tcgetattr(fd)
        except Exception:  # noqa: BLE001
            return
        try:
            tty.setcbreak(fd)
            while not self.stop.is_set():
                b = self._read(fd, 0.1)
                if not b:
                    continue
                self.keys.put(self._tokenize(b, fd))
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception:  # noqa: BLE001
                pass

    def _tokenize(self, b: bytes, fd: int) -> str:
        if b != b"\x1b":
            return b.decode("utf-8", errors="replace")
        nxt = self._read(fd, 0.05)
        if nxt is None or nxt == b"\x1b":
            return "escape"  # lone ESC (or double-ESC)
        if nxt == b"[":
            first = self._read(fd, 0.05)
            if first is None:
                return "escape"
            ch = first.decode("utf-8", errors="replace")
            if ch in _CSI_ARROWS:
                return _CSI_ARROWS[ch]
            rest = self._read(fd, 0.05)
            seq = ch + (rest or b"").decode("utf-8", errors="replace")
            return _CSI_OTHER.get(seq, "ignore")
        if nxt == b"O":  # SS3 — F-keys and similar
            self._read(fd, 0.05)
            return "ignore"
        return "escape"  # Alt+key etc.

    def _run_windows(self) -> None:
        try:
            import msvcrt
        except Exception:  # noqa: BLE001
            return
        arrows = {"H": "up", "P": "down", "K": "left", "M": "right"}
        while not self.stop.is_set():
            try:
                if not msvcrt.kbhit():
                    time.sleep(0.05)
                    continue
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    ch2 = msvcrt.getwch() if msvcrt.kbhit() else ""
                    self.keys.put(arrows.get(ch2, "ignore"))
                elif ch == "\x1b":
                    self.keys.put("escape")
                else:
                    self.keys.put(ch)
            except Exception:  # noqa: BLE001
                pass


class ParallelView:
    """Split-screen live view of all concurrently running tools.

    Each running command registers a stream via :meth:`add` and pushes its
    stdout/stderr lines via :meth:`update`. A dedicated render thread owns
    a rich ``Live`` and redraws the whole dashboard every refresh tick:
    a header row of tool chips, plus one panel per tool — the focused
    panel is enlarged (and bright) and shows more stream lines, while the
    rest stay compact and keep streaming.

    Keys while the view is up:
      1-9          focus a tool panel
      Tab / ↓ / →  cycle focus to the next tool
      ↑ / ←        cycle focus to the previous tool
      Home / End   jump to the first / last tool
      q / Esc / Ctrl-C  quit the view for this stage (plain lines take over)
    """

    FOCUSED_RATIO = 3
    FOCUSED_LINES = 18
    COMPACT_LINES = 4

    def __init__(self, console: Console, refresh: float = REFRESH_SECONDS):
        self.console = console
        self.refresh = refresh
        self.enabled = bool(console.is_terminal)
        self.active = False
        self._streams: dict = {}
        self._order: list = []
        self._focus = 0
        self._lock = threading.RLock()
        self._dirty = threading.Event()
        self._stop = threading.Event()
        self._live: Optional[Live] = None
        self._thread: Optional[threading.Thread] = None
        self._keys: "queue.Queue[str]" = queue.Queue()
        self._key_thread: Optional[_KeyReader] = None

    # ------------------------------------------------------------------ #
    # stage lifecycle (driven by CommandRunner.parallel_mode)
    # ------------------------------------------------------------------ #
    def begin_stage(self) -> None:
        """Re-arm the view for a new parallel stage."""
        self.active = self.enabled
        if not self.active:
            return
        with self._lock:
            self._stop = threading.Event()
            self._dirty.set()
            self._focus = 0
            self._streams.clear()
            self._order.clear()
            # fresh queue — never replay leftover key bytes from a stage
            # that was quit with q/Esc mid-sequence
            self._keys = queue.Queue()
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        if self._key_thread is None or not self._key_thread.is_alive():
            self._key_thread = _KeyReader(self._keys, self._stop)
            self._key_thread.start()

    def end_stage(self) -> None:
        """Final render of the stage, then stop the view."""
        if not self.active:
            return
        self.active = False
        self._stop.set()
        self._dirty.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        self._live = None
        if self._key_thread:
            self._key_thread.join(timeout=2)
            self._key_thread = None

    # ------------------------------------------------------------------ #
    # stream API (called from runner threads)
    # ------------------------------------------------------------------ #
    def add(self, title: str, label: str, quiet: bool = False) -> str:
        if not self.active:
            return ""
        with self._lock:
            sid = f"{label}-{len(self._order)}"
            self._streams[sid] = _Stream(title, label, quiet)
            self._order.append(sid)
            self._dirty.set()
        return sid

    def update(self, sid: str, line: str) -> None:
        with self._lock:
            s = self._streams.get(sid)
            if s is None:
                return
            s.tail.append(line)
            self._dirty.set()

    def finish(self, sid: str, rc: int, elapsed: float) -> None:
        with self._lock:
            s = self._streams.get(sid)
            if s is None:
                return
            s.done = True
            s.ok = rc == 0
            s.elapsed = elapsed
            self._dirty.set()

    # ------------------------------------------------------------------ #
    # render loop (owns the Live)
    # ------------------------------------------------------------------ #
    def _loop(self) -> None:
        # screen=True: the view renders on the terminal's alternate screen
        # buffer, so it always fills the whole terminal from the top — an
        # inline Live would start below previously printed output and its
        # top would scroll off-screen as the panel grows
        live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=int(1 / self.refresh),
            transient=True,
            vertical_overflow="ellipsis",
        )
        live.start()
        self._live = live
        last_render = time.monotonic()
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                if now - last_render < self.refresh:
                    self._dirty.wait(self.refresh - (now - last_render))
                    self._dirty.clear()
                    continue
                self._process_keys()
                try:
                    live.update(self._render())
                except Exception:  # noqa: BLE001
                    pass
                last_render = time.monotonic()
            self._process_keys()
            try:
                live.update(self._render())
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                live.stop()
            except Exception:  # noqa: BLE001
                pass

    def _process_keys(self) -> None:
        quit_view = False
        while True:
            try:
                ch = self._keys.get_nowait()
            except queue.Empty:
                break
            if ch in ("q", "Q", "escape", "\x03"):
                quit_view = True
                break
            if ch.isdigit():
                idx = int(ch) - 1
                if 0 <= idx < len(self._order):
                    self._focus = idx
                    self._dirty.set()
            elif ch in ("tab", "n", "N", "down", "right"):
                if self._order:
                    self._focus = (self._focus + 1) % len(self._order)
                    self._dirty.set()
            elif ch in ("up", "left"):
                if self._order:
                    self._focus = (self._focus - 1) % len(self._order)
                    self._dirty.set()
            elif ch == "home":
                if self._order:
                    self._focus = 0
                    self._dirty.set()
            elif ch == "end":
                if self._order:
                    self._focus = len(self._order) - 1
                    self._dirty.set()
        if quit_view:
            self.active = False
            self._stop.set()
            self._dirty.set()
            # restore the terminal immediately (cbreak off) so plain status
            # lines work normally for the rest of the stage
            if self._key_thread is not None:
                self._key_thread.join(timeout=1)
                self._key_thread = None

    # ------------------------------------------------------------------ #
    def _render(self) -> Panel:
        with self._lock:
            order = list(self._order)
            streams = [self._streams[sid] for sid in order]
            focus = self._focus if self._focus < len(streams) else 0

        if not streams:
            return Panel(
                Text("starting parallel tools…", style="dim"),
                border_style="cyan",
                title="[bold cyan]Reconk — parallel stage[/bold cyan]",
            )

        header = Text()
        for i, s in enumerate(streams):
            mark = "✔" if s.done and s.ok else "✗" if s.done else "▶"
            chip = f"[{i + 1}]{mark} {s.label}"
            if i == focus:
                header.append(f" {chip} ", style="bold cyan")
            else:
                header.append(f" {chip} ", style="dim")
        header.append(
            "   [q] quit view  [tab/↓/→] next  [↑/←] prev  [home/end] first/last  [1-9] focus",
            style="bold white",
        )

        # Keep the whole renderable inside the terminal height. Rich's inline
        # Live cannot scroll back: whenever the panel grows taller than the
        # terminal, its top scrolls off-screen for good ("started slightly
        # down, the top is not shown"). Panels are measured after every
        # change and their tails shrunk until the total fits.
        total_h = self.console.height or 24
        focus_tail = self.FOCUSED_LINES
        compact_tail = self.COMPACT_LINES

        def build() -> Panel:
            body: list = [header]
            for i, s in enumerate(streams):
                body.append(
                    self._stream_panel(
                        s,
                        focused=(i == focus),
                        tail_lines=focus_tail if i == focus else compact_tail,
                    )
                )
            return Panel(
                Group(*body),
                border_style="cyan",
                title="[bold cyan]Reconk — parallel tools[/bold cyan]",
                subtitle="[dim]press 1-9 to watch a tool's stream[/dim]",
            )

        panel = build()
        for _ in range(6):
            overshoot = len(self.console.render_lines(panel)) - total_h
            if overshoot <= 0:
                break
            if focus_tail > 3:
                focus_tail = max(3, focus_tail - overshoot)
            elif compact_tail > 1:
                compact_tail = max(1, compact_tail - overshoot)
            else:
                break
            panel = build()
        return panel

    def _stream_panel(self, s: _Stream, focused: bool, tail_lines: int) -> Panel:
        if s.done:
            style = "bold green" if s.ok else "bold red"
            head = Text(f"{'✔' if s.ok else '✗'} {s.title}  ({s.elapsed:.1f}s)", style=style)
        else:
            head = Spinner("dots", text=f" {s.title}  {time.monotonic() - s.started:5.1f}s", style="cyan")
        body: list = [head, Text("")]
        style = "bright_black" if focused else "grey37"
        for l in list(s.tail)[-tail_lines:]:
            body.append(Text(l, style=style))
        return Panel(
            Group(*body),
            title=f"[{'bold cyan' if focused else 'dim'}]{s.label}[/{'bold cyan' if focused else 'dim'}]",
            border_style="cyan" if focused else "grey37",
            padding=(0, 1),
        )


# --------------------------------------------------------------------------- #
# Command runner
# --------------------------------------------------------------------------- #
class CommandRunner:
    """Executes commands with a live streaming TUI panel."""

    def __init__(self, console: Console, log_dir: Optional[Path] = None, verbose: bool = False):
        self.console = console
        self.log_dir = log_dir
        self.verbose = verbose
        self.parallel_view = ParallelView(console)
        self._parallel_mode = False

    @property
    def parallel_mode(self) -> bool:
        """True while a parallel stage runs — phases then stream via the
        split-screen view instead of overlapping Live panels."""
        return self._parallel_mode

    @parallel_mode.setter
    def parallel_mode(self, value: bool) -> None:
        self._parallel_mode = value
        if value:
            self.parallel_view.begin_stage()
        else:
            self.parallel_view.end_stage()

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

        if self.verbose:
            self.console.print(f"  [dim]$ {display}[/dim]")

        view_on = self._parallel_mode and self.parallel_view.active
        view_sid = self.parallel_view.add(title, label, quiet) if view_on else ""

        if not quiet and not view_on:
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
            max_tail = max(1, (self.console.height or 24) - 6)
            tail_lines = list(tail)[-max_tail:]
            limit = self.console.height or 24

            def build(lines: list) -> Panel:
                return Panel(
                    Group(head, *[Text(l, style="dim") for l in lines]),
                    title=f"[bold cyan]{title}[/bold cyan]",
                    border_style="cyan",
                    padding=(0, 1),
                    subtitle=f"[dim]{label}[/dim]",
                )

            # cap the panel to the terminal height — a taller panel pushes
            # its own top off-screen (inline Live has no scrollback); drop
            # exactly the overflow (long wrapped lines are measured, too)
            panel = build(tail_lines)
            for _ in range(8):
                overshoot = len(self.console.render_lines(panel)) - limit
                if overshoot <= 0 or not tail_lines:
                    break
                tail_lines = tail_lines[max(1, overshoot):]
                panel = build(tail_lines)
            return panel

        if quiet or self._parallel_mode or view_on:
            live = None
        else:
            # screen=True: full-screen panel on the alternate buffer — it
            # always fills the terminal from the top (an inline panel would
            # start below earlier output and scroll its top off-screen)
            live = Live(
                render("running..."),
                console=self.console,
                refresh_per_second=8,
                transient=True,
                screen=True,
                vertical_overflow="ellipsis",
            )
            live.start()

        # single-panel mode: capture stdin in raw mode so typed keys don't
        # echo into the live region; q/Esc closes the panel early (the
        # command keeps running, plain lines take over)
        keys_q: "queue.Queue[str]" = queue.Queue()
        key_stop = threading.Event()
        key_thread: Optional[_KeyReader] = None
        panel_closed = False
        if live is not None:
            key_thread = _KeyReader(keys_q, key_stop)
            key_thread.start()

        try:
            while True:
                if kill_flag.is_set():
                    break
                if key_thread is not None:
                    while True:
                        try:
                            k = keys_q.get_nowait()
                        except queue.Empty:
                            break
                        if k in ("q", "Q", "escape", "\x03"):
                            panel_closed = True
                            break
                    if panel_closed:
                        live.stop()  # type: ignore[union-attr]
                        live = None
                        key_stop.set()
                        key_thread.join(timeout=1)
                        key_thread = None
                        if not quiet:
                            self.console.print(
                                "  [dim]panel closed — output continues below[/dim]"
                            )
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
                if view_on:
                    self.parallel_view.update(view_sid, line)
                elif live:
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
            if key_thread is not None:
                key_stop.set()
                key_thread.join(timeout=1)
            if live is not None:
                try:
                    live.stop()
                except Exception:  # noqa: BLE001
                    pass
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

        status_printed = False
        if view_on:
            self.parallel_view.finish(view_sid, rc, elapsed)
        elif not quiet and (live is not None or panel_closed):
            # full-screen panel was used — report the result as a plain line
            # (the alternate screen is already restored by the finally)
            if rc == 0:
                self.console.print(f"  [green]✔ {label}[/green] completed in {elapsed:.1f}s")
            else:
                self.console.print(f"  [red]✗ {label}[/red] exited with code {rc}")
            status_printed = True
        elif not quiet and self._parallel_mode and not view_on:
            if rc == 0:
                self.console.print(f"  [green]✔ {label}[/green] completed in {elapsed:.1f}s")
            else:
                self.console.print(f"  [red]✗ {label}[/red] exited with code {rc}")
            status_printed = True

        if check and rc != 0:
            if not quiet and not view_on and not status_printed:
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

        env_full = dict(os.environ)
        if env:
            env_full.update(env)

        view_on = self._parallel_mode and self.parallel_view.active
        view_sid = self.parallel_view.add(title or label, label, quiet) if view_on else ""
        started = time.monotonic()

        if not quiet and not view_on:
            self.console.print(
                f"  [bold cyan]▶ {title or label}[/bold cyan] [dim]« {len(inputs):,} lines[/dim]"
            )

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
            elapsed = time.monotonic() - started
            if view_on:
                self.parallel_view.finish(view_sid, proc.returncode, elapsed)
            if check and proc.returncode != 0:
                if not quiet and not view_on:
                    self.console.print(f"  [red]✗ {label}[/red] exited with code {proc.returncode}")
                raise CommandError(display, proc.returncode, log)
            return out
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - started
            if view_on:
                self.parallel_view.finish(view_sid, -9, elapsed)
            if not quiet and not view_on:
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
