"""Dependency-free, stderr-only progress with bounded terminal/log output."""

import contextlib
import logging
import shutil
import sys
import threading
import time


def clean(text):
    # Feed names and DNS answers must not inject terminal control sequences.
    """Remove terminal control characters from untrusted source names and details."""
    return "".join(c if c.isprintable() else " " for c in str(text))


class Progress:
    """Serialize stderr progress and log messages without a third-party UI library.

    Only interactive terminals use a background spinner. Plain logs update
    on work notifications, so quiet blocking operations do not emit heartbeats."""

    def __init__(self, mode="auto", stream=None, interval=0.1, log_interval=5):
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = mode != "off"
        self.animated = self.enabled and mode != "plain" and self.stream.isatty()
        self.interval, self.log_interval = interval, log_interval
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = None
        self.stage = None
        self.frame = 0
        self.last_log = 0
        self.completed = 0
        self.total = None
        self.detail = ""
        self.started = 0
        self.dns_scheduled = 0
        self.dns_completed = 0

    def __enter__(self):
        """Start a daemon that animates while the main thread waits on blocking work."""
        if self.animated:
            self.thread = threading.Thread(
                target=self._spin, daemon=True, name="blocklists-progress"
            )
            self.thread.start()
        return self

    def __exit__(self, typ, value, traceback):
        """Print the final status and stop the animation, including on exceptions."""
        self.finish("failed" if typ else "done")
        self.stop.set()
        if self.thread:
            self.thread.join()

    def _spin(self):
        """Refresh the current stage while holding the same lock used by log output."""
        while not self.stop.wait(self.interval):
            with self.lock:
                if self.stage:
                    self._render()

    def _text(self, status):
        """Format a stage-local count; unknown totals never receive a guessed percentage."""
        count = (
            f"{self.completed:,} completed"
            if self.completed
            else ("complete" if status == "done" else "working")
        )
        if self.total is not None:
            count = f"{self.completed:,}/{self.total:,} completed"
            if self.total:
                count += f" ({100 * self.completed / self.total:.0f}%)"
        elapsed = time.monotonic() - self.started
        dns = (
            f" | DNS {self.dns_completed:,}/{self.dns_scheduled:,} completed"
            if self.dns_scheduled
            else ""
        )
        return f"{status} {self.stage}{dns} | {count} | {elapsed:.1f}s | {self.detail}"

    def _render(self, status=None, final=False):
        """Write one bounded terminal line or one complete plain-text log record."""
        if not self.enabled:
            return
        marker = status or "|/-\\"[self.frame % 4]
        self.frame += 1
        text = clean(self._text(marker))
        if self.animated:
            width = max(1, shutil.get_terminal_size((100, 24)).columns - 1)
            self.stream.write("\r\033[2K" + text[:width] + ("\n" if final else ""))
        else:
            self.stream.write(text + "\n")
        self.stream.flush()
        self.last_log = time.monotonic()

    def start(self, stage, total=None, detail=""):
        """Finish the preceding stage and reset the elapsed clock and item count."""
        with self.lock:
            self.finish()
            self.stage, self.total, self.detail = stage, total, detail
            self.completed, self.started = 0, time.monotonic()
            self._render("start")

    def update(self, detail=None, completed=None, advance=0):
        """Record current work; callers advance only when an item has completed."""
        with self.lock:
            if detail is not None:
                self.detail = detail
            if completed is not None:
                self.completed = completed
            self.completed += advance
            self._render_update()

    def dns_update(self, scheduled=0, completed=0, detail=None):
        """Track DNS work across foreground stages and successive expansion rounds."""
        if not self.enabled:
            return
        with self.lock:
            self.dns_scheduled += scheduled
            self.dns_completed += completed
            if detail and self.stage and self.stage.startswith("[4/7]"):
                self.detail = detail
            self._render_update()

    def _render_update(self):
        if (
            self.stage
            and not self.animated
            and time.monotonic() - self.last_log >= self.log_interval
        ):
            self._render("work")

    def finish(self, status="done"):
        """Close the active stage without inventing completion for unfinished items."""
        with self.lock:
            if self.stage:
                self._render(status, final=True)
                self.stage = None

    @contextlib.contextmanager
    def logging(self, logger):
        """Temporarily route one logger through the display, restoring its configuration."""
        progress = self

        class Handler(logging.Handler):
            def emit(self, record):
                with progress.lock:
                    if progress.animated and progress.stage:
                        progress.stream.write("\r\033[2K")
                    progress.stream.write(clean(self.format(record)) + "\n")
                    progress.stream.flush()
                    if progress.animated and progress.stage:
                        progress._render()

        previous = logger.handlers[:], logger.propagate, logger.level
        handler = Handler()
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.handlers, logger.propagate = [handler], False
        logger.setLevel(logging.INFO)
        try:
            yield
        finally:
            logger.handlers, logger.propagate, level = previous
            logger.setLevel(level)
