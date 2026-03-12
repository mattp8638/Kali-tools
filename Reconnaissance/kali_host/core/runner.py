"""
Tool Runner - executes tool modules in background threads, streams output.
Uses Qt signals for real-time output streaming back to the UI.
"""
import sys
import io
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from PyQt5.QtCore import QObject, QThread, pyqtSignal, pyqtSlot

from .models import ToolDefinition, ScanResult, ToolStatus
from .registry import ToolRegistry


class OutputCapture(io.StringIO):
    """Captures stdout/stderr and forwards each line via a callback."""

    def __init__(self, callback: Callable[[str], None]):
        super().__init__()
        self._callback = callback
        self._buffer = ""

    def write(self, text: str) -> int:
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._callback(line)
        return len(text)

    def flush(self):
        if self._buffer:
            self._callback(self._buffer)
            self._buffer = ""


class ToolWorker(QObject):
    """Runs a tool in a background thread."""

    # Signals
    output_line = pyqtSignal(str)          # Real-time output line
    status_changed = pyqtSignal(str)       # Status update
    progress = pyqtSignal(int, int)        # current, total
    finished = pyqtSignal(object)          # ScanResult
    error = pyqtSignal(str)                # Error message

    def __init__(
        self,
        registry: ToolRegistry,
        tool_def: ToolDefinition,
        params: Dict[str, Any],
    ):
        super().__init__()
        self._registry = registry
        self._tool_def = tool_def
        self._params = params
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    @pyqtSlot()
    def run(self):
        """Execute the tool module."""
        result = ScanResult(
            tool_id=self._tool_def.tool_id,
            tool_name=self._tool_def.name,
            params_used=dict(self._params),
            started_at=datetime.now(),
        )

        self.status_changed.emit("running")
        result.status = ToolStatus.RUNNING

        # Capture stdout
        captured_lines = []

        def on_output(line: str):
            captured_lines.append(line)
            self.output_line.emit(line)

        capture = OutputCapture(on_output)
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        try:
            sys.stdout = capture
            sys.stderr = capture

            # Import and run the tool module
            module = self._registry.get_module(self._tool_def.tool_id)
            entry_fn = getattr(module, self._tool_def.entry_function)

            # Call with params + optional callbacks
            tool_result = entry_fn(
                params=self._params,
                on_progress=lambda cur, tot: self.progress.emit(cur, tot),
                on_output=on_output,
                is_cancelled=lambda: self._cancelled,
            )

            capture.flush()

            result.raw_output = "\n".join(captured_lines)
            result.finished_at = datetime.now()

            if self._cancelled:
                result.status = ToolStatus.CANCELLED
                self.status_changed.emit("cancelled")
            else:
                result.status = ToolStatus.COMPLETED
                self.status_changed.emit("completed")
                if isinstance(tool_result, dict):
                    result.structured_data = tool_result

        except Exception as e:
            capture.flush()
            result.raw_output = "\n".join(captured_lines)
            result.error_message = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
            result.status = ToolStatus.FAILED
            result.finished_at = datetime.now()
            self.status_changed.emit("failed")
            self.error.emit(str(e))

        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        self.finished.emit(result)


class ToolRunner:
    """Manages running tools in background threads."""

    def __init__(self, registry: ToolRegistry):
        self._registry = registry
        self._active_workers: Dict[str, tuple] = {}  # result_id -> (thread, worker)

    def run_tool(
        self,
        tool_id: str,
        params: Dict[str, Any],
        on_output: Optional[Callable[[str], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_finished: Optional[Callable[[ScanResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Start a tool run. Returns the result_id for tracking."""
        tool_def = self._registry.get_tool(tool_id)
        if not tool_def:
            raise ValueError(f"Unknown tool: {tool_id}")

        worker = ToolWorker(self._registry, tool_def, params)
        thread = QThread()
        worker.moveToThread(thread)

        # Connect signals
        if on_output:
            worker.output_line.connect(on_output)
        if on_status:
            worker.status_changed.connect(on_status)
        if on_progress:
            worker.progress.connect(on_progress)
        if on_error:
            worker.error.connect(on_error)

        # Create a temporary result to get the ID
        temp_result = ScanResult(tool_id=tool_id, tool_name=tool_def.name)
        result_id = temp_result.result_id

        def handle_finished(result: ScanResult):
            if on_finished:
                on_finished(result)
            # Cleanup
            thread.quit()
            thread.wait()
            self._active_workers.pop(result_id, None)

        worker.finished.connect(handle_finished)
        thread.started.connect(worker.run)
        thread.finished.connect(thread.deleteLater)

        self._active_workers[result_id] = (thread, worker)
        thread.start()

        return result_id

    def cancel(self, result_id: str):
        """Cancel a running tool."""
        if result_id in self._active_workers:
            _, worker = self._active_workers[result_id]
            worker.cancel()

    def cancel_all(self):
        """Cancel all running tools."""
        for result_id in list(self._active_workers.keys()):
            self.cancel(result_id)

    @property
    def active_count(self) -> int:
        return len(self._active_workers)
