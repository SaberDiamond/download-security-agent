"""
Download Security Agent - GUI application.

This module wires together the existing backend (monitor, processor,
actions) with the presentation layer in this package. It does not
implement any security analysis, URL/WHOIS/DNSBL logic, or file-moving
logic of its own - it only calls the existing backend functions and
displays their results.

Design intent:
    The alert window (source.gui.alert_window.AlertWindow) is the
    primary security experience - it's where risk is explained and
    decisions get made. This module is deliberately a small, secondary
    dashboard: current status, a way to scan a file on demand, and a
    compact activity feed you can use to reopen a past alert. It should
    never compete with the alert window for attention.

Thread safety:
    The file monitor's worker thread calls ``process_file`` off of the
    main thread. GUI widgets must only be touched from the main thread,
    so the worker's callback (``_on_backend_result``) does nothing but
    push the result onto a plain ``queue.Queue``. The main thread polls
    that queue on a Tkinter timer (``root.after``) and only then builds
    any widgets. Manual "Scan File" runs are handled the same way, using
    a background ``threading.Thread`` so the UI never blocks while
    ``process_file`` is running.
"""

import queue
import threading
from pathlib import Path
from datetime import datetime

import customtkinter as ctk
from tkinter import filedialog

from source.gui import theme
from source.gui.alert_window import AlertWindow
from source.monitor.file_monitor import monitor_directory
from source.processor import process_file


DEFAULT_MONITOR_DIR = "samples/test_downloads"

POLL_INTERVAL_MS = 200
MAX_ACTIVITY_ROWS = 6


class DownloadSecurityAgentApp:
    def __init__(
        self,
        root: ctk.CTk,
        monitor_dir: str = DEFAULT_MONITOR_DIR,
    ):
        self.root = root
        self.monitor_dir = monitor_dir

        self._result_queue = queue.Queue()
        self._history = []
        self._open_alerts = []
        self._observer = None

        self._activity_expanded = False
        self._activity_content = None

        self._build_ui()
        self._start_monitor()

        self.root.after(
            POLL_INTERVAL_MS,
            self._poll_results,
        )

    # ------------------------------------------------------------------
    # Main window
    # ------------------------------------------------------------------

    def _build_ui(self):
        self.root.title("Download Security Agent")
        self.root.configure(
            fg_color=theme.APP_BG
        )

        self.root.geometry("500x560")
        self.root.minsize(440, 500)

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self._on_close,
        )

        outer = ctk.CTkFrame(
            self.root,
            fg_color="transparent",
        )

        outer.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=24,
        )

        # --------------------------------------------------------------
        # Header
        # --------------------------------------------------------------

        header = ctk.CTkFrame(
            outer,
            fg_color="transparent",
        )

        header.pack(
            fill="x",
        )

        ctk.CTkLabel(
            header,
            text="Download Security Agent",
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_APP_TITLE,
            anchor="w",
        ).pack(
            side="left",
        )

        self.header_status_dot = ctk.CTkLabel(
            header,
            text="●",
            text_color=theme.STATUS_IDLE,
            font=(theme.FONT_FAMILY, 12),
            width=18,
        )

        self.header_status_dot.pack(
            side="right",
            padx=(0, 2),
        )

        # --------------------------------------------------------------
        # Protection card
        # --------------------------------------------------------------

        protection_card = ctk.CTkFrame(
            outer,
            fg_color=theme.PANEL_BG,
            corner_radius=theme.CORNER_RADIUS,
            border_width=1,
            border_color=theme.BORDER,
        )

        protection_card.pack(
            fill="x",
            pady=(24, 16),
        )

        ctk.CTkLabel(
            protection_card,
            text="PROTECTION",
            text_color=theme.TEXT_MUTED,
            font=theme.FONT_SMALL_BOLD,
            anchor="w",
        ).pack(
            anchor="w",
            padx=18,
            pady=(16, 4),
        )

        status_row = ctk.CTkFrame(
            protection_card,
            fg_color="transparent",
        )

        status_row.pack(
            fill="x",
            padx=18,
        )

        self.status_dot = ctk.CTkLabel(
            status_row,
            text="●",
            text_color=theme.STATUS_IDLE,
            font=(theme.FONT_FAMILY, 15),
            width=20,
        )

        self.status_dot.pack(
            side="left",
        )

        self.status_text = ctk.CTkLabel(
            status_row,
            text="Starting...",
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_STATUS,
            anchor="w",
        )

        self.status_text.pack(
            side="left",
        )

        ctk.CTkLabel(
            protection_card,
            text="Monitoring",
            text_color=theme.TEXT_SECONDARY,
            font=theme.FONT_SMALL,
            anchor="w",
        ).pack(
            anchor="w",
            padx=18,
            pady=(12, 0),
        )

        self.folder_label = ctk.CTkLabel(
            protection_card,
            text="",
            text_color=theme.TEXT_MUTED,
            font=theme.FONT_SMALL,
            anchor="w",
        )

        self.folder_label.pack(
            fill="x",
            padx=18,
            pady=(2, 16),
        )

        # --------------------------------------------------------------
        # Scan button
        # --------------------------------------------------------------

        self.scan_button = ctk.CTkButton(
            outer,
            text="Scan a File",
            fg_color=theme.TEXT_PRIMARY,
            hover_color="#30343b",
            text_color="#ffffff",
            font=theme.FONT_BODY_BOLD,
            height=42,
            corner_radius=theme.CORNER_RADIUS_SM,
            command=self._on_scan_file_clicked,
        )

        self.scan_button.pack(
            fill="x",
            pady=(0, 20),
        )

        # --------------------------------------------------------------
        # Activity
        # --------------------------------------------------------------

        self.activity_section = CollapsibleActivity(
            outer,
            title="RECENT ACTIVITY",
            expanded=False,
            command=self._toggle_activity,
        )

        self.activity_section.pack(
            fill="x",
        )

        self._activity_content = self.activity_section.content_frame

        self._render_empty_activity()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def _set_status(
        self,
        text: str,
        color: str,
    ):
        self.status_dot.configure(
            text_color=color
        )

        self.header_status_dot.configure(
            text_color=color
        )

        self.status_text.configure(
            text=text
        )

    # ------------------------------------------------------------------
    # Monitoring
    # ------------------------------------------------------------------

    def _start_monitor(self):
        monitor_path = Path(
            self.monitor_dir
        )

        try:
            monitor_path.mkdir(
                parents=True,
                exist_ok=True,
            )
        except Exception:
            pass

        self.folder_label.configure(
            text=str(monitor_path)
        )

        try:
            self._observer = monitor_directory(
                self.monitor_dir,
                on_result=self._on_backend_result,
                blocking=False,
            )

            self._set_status(
                "Protection Active",
                theme.STATUS_ACTIVE,
            )

        except (
            FileNotFoundError,
            NotADirectoryError,
        ) as error:
            self._set_status(
                "Monitoring Unavailable",
                theme.STATUS_ERROR,
            )

            self.folder_label.configure(
                text=str(error)
            )

    def _on_backend_result(
        self,
        result: dict,
        file_path: Path,
    ):
        self._result_queue.put(
            (
                result,
                str(file_path),
            )
        )

    def _poll_results(self):
        try:
            while True:
                result, file_path = (
                    self._result_queue.get_nowait()
                )

                self._handle_new_result(
                    result,
                    file_path,
                )

        except queue.Empty:
            pass

        self.root.after(
            POLL_INTERVAL_MS,
            self._poll_results,
        )

    # ------------------------------------------------------------------
    # Manual scanning
    # ------------------------------------------------------------------

    def _on_scan_file_clicked(self):
        selected = filedialog.askopenfilename(
            title="Select a file to scan",
        )

        if not selected:
            return

        filename = Path(selected).name

        self._set_status(
            f"Analyzing {filename}...",
            theme.STATUS_ACTIVE,
        )

        self.scan_button.configure(
            state="disabled",
            text="Analyzing...",
        )

        thread = threading.Thread(
            target=self._scan_file_worker,
            args=(selected,),
            daemon=True,
        )

        thread.start()

    def _scan_file_worker(
        self,
        file_path: str,
    ):
        try:
            result = process_file(
                file_path
            )

        except Exception as error:
            result = {
                "file": {
                    "name": Path(file_path).name,
                    "path": file_path,
                },
                "status": "identification_failed",
                "error": str(error),
                "analysis": None,
                "risk": None,
                "available_actions": [],
                "action": None,
            }

        self._result_queue.put(
            (
                result,
                file_path,
            )
        )

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def _handle_new_result(
        self,
        result: dict,
        file_path: str,
    ):
        self._set_status(
            "Protection Active",
            theme.STATUS_ACTIVE,
        )

        self.scan_button.configure(
            state="normal",
            text="Scan a File",
        )

        self._history.insert(
            0,
            {
                "result": result,
                "file_path": file_path,
                "time": datetime.now(),
            },
        )

        self._refresh_activity()

        self._show_alert(
            result,
            file_path,
        )

    # ------------------------------------------------------------------
    # Activity
    # ------------------------------------------------------------------

    def _toggle_activity(self):
        self._activity_expanded = (
            not self._activity_expanded
        )

        self.activity_section.set_expanded(
            self._activity_expanded
        )

    def _render_empty_activity(self):
        for child in self._activity_content.winfo_children():
            child.destroy()

        ctk.CTkLabel(
            self._activity_content,
            text="No recent activity.",
            text_color=theme.TEXT_MUTED,
            font=theme.FONT_SMALL,
            anchor="w",
        ).pack(
            fill="x",
            pady=8,
        )

    def _refresh_activity(self):
        for child in self._activity_content.winfo_children():
            child.destroy()

        if not self._history:
            self._render_empty_activity()
            return

        for entry in self._history[:MAX_ACTIVITY_ROWS]:
            self._build_activity_row(
                entry
            )

    def _build_activity_row(
        self,
        entry,
    ):
        result = entry["result"]
        file_path = entry["file_path"]
        timestamp = entry["time"]

        file_info = result.get("file") or {}
        name = file_info.get(
            "name",
            Path(file_path).name,
        )

        status = result.get(
            "status"
        )

        risk = result.get("risk") or {}
        level = (
            risk.get("level")
            or "UNKNOWN"
        ).upper()

        if status == "analyzed":
            colors = theme.risk_colors(
                level
            )

            label = level.title()
            dot_color = colors["accent"]

        elif status == "unsupported":
            label = "Unsupported"
            dot_color = theme.STATUS_IDLE

        else:
            label = "Error"
            dot_color = theme.STATUS_ERROR

        row = ctk.CTkFrame(
            self._activity_content,
            fg_color="transparent",
            corner_radius=6,
            cursor="hand2",
        )

        row.pack(
            fill="x",
            pady=2,
        )

        dot = ctk.CTkLabel(
            row,
            text="●",
            text_color=dot_color,
            font=(theme.FONT_FAMILY, 9),
            width=16,
        )

        dot.pack(
            side="left",
            padx=(6, 4),
        )

        info = ctk.CTkFrame(
            row,
            fg_color="transparent",
        )

        info.pack(
            side="left",
            fill="x",
            expand=True,
            pady=5,
        )

        ctk.CTkLabel(
            info,
            text=name,
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_SMALL_BOLD,
            anchor="w",
        ).pack(
            fill="x",
        )

        ctk.CTkLabel(
            info,
            text=self._relative_time(
                timestamp
            ),
            text_color=theme.TEXT_MUTED,
            font=theme.FONT_TINY,
            anchor="w",
        ).pack(
            fill="x",
        )

        ctk.CTkLabel(
            row,
            text=label,
            text_color=dot_color,
            font=theme.FONT_SMALL_BOLD,
        ).pack(
            side="right",
            padx=(4, 10),
        )

        def on_click(_event=None):
            self._show_alert(
                result,
                file_path,
            )

        def on_enter(_event=None):
            row.configure(
                fg_color=theme.HOVER_BG
            )

        def on_leave(_event=None):
            row.configure(
                fg_color="transparent"
            )

        for widget in (
            row,
            dot,
            info,
        ):
            widget.bind(
                "<Button-1>",
                on_click,
            )

            widget.bind(
                "<Enter>",
                on_enter,
            )

            widget.bind(
                "<Leave>",
                on_leave,
            )

        for child in info.winfo_children():
            child.bind(
                "<Button-1>",
                on_click,
            )

    @staticmethod
    def _relative_time(timestamp):
        seconds = (
            datetime.now() - timestamp
        ).total_seconds()

        if seconds < 10:
            return "Just now"

        if seconds < 60:
            return f"{int(seconds)} sec ago"

        minutes = int(seconds / 60)

        if minutes < 60:
            return f"{minutes} min ago"

        hours = int(minutes / 60)

        if hours < 24:
            return f"{hours} hr ago"

        return timestamp.strftime(
            "%b %d, %I:%M %p"
        )

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def _show_alert(
        self,
        result: dict,
        file_path: str,
    ):
        alert = AlertWindow(
            self.root,
            result,
            file_path,
            on_closed=self._on_alert_closed,
            stack_index=len(
                self._open_alerts
            ),
        )

        self._open_alerts.append(
            alert
        )

    def _on_alert_closed(
        self,
        alert,
    ):
        if alert in self._open_alerts:
            self._open_alerts.remove(
                alert
            )

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _on_close(self):
        if self._observer is not None:
            try:
                self._observer.stop()
            except Exception:
                pass

            try:
                self._observer.join(
                    timeout=2
                )
            except Exception:
                pass

        for alert in list(
            self._open_alerts
        ):
            try:
                alert.destroy()
            except Exception:
                pass

        self._open_alerts.clear()

        self.root.destroy()


class CollapsibleActivity(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        title,
        expanded=False,
        command=None,
    ):
        super().__init__(
            parent,
            fg_color=theme.PANEL_BG,
            corner_radius=theme.CORNER_RADIUS,
            border_width=1,
            border_color=theme.BORDER,
        )

        self._expanded = expanded
        self._title = title
        self._command = command

        self.header = ctk.CTkButton(
            self,
            text=self._header_text(),
            anchor="w",
            fg_color="transparent",
            hover_color=theme.HOVER_BG,
            text_color=theme.TEXT_SECONDARY,
            font=theme.FONT_SMALL_BOLD,
            height=40,
            corner_radius=theme.CORNER_RADIUS,
            command=self._toggle,
        )

        self.header.pack(
            fill="x",
            padx=4,
            pady=4,
        )

        self.content_frame = ctk.CTkFrame(
            self,
            fg_color="transparent",
        )

        if expanded:
            self._show()

    def _header_text(self):
        arrow = "▼" if self._expanded else "›"
        return f"{arrow}  {self._title}"

    def _toggle(self):
        if self._command:
            self._command()
        else:
            self.set_expanded(
                not self._expanded
            )

    def set_expanded(self, expanded):
        self._expanded = expanded

        self.header.configure(
            text=self._header_text()
        )

        if self._expanded:
            self._show()
        else:
            self._hide()

    def _show(self):
        self.content_frame.pack(
            fill="x",
            padx=14,
            pady=(0, 12),
        )

    def _hide(self):
        self.content_frame.pack_forget()


def run(
    monitor_dir: str = DEFAULT_MONITOR_DIR,
):
    root = ctk.CTk()

    DownloadSecurityAgentApp(
        root,
        monitor_dir=monitor_dir,
    )

    root.mainloop()


if __name__ == "__main__":
    run()