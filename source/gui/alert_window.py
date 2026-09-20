"""
The primary security alert window.

This is the main surface of the Download Security Agent: the compact
dashboard (source.gui.app) only shows status and lets the user launch
a scan, but the alert window is where the actual security decision
happens, so it is built to be the visually dominant, most detailed
part of the interface.

This module is presentation-only: it receives the structured result
already produced by ``source.processor.process_file`` and the two
existing action functions from ``source.actions.file_actions``. It does
not perform any analysis itself and does not implement its own
filesystem logic.
"""

import customtkinter as ctk
from tkinter import messagebox

from source.gui import theme
from source.gui.widgets import (
    CollapsibleSection,
    add_kv_row,
    add_bullet_list,
)
from source.gui import formatters as fmt_mod
from source.actions.file_actions import (
    allow_file,
    move_to_trash,
)


ALERT_WIDTH = 600
ALERT_HEIGHT = 760
STACK_OFFSET = 28


class AlertWindow(ctk.CTkToplevel):
    def __init__(
        self,
        master,
        result: dict,
        file_path: str,
        on_closed=None,
        stack_index: int = 0,
    ):
        super().__init__(master)

        self.result = result
        self.file_path = file_path
        self.on_closed = on_closed

        file_name = (
            result.get("file") or {}
        ).get(
            "name",
            "Unknown file",
        )

        self.title(
            f"Security Alert - {file_name}"
        )

        self.configure(
            fg_color=theme.APP_BG
        )

        self.minsize(
            500,
            520,
        )

        self.protocol(
            "WM_DELETE_WINDOW",
            self._on_close,
        )

        self._place_window(
            stack_index
        )

        if result.get("status") == "analyzed":
            self._build_analyzed_view()
        else:
            self._build_status_view(
                result.get("status")
            )

        self.after(
            100,
            self._bring_to_front,
        )

    # ------------------------------------------------------------------
    # Window
    # ------------------------------------------------------------------

    def _place_window(
        self,
        stack_index,
    ):
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()

        x = (
            screen_w - ALERT_WIDTH
        ) // 2

        y = (
            screen_h - ALERT_HEIGHT
        ) // 3

        x += stack_index * STACK_OFFSET
        y += stack_index * STACK_OFFSET

        self.geometry(
            f"{ALERT_WIDTH}x{ALERT_HEIGHT}"
            f"+{max(x, 0)}+{max(y, 0)}"
        )

    def _bring_to_front(self):
        try:
            self.lift()
            self.focus_force()
            self.attributes(
                "-topmost",
                True,
            )

            self.after(
                250,
                lambda: self.attributes(
                    "-topmost",
                    False,
                ),
            )

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Analyzed result
    # ------------------------------------------------------------------

    def _build_analyzed_view(self):
        risk = self.result.get(
            "risk"
        ) or {
            "score": None,
            "level": "UNKNOWN",
            "findings": [],
        }

        file_info = (
            self.result.get("file")
            or {}
        )

        analysis = (
            self.result.get("analysis")
            or {}
        )

        level = (
            risk.get("level")
            or "UNKNOWN"
        ).upper()

        colors = theme.risk_colors(
            level
        )

        # --------------------------------------------------------------
        # Risk header
        # --------------------------------------------------------------

        header = ctk.CTkFrame(
            self,
            fg_color=colors["bg"],
            corner_radius=0,
        )

        header.pack(
            fill="x"
        )

        ctk.CTkLabel(
            header,
            text="SECURITY ANALYSIS",
            text_color=theme.TEXT_MUTED,
            font=theme.FONT_SMALL_BOLD,
        ).pack(
            pady=(18, 4)
        )

        ctk.CTkLabel(
            header,
            text=f"{level} RISK",
            text_color=colors["fg"],
            font=theme.FONT_RISK_LEVEL,
        ).pack(
            pady=(0, 2)
        )

        ctk.CTkLabel(
            header,
            text=file_info.get(
                "name",
                "Unknown file",
            ),
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_FILENAME,
            wraplength=520,
        ).pack(
            padx=24,
            pady=(0, 3)
        )

        score = risk.get(
            "score"
        )

        score_text = (
            f"Risk Score: {score}"
            if score is not None
            else "Risk Score: N/A"
        )

        ctk.CTkLabel(
            header,
            text=score_text,
            text_color=theme.TEXT_SECONDARY,
            font=theme.FONT_SCORE,
        ).pack(
            pady=(0, 5)
        )

        ctk.CTkLabel(
            header,
            text=fmt_mod.risk_level_summary(
                level
            ),
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_BODY,
            wraplength=500,
            justify="center",
        ).pack(
            padx=24,
            pady=(0, 18)
        )

        # --------------------------------------------------------------
        # Scrollable details
        # --------------------------------------------------------------

        scrollable = ctk.CTkScrollableFrame(
            self,
            fg_color=theme.APP_BG,
            scrollbar_button_color=theme.BORDER,
            scrollbar_button_hover_color=theme.TEXT_MUTED,
        )

        scrollable.pack(
            fill="both",
            expand=True,
            padx=8,
            pady=(8, 0),
        )

        self._build_why_flagged(
            scrollable,
            risk,
        )

        self._build_file_information(
            scrollable,
            file_info,
        )

        self._build_pdf_analysis(
            scrollable,
            analysis,
        )

        self._build_javascript_analysis(
            scrollable,
            analysis,
        )

        self._build_url_analysis(
            scrollable,
            analysis,
        )

        self._build_embedded_files(
            scrollable,
            analysis,
        )

        # --------------------------------------------------------------
        # Action bar
        # --------------------------------------------------------------

        action_bar = ctk.CTkFrame(
            self,
            fg_color=theme.PANEL_BG,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=0,
        )

        action_bar.pack(
            fill="x",
            pady=(8, 0),
        )

        self._build_action_bar(
            action_bar,
            self.result.get(
                "available_actions"
            ) or [],
        )

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _build_why_flagged(
        self,
        parent,
        risk,
    ):
        section = CollapsibleSection(
            parent,
            "Why was this flagged?",
            expanded=True,
        )

        section.pack(
            fill="x",
            pady=(0, 8),
        )

        add_bullet_list(
            section.content_frame,
            fmt_mod.format_findings(
                risk.get("findings")
            ),
            empty_text=(
                "No specific risk findings "
                "were returned for this file."
            ),
        )

    def _build_file_information(
        self,
        parent,
        file_info,
    ):
        section = CollapsibleSection(
            parent,
            "File Information",
        )

        section.pack(
            fill="x",
            pady=(0, 8),
        )

        content = section.content_frame

        add_kv_row(
            content,
            "Name",
            fmt_mod.fmt(
                file_info.get("name")
            ),
        )

        add_kv_row(
            content,
            "Path",
            fmt_mod.fmt(
                file_info.get("path")
            ),
            wraplength=350,
        )

        add_kv_row(
            content,
            "Type",
            fmt_mod.fmt(
                file_info.get("type")
            ),
        )

        add_kv_row(
            content,
            "Extension",
            fmt_mod.fmt(
                file_info.get("extension")
            ),
        )

        add_kv_row(
            content,
            "MIME Type",
            fmt_mod.fmt(
                file_info.get("mime_type")
            ),
        )

        add_kv_row(
            content,
            "Size",
            fmt_mod.format_size(
                file_info.get("size")
            ),
        )

        sha256 = file_info.get(
            "sha256"
        )

        row = add_kv_row(
            content,
            "SHA-256",
            fmt_mod.truncate_hash(
                sha256
            ),
            wraplength=250,
        )

        if sha256:
            ctk.CTkButton(
                row,
                text="Copy",
                width=54,
                height=24,
                font=theme.FONT_SMALL,
                fg_color=theme.PANEL_BG,
                hover_color=theme.HOVER_BG,
                text_color=theme.TEXT_SECONDARY,
                border_width=1,
                border_color=theme.BORDER,
                command=lambda: (
                    self._copy_to_clipboard(
                        sha256
                    )
                ),
            ).pack(
                side="right",
                padx=(6, 0),
            )

    def _build_pdf_analysis(
        self,
        parent,
        analysis,
    ):
        if not analysis:
            return

        section = CollapsibleSection(
            parent,
            "PDF Analysis",
        )

        section.pack(
            fill="x",
            pady=(0, 8),
        )

        content = section.content_frame

        add_kv_row(
            content,
            "Pages",
            fmt_mod.fmt(
                analysis.get("pages")
            ),
        )

        add_kv_row(
            content,
            "Encrypted",
            fmt_mod.fmt(
                analysis.get("encrypted")
            ),
        )

        add_kv_row(
            content,
            "JavaScript",
            fmt_mod.fmt(
                analysis.get(
                    "javascript_detected"
                )
            ),
        )

        add_kv_row(
            content,
            "URLs",
            str(
                len(
                    analysis.get(
                        "urls"
                    ) or []
                )
            ),
        )

        add_kv_row(
            content,
            "Embedded Files",
            fmt_mod.fmt(
                analysis.get(
                    "embedded_files_detected"
                )
            ),
        )

        add_kv_row(
            content,
            "Actions",
            fmt_mod.fmt(
                analysis.get(
                    "actions_detected"
                )
            ),
        )

    def _build_javascript_analysis(
        self,
        parent,
        analysis,
    ):
        scripts = (
            analysis.get(
                "javascript_analysis"
            )
            if analysis
            else None
        )

        if not scripts:
            return

        section = CollapsibleSection(
            parent,
            "JavaScript Analysis",
        )

        section.pack(
            fill="x",
            pady=(0, 8),
        )

        content = section.content_frame

        for index, script in enumerate(
            scripts
        ):
            if index:
                ctk.CTkFrame(
                    content,
                    fg_color=theme.BORDER,
                    height=1,
                ).pack(
                    fill="x",
                    pady=10,
                )

            add_kv_row(
                content,
                "Name",
                fmt_mod.fmt(
                    script.get("name")
                ),
            )

            suspicious = (
                script.get(
                    "suspicious"
                )
            )

            add_kv_row(
                content,
                "Suspicious",
                fmt_mod.fmt(
                    suspicious
                ),
                value_fg=(
                    theme.risk_colors(
                        "HIGH"
                    )["fg"]
                    if suspicious
                    else None
                ),
            )

            ctk.CTkLabel(
                content,
                text="Findings",
                text_color=theme.TEXT_SECONDARY,
                font=theme.FONT_BODY_BOLD,
                anchor="w",
            ).pack(
                fill="x",
                pady=(5, 2),
            )

            add_bullet_list(
                content,
                script.get(
                    "findings"
                ) or [],
                empty_text=(
                    "No specific indicators "
                    "were reported."
                ),
            )

    def _build_url_analysis(
        self,
        parent,
        analysis,
    ):
        url_analysis = (
            analysis.get(
                "url_analysis"
            )
            if analysis
            else None
        )

        if not url_analysis:
            return

        assessments = (
            analysis.get(
                "url_assessment"
            )
            or []
        )

        assessment_by_url = {
            item.get("url"): item
            for item in assessments
        }

        section = CollapsibleSection(
            parent,
            "URL Analysis",
        )

        section.pack(
            fill="x",
            pady=(0, 8),
        )

        content = section.content_frame

        for index, url_result in enumerate(
            url_analysis
        ):
            if index:
                ctk.CTkFrame(
                    content,
                    fg_color=theme.BORDER,
                    height=1,
                ).pack(
                    fill="x",
                    pady=10,
                )

            url = url_result.get(
                "url"
            )

            ctk.CTkLabel(
                content,
                text=fmt_mod.fmt(url),
                text_color=theme.TEXT_PRIMARY,
                font=theme.FONT_BODY_BOLD,
                wraplength=460,
                justify="left",
                anchor="w",
            ).pack(
                fill="x",
                pady=(0, 5),
            )

            if url_result.get("error"):
                add_kv_row(
                    content,
                    "Error",
                    str(
                        url_result[
                            "error"
                        ]
                    ),
                )

                continue

            add_kv_row(
                content,
                "Domain",
                fmt_mod.fmt(
                    url_result.get(
                        "domain"
                    )
                ),
            )

            ips = (
                url_result.get(
                    "ip_addresses"
                )
                or []
            )

            add_kv_row(
                content,
                "IP Addresses",
                ", ".join(ips)
                if ips
                else fmt_mod.PLACEHOLDER,
                wraplength=340,
            )

            self._build_domain_reputation(
                content,
                url_result.get(
                    "whois"
                ),
            )

            self._build_dnsbl(
                content,
                url_result.get(
                    "dnsbl"
                ),
            )

            assessment = (
                assessment_by_url.get(
                    url
                )
            )

            if assessment:
                self._build_url_assessment(
                    content,
                    assessment,
                )

    def _build_domain_reputation(
        self,
        parent,
        whois,
    ):
        section = CollapsibleSection(
            parent,
            "Domain Reputation",
        )

        section.pack(
            fill="x",
            pady=(5, 5),
        )

        content = section.content_frame

        info = fmt_mod.format_whois(
            whois
        )

        if info["unavailable_reason"]:
            ctk.CTkLabel(
                content,
                text=info[
                    "unavailable_reason"
                ],
                text_color=theme.TEXT_MUTED,
                font=theme.FONT_SMALL,
                wraplength=420,
                justify="left",
                anchor="w",
            ).pack(
                fill="x"
            )

            return

        add_kv_row(
            content,
            "Registrar",
            info["registrar"],
        )

        add_kv_row(
            content,
            "Created",
            info["created"],
        )

        add_kv_row(
            content,
            "Expires",
            info["expires"],
        )

        add_kv_row(
            content,
            "Domain Age",
            info["age"],
        )

    def _build_dnsbl(
        self,
        parent,
        dnsbl_results,
    ):
        section = CollapsibleSection(
            parent,
            "DNSBL",
        )

        section.pack(
            fill="x",
            pady=(5, 5),
        )

        content = section.content_frame

        rows = fmt_mod.format_dnsbl_rows(
            dnsbl_results
        )

        if not rows:
            ctk.CTkLabel(
                content,
                text="No DNSBL results were available.",
                text_color=theme.TEXT_MUTED,
                font=theme.FONT_SMALL,
                anchor="w",
            ).pack(
                fill="x"
            )

            return

        for ip, status, listed in rows:
            status_color = (
                theme.risk_colors(
                    "HIGH"
                )["fg"]
                if listed
                else theme.TEXT_PRIMARY
            )

            add_kv_row(
                content,
                ip,
                status,
                value_fg=status_color,
            )

    def _build_url_assessment(
        self,
        parent,
        assessment,
    ):
        section = CollapsibleSection(
            parent,
            "URL Assessment",
        )

        section.pack(
            fill="x",
            pady=(5, 5),
        )

        content = section.content_frame

        verdict = (
            assessment.get(
                "verdict"
            )
        )

        verdict_colors = {
            "LOW_RISK": theme.risk_colors(
                "LOW"
            )["fg"],
            "CAUTION": theme.risk_colors(
                "MEDIUM"
            )["fg"],
            "SUSPICIOUS": theme.risk_colors(
                "HIGH"
            )["fg"],
        }

        add_kv_row(
            content,
            "Verdict",
            fmt_mod.verdict_label(
                verdict
            ),
            value_fg=verdict_colors.get(
                (
                    verdict
                    or ""
                ).upper(),
                theme.TEXT_PRIMARY,
            ),
        )

        assessment_text = assessment.get(
            "assessment"
        )

        if assessment_text:
            add_kv_row(
                content,
                "Assessment",
                str(
                    assessment_text
                ),
                wraplength=340,
            )

        ctk.CTkLabel(
            content,
            text="Findings",
            text_color=theme.TEXT_SECONDARY,
            font=theme.FONT_BODY_BOLD,
            anchor="w",
        ).pack(
            fill="x",
            pady=(5, 2),
        )

        add_bullet_list(
            content,
            assessment.get(
                "findings"
            ) or [],
            empty_text=(
                "No specific concerns "
                "were identified."
            ),
        )

    def _build_embedded_files(
        self,
        parent,
        analysis,
    ):
        embedded = (
            analysis.get(
                "embedded_file_analysis"
            )
            if analysis
            else None
        )

        if not embedded:
            return

        section = CollapsibleSection(
            parent,
            "Embedded Files",
        )

        section.pack(
            fill="x",
            pady=(0, 8),
        )

        content = section.content_frame

        for index, item in enumerate(
            embedded
        ):
            if index:
                ctk.CTkFrame(
                    content,
                    fg_color=theme.BORDER,
                    height=1,
                ).pack(
                    fill="x",
                    pady=10,
                )

            classification = (
                item.get(
                    "classification"
                )
                or ""
            ).lower()

            concerning = classification in (
                "executable",
                "script",
                "suspicious",
            )

            ctk.CTkLabel(
                content,
                text=fmt_mod.fmt(
                    item.get(
                        "filename"
                    )
                ),
                text_color=theme.TEXT_PRIMARY,
                font=theme.FONT_BODY_BOLD,
                anchor="w",
            ).pack(
                fill="x",
                pady=(0, 5),
            )

            add_kv_row(
                content,
                "Extension",
                fmt_mod.fmt(
                    item.get(
                        "extension"
                    )
                ),
            )

            add_kv_row(
                content,
                "MIME Type",
                fmt_mod.fmt(
                    item.get(
                        "mime_type"
                    )
                ),
            )

            add_kv_row(
                content,
                "Size",
                fmt_mod.format_size(
                    item.get(
                        "size"
                    )
                ),
            )

            add_kv_row(
                content,
                "SHA-256",
                fmt_mod.truncate_hash(
                    item.get(
                        "sha256"
                    )
                ),
            )

            add_kv_row(
                content,
                "Classification",
                fmt_mod.fmt(
                    item.get(
                        "classification"
                    )
                ),
                value_fg=(
                    theme.risk_colors(
                        "HIGH"
                    )["fg"]
                    if concerning
                    else None
                ),
            )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _build_action_bar(
        self,
        parent,
        available_actions,
    ):
        inner = ctk.CTkFrame(
            parent,
            fg_color="transparent",
        )

        inner.pack(
            fill="x",
            padx=18,
            pady=14,
        )

        if "allow" in available_actions:
            ctk.CTkButton(
                inner,
                text="Keep File",
                fg_color=theme.PANEL_BG,
                hover_color=theme.HOVER_BG,
                text_color=theme.TEXT_PRIMARY,
                border_width=1,
                border_color=theme.BORDER,
                height=40,
                font=theme.FONT_BODY_BOLD,
                command=self._handle_keep,
            ).pack(
                side="left",
                fill="x",
                expand=True,
                padx=(0, 6),
            )

        if "move_to_trash" in available_actions:
            ctk.CTkButton(
                inner,
                text="Move to Trash",
                fg_color=theme.DANGER,
                hover_color=theme.DANGER_HOVER,
                text_color="#ffffff",
                height=40,
                font=theme.FONT_BODY_BOLD,
                command=self._handle_trash,
            ).pack(
                side="left",
                fill="x",
                expand=True,
                padx=(6, 0),
            )

    def _handle_keep(self):
        outcome = allow_file(
            self.file_path
        )

        if outcome.get("success"):
            messagebox.showinfo(
                "File Kept",
                "The file will remain in its original location.",
                parent=self,
            )
        else:
            messagebox.showwarning(
                "Could Not Keep File",
                outcome.get(
                    "error"
                )
                or "The file could not be kept.",
                parent=self,
            )

        self._on_close()

    def _handle_trash(self):
        confirmed = messagebox.askyesno(
            "Move to Trash?",
            "Move this file to Trash?\n\n"
            "The file will be moved out of its current "
            "location and placed in the Download Security "
            "Agent trash folder.",
            parent=self,
        )

        if not confirmed:
            return

        outcome = move_to_trash(
            self.file_path
        )

        if outcome.get("success"):
            messagebox.showinfo(
                "File Moved",
                "The file was moved to Trash.",
                parent=self,
            )
        else:
            messagebox.showwarning(
                "Could Not Move File",
                outcome.get(
                    "error"
                )
                or "The file could not be moved to Trash.",
                parent=self,
            )

        self._on_close()

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _copy_to_clipboard(
        self,
        text,
    ):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()

    def _build_status_view(
        self,
        status,
    ):
        container = ctk.CTkFrame(
            self,
            fg_color=theme.APP_BG,
        )

        container.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=28,
        )

        file_info = (
            self.result.get("file")
            or {}
        )

        status_title = (
            "File Type Mismatch"
            if status == "type_mismatch"
            else fmt_mod.status_title(status)
        )

        ctk.CTkLabel(
            container,
            text=status_title,
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_PAGE_TITLE,
            anchor="w",
        ).pack(
            anchor="w",
            pady=(20, 12),
        )

        ctk.CTkLabel(
            container,
            text=file_info.get(
                "name",
                "Unknown file",
            ),
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_FILENAME,
            anchor="w",
        ).pack(
            anchor="w",
            pady=(0, 12),
        )

        messages = {
            "type_mismatch": (
                "The file extension does not match the "
                "actual file type detected."
            ),
            "unsupported": (
                "This version currently supports "
                "PDF files. This file was not analyzed."
            ),
            "identification_failed": (
                "The file could not be identified."
            ),
            "analysis_failed": (
                "The file was identified, but "
                "security analysis failed."
            ),
            "risk_assessment_failed": (
                "The file was analyzed, but the "
                "risk engine failed. No risk verdict "
                "is available."
            ),
        }

        ctk.CTkLabel(
            container,
            text=messages.get(
                status,
                "The file could not be processed.",
            ),
            text_color=theme.TEXT_SECONDARY,
            font=theme.FONT_BODY,
            wraplength=500,
            justify="left",
            anchor="w",
        ).pack(
            fill="x",
            pady=(0, 18),
        )

        if status == "type_mismatch":
            actual_type = file_info.get(
                "actual_type"
            ) or "Unknown"

            ctk.CTkLabel(
                container,
                text=f"Detected file type: {actual_type}",
                text_color=theme.TEXT_PRIMARY,
                font=theme.FONT_BODY_BOLD,
                anchor="w",
            ).pack(
                fill="x",
                pady=(0, 18),
            )

        error = self.result.get(
            "error"
        )

        if error:
            error_box = ctk.CTkFrame(
                container,
                fg_color=theme.PANEL_BG,
                corner_radius=theme.CORNER_RADIUS_SM,
                border_width=1,
                border_color=theme.BORDER,
            )

            error_box.pack(
                fill="x",
                pady=(0, 18),
            )

            ctk.CTkLabel(
                error_box,
                text=str(error),
                text_color=theme.TEXT_PRIMARY,
                font=theme.FONT_MONO,
                wraplength=460,
                justify="left",
                anchor="w",
            ).pack(
                fill="x",
                padx=14,
                pady=14,
            )

        available_actions = (
            self.result.get(
                "available_actions"
            )
            or []
        )

        if available_actions:
            self._build_action_bar(
                container,
                available_actions,
            )
        else:
            ctk.CTkButton(
                container,
                text="Close",
                fg_color=theme.TEXT_PRIMARY,
                hover_color="#30343b",
                text_color="#ffffff",
                height=40,
                command=self._on_close,
            ).pack(
                anchor="e"
            )

    def _on_close(self):
        if self.on_closed:
            try:
                self.on_closed(
                    self
                )
            except Exception:
                pass

        self.destroy()