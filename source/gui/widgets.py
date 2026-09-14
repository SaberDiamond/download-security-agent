import customtkinter as ctk

from source.gui import theme


class CollapsibleSection(ctk.CTkFrame):
    """
    Reusable expandable section.

    The section header is always visible.
    The content can be expanded or collapsed by clicking the header.
    """

    def __init__(
        self,
        parent,
        title: str,
        expanded: bool = False,
        **kwargs,
    ):
        kwargs.setdefault("fg_color", theme.PANEL_BG)
        kwargs.setdefault("corner_radius", theme.CORNER_RADIUS_SM)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("border_color", theme.BORDER)

        super().__init__(parent, **kwargs)

        self._title = title
        self._expanded = expanded

        self.header = ctk.CTkButton(
            self,
            text=self._header_text(),
            anchor="w",
            fg_color="transparent",
            hover_color=theme.HOVER_BG,
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_SECTION_HEADER,
            height=36,
            corner_radius=theme.CORNER_RADIUS_SM,
            command=self._toggle,
        )

        self.header.pack(
            fill="x",
            padx=3,
            pady=3,
        )

        self.content_frame = ctk.CTkFrame(
            self,
            fg_color="transparent",
        )

        if self._expanded:
            self._show()

    def _header_text(self):
        arrow = "▼" if self._expanded else "›"
        return f"  {arrow}   {self._title}"

    def _toggle(self):
        if self._expanded:
            self._hide()
        else:
            self._show()

    def _show(self):
        self._expanded = True

        self.header.configure(
            text=self._header_text()
        )

        self.content_frame.pack(
            fill="x",
            padx=14,
            pady=(0, 12),
        )

    def _hide(self):
        self._expanded = False

        self.header.configure(
            text=self._header_text()
        )

        self.content_frame.pack_forget()


def add_kv_row(
    parent,
    label: str,
    value: str,
    value_fg: str = None,
    wraplength: int = 300,
):
    row = ctk.CTkFrame(
        parent,
        fg_color="transparent",
    )

    row.pack(
        fill="x",
        pady=3,
    )

    label_widget = ctk.CTkLabel(
        row,
        text=label,
        text_color=theme.TEXT_SECONDARY,
        font=theme.FONT_BODY,
        width=105,
        anchor="nw",
        justify="left",
    )

    label_widget.pack(
        side="left",
    )

    value_widget = ctk.CTkLabel(
        row,
        text=value,
        text_color=value_fg or theme.TEXT_PRIMARY,
        font=theme.FONT_BODY,
        anchor="w",
        justify="left",
        wraplength=wraplength,
    )

    value_widget.pack(
        side="left",
        fill="x",
        expand=True,
    )

    return row


def add_bullet_list(
    parent,
    items,
    empty_text: str = None,
):
    if not items:
        if empty_text:
            ctk.CTkLabel(
                parent,
                text=empty_text,
                text_color=theme.TEXT_MUTED,
                font=theme.FONT_BODY,
                anchor="w",
                justify="left",
                wraplength=420,
            ).pack(
                fill="x",
                pady=3,
            )

        return

    for item in items:
        ctk.CTkLabel(
            parent,
            text=f"• {item}",
            text_color=theme.TEXT_PRIMARY,
            font=theme.FONT_BODY,
            anchor="w",
            justify="left",
            wraplength=420,
        ).pack(
            fill="x",
            pady=2,
        )


def risk_dot(
    parent,
    level: str,
    size: int = 10,
):
    colors = theme.risk_colors(level)

    return ctk.CTkLabel(
        parent,
        text="●",
        text_color=colors["accent"],
        font=(theme.FONT_FAMILY, size),
        width=size,
    )