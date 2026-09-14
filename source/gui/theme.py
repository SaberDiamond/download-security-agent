import customtkinter as ctk


ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


# ------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------

APP_BG = "#f5f6f8"
PANEL_BG = "#ffffff"
PANEL_ALT = "#f8f9fb"
BORDER = "#e2e4e8"

TEXT_PRIMARY = "#17191d"
TEXT_SECONDARY = "#5d6470"
TEXT_MUTED = "#8b919c"

HOVER_BG = "#eef0f3"

STATUS_ACTIVE = "#2e9e4f"
STATUS_IDLE = "#9aa0aa"
STATUS_ERROR = "#d64545"

DANGER = "#d64545"
DANGER_HOVER = "#b93636"

RISK_COLORS = {
    "LOW": {
        "bg": "#eaf6ed",
        "fg": "#237a38",
        "accent": "#2e9e4f",
    },
    "MEDIUM": {
        "bg": "#fff5df",
        "fg": "#956200",
        "accent": "#dfa02d",
    },
    "HIGH": {
        "bg": "#fdeaea",
        "fg": "#a1262b",
        "accent": "#d64545",
    },
    "CRITICAL": {
        "bg": "#f7dddd",
        "fg": "#781616",
        "accent": "#b52222",
    },
    "UNKNOWN": {
        "bg": "#eceef1",
        "fg": "#555b65",
        "accent": "#8b919c",
    },
}


# ------------------------------------------------------------------
# Typography
# ------------------------------------------------------------------

FONT_FAMILY = "Helvetica"
FONT_MONO_FAMILY = "Menlo"

FONT_APP_TITLE = (FONT_FAMILY, 16, "bold")
FONT_PAGE_TITLE = (FONT_FAMILY, 24, "bold")

FONT_STATUS = (FONT_FAMILY, 13, "bold")
FONT_BODY = (FONT_FAMILY, 12)
FONT_BODY_BOLD = (FONT_FAMILY, 12, "bold")
FONT_SMALL = (FONT_FAMILY, 10)
FONT_SMALL_BOLD = (FONT_FAMILY, 10, "bold")
FONT_TINY = (FONT_FAMILY, 9)

FONT_RISK_LEVEL = (FONT_FAMILY, 28, "bold")
FONT_FILENAME = (FONT_FAMILY, 16, "bold")
FONT_SCORE = (FONT_FAMILY, 12)

FONT_SECTION_HEADER = (FONT_FAMILY, 11, "bold")
FONT_MONO = (FONT_MONO_FAMILY, 10)


# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------

CORNER_RADIUS = 12
CORNER_RADIUS_SM = 8


def risk_colors(level: str):
    return RISK_COLORS.get(
        (level or "UNKNOWN").upper(),
        RISK_COLORS["UNKNOWN"],
    )