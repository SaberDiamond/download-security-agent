"""
Entry point for the Download Security Agent GUI.

Run with:

    python -m source.gui_main

This starts the same file monitor and backend pipeline used by the
terminal interface (source/main.py), but routes results into a
graphical alert window instead of printing them to the terminal.
The terminal interface continues to work independently; this module
does not modify it.
"""

from source.gui.app import run


def main():
    run()


if __name__ == "__main__":
    main()
