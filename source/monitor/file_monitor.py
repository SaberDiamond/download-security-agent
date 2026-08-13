from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import time # Timer to prevent CPU Consumption

class DownloadEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        print(f"[DETECTED] New file: {file_path.name}")


def monitor_directory(directory: str):
    path = Path(directory)

    if not path.exists():
        raise FileNotFoundError(f"Directory does not exist: {path}")

    event_handler = DownloadEventHandler()
    observer = Observer()

    observer.schedule(event_handler, str(path), recursive=False)
    observer.start()

    print(f"Monitoring: {path}")
    print("Waiting for files...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()