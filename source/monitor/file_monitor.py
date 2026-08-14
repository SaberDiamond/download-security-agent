from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from source.identification.file_identifier import identify_file

import time # Timer to prevent CPU Consumption

class DownloadEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        print(f"[DETECTED] New file: {file_path.name}")

        try:
            file_info = identify_file(str(file_path))

            print(f"Filename: {file_info['filename']}")
            print(f"Extension: {file_info['extension']}")
            print(f"MIME Type: {file_info['mime_type']}")
            print(f"Size: {file_info['size']} bytes")
            print(f"SHA-256: {file_info['sha256']}")

        except Exception as error:
            print(f"[ERROR] Could not identify file: {error}")


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