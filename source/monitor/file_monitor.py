from pathlib import Path
from queue import Queue
from threading import Thread

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from source.processor import process_file, print_result


class DownloadEventHandler(FileSystemEventHandler):
    """
    Detect newly created files and place them into the
    processing queue.
    """

    def __init__(self, file_queue: Queue):
        super().__init__()

        self.file_queue = file_queue

    def on_created(self, event):
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        print(
            f"[DETECTED] New file: "
            f"{file_path.name}"
        )

        self.file_queue.put(file_path)

        print(
            f"[QUEUED] {file_path.name}"
        )


def process_queue(file_queue: Queue):
    """
    Worker that waits for files in the queue.

    The worker blocks while the queue is empty, so the agent
    does not continuously scan the directory.

    Each file is passed through the complete processing
    pipeline and the resulting structured object is displayed.
    """

    print(
        "[WORKER] Processing worker started."
    )

    print(
        "[WORKER] Waiting for files..."
    )

    while True:
        file_path = file_queue.get()

        try:
            print(
                f"\n[PROCESSING] "
                f"{file_path.name}"
            )

            try:
                result = process_file(
                    str(file_path)
                )

            except Exception as error:
                print(
                    f"[ERROR] "
                    f"Could not process file: "
                    f"{error}"
                )

                continue

            print_result(result)

            print()
            print(
                "[ACTION] "
                "Waiting for user decision."
            )

            print(
                "[ACTION] "
                "No automatic file action was taken."
            )

            print(
                f"[COMPLETE] "
                f"Finished processing: "
                f"{file_path.name}"
            )

        finally:
            file_queue.task_done()


def monitor_directory(directory: str):
    """
    Monitor a directory for newly created files.
    """

    path = Path(directory)

    if not path.exists():
        raise FileNotFoundError(
            f"Directory does not exist: {path}"
        )

    if not path.is_dir():
        raise NotADirectoryError(
            f"Path is not a directory: {path}"
        )

    # --------------------------------------------------
    # Create the processing queue
    # --------------------------------------------------

    file_queue = Queue()

    # --------------------------------------------------
    # Start the worker
    # --------------------------------------------------

    worker = Thread(
        target=process_queue,
        args=(file_queue,),
        daemon=True,
    )

    worker.start()

    # --------------------------------------------------
    # Start filesystem monitoring
    # --------------------------------------------------

    event_handler = DownloadEventHandler(
        file_queue
    )

    observer = Observer()

    observer.schedule(
        event_handler,
        str(path),
        recursive=False,
    )

    observer.start()

    print(
        f"\nMonitoring: {path}"
    )

    print(
        "Download Security Agent is running."
    )

    print(
        "Waiting for files...\n"
    )

    try:
        observer.join()

    except KeyboardInterrupt:
        print(
            "\nStopping "
            "Download Security Agent..."
        )

        observer.stop()
        observer.join()

        print(
            "Download Security Agent stopped."
        )