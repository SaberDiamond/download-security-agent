from pathlib import Path
from queue import Queue
from threading import Thread

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from source.processor import process_file, print_result


IGNORED_FILENAMES = {
    ".DS_Store",
    ".localized",
}


def should_ignore(file_path: Path) -> bool:
    """
    Ignore operating-system metadata files and other files that should
    never enter the security-analysis pipeline.
    """

    if file_path.name in IGNORED_FILENAMES:
        return True

    # macOS AppleDouble metadata files begin with "._".
    if file_path.name.startswith("._"):
        return True

    return False


class DownloadEventHandler(FileSystemEventHandler):
    """
    Detect newly created or moved files and place them into the
    processing queue.

    Both events are handled because real browser downloads may be
    written to a temporary filename and then renamed to their final
    filename when the download completes.
    """

    def __init__(self, file_queue: Queue):
        super().__init__()

        self.file_queue = file_queue

    def _queue_file(self, file_path: Path):
        if should_ignore(file_path):
            return

        if not file_path.is_file():
            return

        print(
            f"[DETECTED] New file: "
            f"{file_path.name}"
        )

        self.file_queue.put(file_path)

        print(
            f"[QUEUED] {file_path.name}"
        )

    def on_created(self, event):
        if event.is_directory:
            return

        self._queue_file(
            Path(event.src_path)
        )

    def on_moved(self, event):
        if event.is_directory:
            return

        # When a browser finishes a download by renaming a temporary
        # file, src_path is the temporary name and dest_path is the
        # completed filename.
        self._queue_file(
            Path(event.dest_path)
        )


def process_queue(
    file_queue: Queue,
    on_result=None,
):
    """
    Worker that waits for files in the queue.

    The worker blocks while the queue is empty, so the agent does not
    continuously scan the directory.

    Each file is passed through the complete processing pipeline.

    If ``on_result`` is provided, the structured result is sent to the
    callback. Otherwise the result is printed to the terminal.
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

            if on_result is not None:
                try:
                    on_result(
                        result,
                        file_path,
                    )

                except Exception as error:
                    print(
                        f"[ERROR] "
                        f"Result handler failed: "
                        f"{error}"
                    )

            else:
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


def monitor_directory(
    directory: str,
    on_result=None,
    blocking: bool = True,
):
    """
    Monitor a directory for newly available files.

    ``on_result`` is forwarded to the processing worker so callers such
    as the GUI can receive structured results.

    ``blocking=True`` preserves the terminal application's original
    behavior.

    ``blocking=False`` returns the observer immediately so a GUI can
    run the monitor alongside its own event loop.
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

    file_queue = Queue()

    worker = Thread(
        target=process_queue,
        args=(
            file_queue,
            on_result,
        ),
        daemon=True,
    )

    worker.start()

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

    if not blocking:
        return observer

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