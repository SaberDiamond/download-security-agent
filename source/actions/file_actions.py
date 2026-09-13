from pathlib import Path
import shutil


def get_trash_directory() -> Path:
    """
    Return the project's trash directory.

    The trash directory is located at the root of the project:

        download-security-agent/
        ├── source/
        ├── samples/
        └── trash/
    """

    project_root = Path(__file__).resolve().parents[2]

    trash_directory = project_root / "trash"

    trash_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return trash_directory


def get_unique_destination(
    destination: Path,
) -> Path:
    """
    Prevent files with the same name from being overwritten.

    Example:

        suspicious.pdf
        suspicious_1.pdf
        suspicious_2.pdf
    """

    if not destination.exists():
        return destination

    counter = 1

    while True:
        new_destination = (
            destination.parent
            / f"{destination.stem}_{counter}"
            f"{destination.suffix}"
        )

        if not new_destination.exists():
            return new_destination

        counter += 1


def move_to_trash(file_path: str) -> dict:
    """
    Move a file into the project's trash directory.

    The file is moved rather than permanently deleted.

    Returns a structured result describing the action.
    """

    source = Path(file_path)

    if not source.exists():
        return {
            "success": False,
            "action": "move_to_trash",
            "source": str(source),
            "destination": None,
            "error": "File does not exist.",
        }

    if not source.is_file():
        return {
            "success": False,
            "action": "move_to_trash",
            "source": str(source),
            "destination": None,
            "error": "Path is not a file.",
        }

    trash_directory = get_trash_directory()

    destination = trash_directory / source.name

    destination = get_unique_destination(
        destination
    )

    try:
        shutil.move(
            str(source),
            str(destination),
        )

        return {
            "success": True,
            "action": "move_to_trash",
            "source": str(source),
            "destination": str(destination),
            "error": None,
        }

    except Exception as error:
        return {
            "success": False,
            "action": "move_to_trash",
            "source": str(source),
            "destination": None,
            "error": str(error),
        }


def allow_file(file_path: str) -> dict:
    """
    Allow a file to remain in its original location.

    No filesystem operation is performed.

    This function exists so that the GUI can use a consistent
    action interface for both allowing and moving files.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        return {
            "success": False,
            "action": "allow",
            "file": str(file_path),
            "error": "File does not exist.",
        }

    return {
        "success": True,
        "action": "allow",
        "file": str(file_path),
        "error": None,
    }