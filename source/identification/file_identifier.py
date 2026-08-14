from pathlib import Path
import hashlib
import mimetypes


def calculate_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)

    return sha256.hexdigest()


def identify_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File does not exist: {path}")

    mime_type, _ = mimetypes.guess_type(path.name)

    return {
        "filename": path.name,
        "extension": path.suffix.lower(),
        "mime_type": mime_type or "unknown",
        "size": path.stat().st_size,
        "sha256": calculate_sha256(path),
    }