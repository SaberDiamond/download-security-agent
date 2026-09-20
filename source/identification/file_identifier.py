from pathlib import Path
import hashlib
import mimetypes


FILE_SIGNATURES = {
    b"%PDF-": "PDF",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"PK\x03\x04": "ZIP",
    b"PK\x05\x06": "ZIP",
    b"PK\x07\x08": "ZIP",
}


EXPECTED_TYPES = {
    ".pdf": "PDF",
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".gif": "GIF",
    ".zip": "ZIP",
}


def calculate_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)

    return sha256.hexdigest()


def detect_file_type(file_path: Path) -> str:
    """
    Detect the actual file type using its binary signature.
    """
    with file_path.open("rb") as file:
        header = file.read(16)

    for signature, file_type in FILE_SIGNATURES.items():
        if header.startswith(signature):
            return file_type

    return "Unknown"


def verify_file_type(
    extension: str,
    actual_type: str,
) -> bool:
    """
    Verify that the file extension matches the detected file type.
    """
    expected_type = EXPECTED_TYPES.get(extension)

    if expected_type is None:
        return True

    return expected_type == actual_type


def identify_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File does not exist: {path}"
        )

    extension = path.suffix.lower()

    mime_type, _ = mimetypes.guess_type(path.name)

    actual_type = detect_file_type(path)

    type_verified = verify_file_type(
        extension,
        actual_type,
    )

    return {
        "filename": path.name,
        "extension": extension,
        "mime_type": mime_type or "unknown",
        "actual_type": actual_type,
        "type_verified": type_verified,
        "size": path.stat().st_size,
        "sha256": calculate_sha256(path),
    }