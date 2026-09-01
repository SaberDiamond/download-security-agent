from pathlib import Path

from pypdf import PdfReader

from source.identification.file_identifier import identify_file


# File extensions that commonly represent executable programs.
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".com",
    ".scr",
    ".msi",
    ".app",
}


# File extensions that commonly represent scripts.
SCRIPT_EXTENSIONS = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".bat",
    ".cmd",
    ".sh",
    ".py",
}


def classify_embedded_file(file_info: dict) -> str:
    """
    Classify an embedded file based on its extension.

    This is only a preliminary classification.
    It does not determine whether a file is malicious.
    """

    extension = file_info.get("extension", "").lower()

    if extension in EXECUTABLE_EXTENSIONS:
        return "executable"

    if extension in SCRIPT_EXTENSIONS:
        return "script"

    return "document_or_data"


def extract_embedded_files(
    file_path: str,
    output_directory: str,
) -> list[dict]:
    """
    Extract embedded files from a PDF without executing them.

    Each extracted file is passed through the existing
    file identification system and then classified.
    """

    path = Path(file_path)
    output_path = Path(output_directory)

    output_path.mkdir(parents=True, exist_ok=True)

    reader = PdfReader(path)

    extracted_files = []

    root = reader.root_object
    names = root.get("/Names")

    if not names:
        return extracted_files

    names = names.get_object()

    embedded_files = names.get("/EmbeddedFiles")

    if not embedded_files:
        return extracted_files

    embedded_files = embedded_files.get_object()

    file_names = embedded_files.get("/Names")

    if not file_names:
        return extracted_files

    file_names = file_names.get_object()

    # /Names contains alternating:
    # [filename, file specification, filename, file specification, ...]

    for index in range(0, len(file_names), 2):
        if index + 1 >= len(file_names):
            break

        filename = str(file_names[index])

        file_spec = file_names[index + 1].get_object()

        embedded_file = file_spec.get("/EF")

        if not embedded_file:
            continue

        embedded_file = embedded_file.get_object()

        file_stream = embedded_file.get("/F")

        if not file_stream:
            continue

        file_stream = file_stream.get_object()

        file_data = file_stream.get_data()

        # Prevent path traversal from embedded filenames.
        safe_filename = Path(filename).name

        destination = output_path / safe_filename

        with destination.open("wb") as output_file:
            output_file.write(file_data)

        # Identify the extracted file.
        file_info = identify_file(str(destination))

        # Add preliminary classification.
        file_info["classification"] = classify_embedded_file(file_info)

        extracted_files.append(file_info)

    return extracted_files