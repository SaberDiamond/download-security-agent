from pathlib import Path

from source.processor import process_file
from source.identification.file_identifier import identify_file


TEST_FILES = [
    (
        "samples/test_pdfs/test_benign.pdf",
        "LOW",
    ),
    (
        "samples/test_pdfs/test_js.pdf",
        "HIGH",
    ),
    (
        "samples/test_pdfs/test_embedded_exe.pdf",
        "HIGH",
    ),
]


def validate_result(
    result: dict,
):
    """
    Validate the common structure returned by process_file().
    """

    assert "file" in result
    assert "status" in result
    assert "error" in result
    assert "analysis" in result
    assert "risk" in result
    assert "available_actions" in result
    assert "action" in result

    file_info = result["file"]

    assert "name" in file_info
    assert "path" in file_info
    assert "extension" in file_info
    assert "mime_type" in file_info
    assert "size" in file_info
    assert "sha256" in file_info
    assert "type" in file_info

    assert result["status"] == "analyzed"

    assert result["risk"] is not None

    assert "score" in result["risk"]
    assert "level" in result["risk"]
    assert "findings" in result["risk"]

    assert "allow" in result["available_actions"]
    assert "move_to_trash" in result["available_actions"]

    assert result["action"] is None


def run_test(
    file_path: str,
    expected_level: str,
):
    """
    Process one sample PDF and validate its result.
    """

    assert Path(file_path).exists(), (
        f"Test file does not exist: {file_path}"
    )

    result = process_file(
        file_path
    )

    validate_result(result)

    actual_level = result["risk"]["level"]

    assert actual_level == expected_level, (
        f"{file_path}: expected "
        f"{expected_level}, got "
        f"{actual_level}"
    )

    return result


def test_pipeline_files():
    """
    Run all sample files through the complete security pipeline.
    """

    for file_path, expected_level in TEST_FILES:
        run_test(
            file_path,
            expected_level,
        )


def test_pdf_file_type_is_verified():
    """
    Verify that the benign sample is actually a PDF
    based on its binary signature.
    """

    file_path = (
        "samples/test_pdfs/test_benign.pdf"
    )

    result = identify_file(file_path)

    assert result["extension"] == ".pdf"
    assert result["actual_type"] == "PDF"
    assert result["type_verified"] is True


def test_file_type_mismatch_is_detected(tmp_path):
    """
    Verify that a file pretending to be a PDF is detected
    as a file-type mismatch.
    """

    fake_pdf = tmp_path / "fake.pdf"

    fake_pdf.write_text(
        "This is not actually a PDF file.",
        encoding="utf-8",
    )

    result = identify_file(
        str(fake_pdf)
    )

    assert result["extension"] == ".pdf"
    assert result["actual_type"] == "Unknown"
    assert result["type_verified"] is False


def main():
    print(
        "Download Security Agent"
    )

    print(
        "Pipeline Test"
    )

    print(
        "========================="
    )

    for file_path, expected_level in TEST_FILES:
        result = run_test(
            file_path,
            expected_level,
        )

        print()
        print(
            f"File: "
            f"{result['file']['name']}"
        )

        print(
            f"Type: "
            f"{result['file']['type']}"
        )

        print(
            f"Risk: "
            f"{result['risk']['level']}"
        )

        print(
            f"Score: "
            f"{result['risk']['score']}"
        )

        print(
            f"Expected: "
            f"{expected_level}"
        )

        print(
            "Result: PASS"
        )

    print()
    print(
        "========================="
    )

    print(
        "All pipeline tests passed."
    )


if __name__ == "__main__":
    main()