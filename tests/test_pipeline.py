from pathlib import Path

from source.processor import process_file


TEST_FILES = [
    (
        "samples/test_downloads/test_benign.pdf",
        "LOW",
    ),
    (
        "samples/test_downloads/test_js.pdf",
        "HIGH",
    ),
    (
        "samples/test_downloads/test_embedded_exe.pdf",
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


def test_file(
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
        result = test_file(
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