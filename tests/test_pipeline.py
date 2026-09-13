from source.processor import process_file


TEST_FILE = "samples/test_downloads/test_js.pdf"


def validate_result(result: dict):
    """
    Validate the structure expected by the terminal interface
    and future GUI.
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


def analyze_file(file_path: str) -> dict:
    return process_file(file_path)


if __name__ == "__main__":
    result = analyze_file(TEST_FILE)

    validate_result(result)

    print("Pipeline Test")
    print("=========================")

    print(f"File: {result['file']['name']}")
    print(f"Type: {result['file']['type']}")
    print(f"MIME Type: {result['file']['mime_type']}")
    print(f"Size: {result['file']['size']} bytes")
    print(f"SHA-256: {result['file']['sha256']}")

    print()
    print("Status")
    print("-------------------------")
    print(result["status"])

    print()
    print("Analysis")
    print("-------------------------")

    analysis = result["analysis"]

    print(
        f"Pages: "
        f"{analysis['pages']}"
    )

    print(
        f"JavaScript: "
        f"{analysis['javascript_detected']}"
    )

    print(
        f"URLs: "
        f"{analysis['urls']}"
    )

    print(
        f"Embedded Files: "
        f"{analysis['embedded_files_detected']}"
    )

    print(
        f"Actions: "
        f"{analysis['actions_detected']}"
    )

    print()
    print("Risk Assessment")
    print("-------------------------")

    print(
        f"Score: "
        f"{result['risk']['score']}"
    )

    print(
        f"Level: "
        f"{result['risk']['level']}"
    )

    print()
    print("Findings")

    for finding in result["risk"]["findings"]:
        print(f"- {finding}")

    print()
    print("Available Actions")
    print("-------------------------")

    for action in result["available_actions"]:
        print(f"- {action}")

    print()
    print("Pipeline test passed.")