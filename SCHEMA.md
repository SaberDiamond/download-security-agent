# Download Security Agent

# Backend Result Schema

This document defines the structured result returned by:

```python
source.processor.process_file()
```

The GUI should consume this result rather than parsing terminal output or directly implementing security analysis logic.

---

## 1. Processing Result

A successful analysis returns an object with this structure:

```text
result
├── file
├── status
├── error
├── analysis
├── risk
├── available_actions
└── action
```

---

## 2. File Information

The `file` object contains basic information about the analyzed file.

```json
{
  "file": {
    "name": "example.pdf",
    "path": "samples/test_downloads/example.pdf",
    "extension": ".pdf",
    "mime_type": "application/pdf",
    "size": 12345,
    "sha256": "..."
    "type": "PDF"
  }
}
```

### Fields

| Field       | Type         | Description              |
| ----------- | ------------ | ------------------------ |
| `name`      | string       | Filename                 |
| `path`      | string       | Original filesystem path |
| `extension` | string       | File extension           |
| `mime_type` | string       | Detected MIME type       |
| `size`      | integer/null | File size in bytes       |
| `sha256`    | string/null  | SHA-256 hash             |
| `type`      | string/null  | Supported file type      |

The GUI should display the filename prominently.

The SHA-256 hash can be displayed in an expandable file information section.

---

## 3. Status

The `status` field describes the processing state.

Possible values include:

```text
analyzed
unsupported
identification_failed
analysis_failed
risk_assessment_failed
```

### `analyzed`

The file was successfully identified, analyzed, and risk-assessed.

The GUI should display the complete analysis and risk result.

### `unsupported`

The file type is not currently supported.

The GUI should clearly explain that the current MVP supports PDF files.

### `identification_failed`

The file could not be identified.

The GUI should display the error information if available.

### `analysis_failed`

The file was identified but security analysis failed.

### `risk_assessment_failed`

The file was analyzed but the risk engine failed.

The GUI should avoid presenting an incomplete risk result as a valid security verdict.

---

## 4. Error

The `error` field contains an error message when processing fails.

Example:

```json
{
  "error": "File does not exist."
}
```

For successful processing:

```json
{
  "error": null
}
```

The GUI should display errors in a clear user-friendly way.

It should not expose Python stack traces to the normal user interface.

---

# 5. PDF Analysis

For a successfully analyzed PDF, the `analysis` object contains:

```text
analysis
├── pages
├── encrypted
├── javascript_detected
├── javascript_analysis
├── urls
├── url_analysis
├── url_assessment
├── embedded_files_detected
├── embedded_file_analysis
├── actions_detected
└── findings
```

---

## 6. Basic PDF Analysis

Example:

```json
{
  "pages": 1,
  "encrypted": false,
  "javascript_detected": true,
  "embedded_files_detected": false,
  "actions_detected": false
}
```

### Fields

| Field                     | Type    | Description                              |
| ------------------------- | ------- | ---------------------------------------- |
| `pages`                   | integer | Number of pages                          |
| `encrypted`               | boolean | Whether the PDF is encrypted             |
| `javascript_detected`     | boolean | Whether embedded JavaScript was detected |
| `embedded_files_detected` | boolean | Whether embedded files were detected     |
| `actions_detected`        | boolean | Whether PDF actions were detected        |

These values should be displayed in a concise PDF Analysis section.

---

# 7. JavaScript Analysis

`javascript_analysis` contains detailed information about detected JavaScript.

Example:

```json
[
  {
    "name": "JavaScript",
    "suspicious": true,
    "findings": [
      "eval"
    ]
  }
]
```

### Fields

| Field        | Type    | Description                                 |
| ------------ | ------- | ------------------------------------------- |
| `name`       | string  | Name or identifier of the JavaScript object |
| `suspicious` | boolean | Whether suspicious indicators were found    |
| `findings`   | array   | Detected JavaScript indicators              |

The GUI should show this in an expandable **JavaScript Analysis** section.

Do not execute the JavaScript.

---

# 8. URLs

The `urls` field contains URLs extracted from the PDF.

Example:

```json
[
  "https://example.com"
]
```

The GUI should display the detected URLs.

A URL being present does not automatically mean the PDF or URL is malicious.

---

# 9. URL Analysis

Each URL can contain:

```text
url_analysis[]
├── url
├── scheme
├── domain
├── port
├── path
├── query
├── fragment
├── ip_addresses
├── whois
└── dnsbl
```

Example:

```json
{
  "url": "https://example.com",
  "scheme": "https",
  "domain": "example.com",
  "port": null,
  "path": "",
  "query": "",
  "fragment": "",
  "ip_addresses": [
    "93.184.216.34"
  ]
}
```

The GUI should group information by URL rather than presenting one large unstructured list.

---

# 10. WHOIS

WHOIS information is contained inside the URL analysis.

Example:

```json
{
  "whois": {
    "domain": "example.com",
    "registrar": "...",
    "creation_date": "...",
    "expiration_date": "...",
    "domain_age_days": 5000
  }
}
```

### Fields

| Field             | Description               |
| ----------------- | ------------------------- |
| `domain`          | Domain being examined     |
| `registrar`       | Domain registrar          |
| `creation_date`   | Domain creation date      |
| `expiration_date` | Domain expiration date    |
| `domain_age_days` | Approximate age of domain |

WHOIS information is evidence.

A young domain should not be presented as automatically malicious.

---

# 11. DNSBL

DNSBL results contain information about the reputation of resolved IP addresses.

Example:

```json
{
  "dnsbl": [
    {
      "ip": "1.2.3.4",
      "listed": false,
      "status": "Not listed"
    }
  ]
}
```

Possible states include:

```text
Listed
Not listed
DQS key not configured
IPv6 not supported
Lookup error
```

A listed IP is a significant reputation concern.

A non-listed IP does not prove that the URL is safe.

The GUI should explain this distinction rather than displaying DNSBL results as definitive malware verdicts.

---

# 12. URL Assessment

Each analyzed URL receives an assessment.

Example:

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "verdict": "LOW_RISK",
  "assessment": "no_obvious_concerns",
  "findings": [],
  "domain_age": {},
  "expiration": {},
  "dnsbl": {},
  "https": {}
}
```

Possible verdicts:

```text
LOW_RISK
CAUTION
SUSPICIOUS
UNKNOWN
```

### Meaning

#### LOW_RISK

No obvious concerns were identified by the implemented reputation checks.

This does not guarantee that the URL is safe.

#### CAUTION

One or more lower-confidence warning indicators were found.

#### SUSPICIOUS

One or more significant reputation concerns were found.

#### UNKNOWN

The available checks were not sufficient to produce a meaningful assessment.

The GUI should avoid using language such as:

> "This URL is definitely malicious."

Instead, it should explain the evidence found.

---

# 13. Embedded Files

Embedded file analysis can contain:

```text
embedded_file_analysis[]
├── filename
├── extension
├── mime_type
├── size
├── sha256
└── classification
```

Possible classifications include:

```text
script
executable
```

The GUI should display embedded files in an expandable section.

---

# 14. Findings

The PDF analyzer produces general findings such as:

```json
[
  "JavaScript detected",
  "External URL(s) detected",
  "Embedded file(s) detected",
  "PDF action detected"
]
```

The risk engine may add more detailed findings.

These findings should be used to explain **why the risk score was generated**.

---

# 15. Risk

The `risk` object contains:

```json
{
  "score": 5,
  "level": "HIGH",
  "findings": [
    "JavaScript detected",
    "Suspicious JavaScript detected",
    "JavaScript indicator: eval"
  ]
}
```

### Fields

| Field      | Type         | Description                       |
| ---------- | ------------ | --------------------------------- |
| `score`    | integer/null | Calculated risk score             |
| `level`    | string       | Risk level                        |
| `findings` | array        | Evidence contributing to the risk |

Current risk levels:

| Score | Level    |
| ----: | -------- |
|   0-1 | LOW      |
|   2-4 | MEDIUM   |
|   5-7 | HIGH     |
|    8+ | CRITICAL |

The risk level should be the most prominent security result in the GUI.

The score can be displayed alongside it.

---

# 16. Available Actions

The processor currently exposes:

```json
{
  "available_actions": [
    "allow",
    "move_to_trash"
  ]
}
```

### Allow

The user chooses to keep the file in its current location.

The backend action is:

```python
allow_file(file_path)
```

No filesystem move is performed.

### Move to Trash

The user chooses to move the file into the project's:

```text
trash/
```

directory.

The backend action is:

```python
move_to_trash(file_path)
```

The file is moved rather than permanently deleted.

The trash system also handles filename collisions.

---

# 17. Action

The `action` field represents the action taken on the file.

Before the user makes a decision:

```json
{
  "action": null
}
```

After an action is performed, the GUI can update this field or maintain the returned action result separately.

The GUI must not automatically perform an action simply because a file has a HIGH or CRITICAL risk level.

The user must explicitly choose the action.

---

# 18. GUI Responsibilities

The GUI should:

1. Receive the structured processing result.
2. Display the file information.
3. Display the overall risk level and score.
4. Explain why the file was flagged.
5. Provide expandable analysis sections.
6. Display URL reputation information.
7. Display WHOIS and DNSBL information.
8. Display JavaScript findings.
9. Display embedded file information.
10. Let the user choose an action.
11. Call the appropriate backend action.
12. Clearly report the result of that action.

---

# 19. GUI Should NOT

The GUI should **not**:

* Reimplement PDF analysis.
* Reimplement URL analysis.
* Reimplement WHOIS.
* Reimplement DNSBL.
* Reimplement risk scoring.
* Parse terminal output.
* Execute embedded JavaScript.
* Automatically delete suspicious files.
* Automatically move files based only on risk level.
* Modify the security analysis rules simply to support the interface.

The security backend remains responsible for security analysis.

The GUI remains responsible for presentation and user interaction.

---

# 20. Recommended User Flow

The intended user experience is:

```text
User downloads a PDF
        |
        v
Agent detects the file
        |
        v
File enters processing queue
        |
        v
Security analysis runs
        |
        v
Risk assessment generated
        |
        v
GUI notification appears
        |
        v
User sees:
    Risk Level
    Risk Score
    File Name
        |
        v
User can expand:
    Why was this flagged?
    File Information
    PDF Analysis
    JavaScript Analysis
    URL Analysis
    Domain Reputation
    Embedded Files
        |
        v
User chooses:
    Allow
       OR
    Move to Trash
        |
        v
GUI displays action result
```

---

# 21. Design Principle

The project follows a separation-of-concerns model:

```text
Security Backend
    |
    | Structured Result
    v
User Interface
    |
    | User Decision
    v
File Action Backend
```

This allows the security engine to evolve independently from the GUI.

Future interfaces could consume the same backend result without rewriting the analyzers.

---

# 22. Example Complete Result

A simplified successful result may look like:

```json
{
  "file": {
    "name": "suspicious.pdf",
    "path": "samples/test_downloads/suspicious.pdf",
    "extension": ".pdf",
    "mime_type": "application/pdf",
    "size": 635,
    "sha256": "aca2e36aef2a19889a67afee8d20822fe0adfa4387df61098b501735627f9653",
    "type": "PDF"
  },

  "status": "analyzed",

  "error": null,

  "analysis": {
    "pages": 1,
    "encrypted": false,
    "javascript_detected": true,
    "javascript_analysis": [
      {
        "name": "JavaScript",
        "suspicious": true,
        "findings": [
          "eval"
        ]
      }
    ],
    "urls": [],
    "url_analysis": [],
    "url_assessment": [],
    "embedded_files_detected": false,
    "embedded_file_analysis": [],
    "actions_detected": false,
    "findings": [
      "JavaScript detected"
    ]
  },

  "risk": {
    "score": 5,
    "level": "HIGH",
    "findings": [
      "JavaScript detected",
      "Suspicious JavaScript detected",
      "JavaScript indicator: eval"
    ]
  },

  "available_actions": [
    "allow",
    "move_to_trash"
  ],

  "action": null
}
```

This example is illustrative. The exact analysis contents depend on the file being processed.
