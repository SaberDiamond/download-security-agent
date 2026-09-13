# Download Security Agent

A lightweight endpoint security tool that analyzes downloaded files before they are opened, identifies suspicious characteristics, and produces a risk assessment to help users decide whether to keep or move a file to trash.

## Project Background

Downloaded files can contain security risks that are not immediately visible to a user. A PDF, for example, can contain JavaScript, embedded files, external URLs, or actions that may be abused for malicious purposes.

The Download Security Agent is designed to inspect downloaded files and provide the user with security-focused information before they decide what to do with the file.

The project was originally developed as a cybersecurity internship project and is now being continued as an independent portfolio project.

---

## Current MVP

The current MVP focuses on **PDF files**.

The agent:

1. Monitors a designated download directory.
2. Detects newly created files.
3. Places detected files into a processing queue.
4. Identifies basic file information.
5. Analyzes supported PDF files.
6. Extracts security-relevant indicators.
7. Analyzes URLs found inside PDFs.
8. Performs domain and IP reputation checks.
9. Calculates a risk score and risk level.
10. Returns a structured analysis result.
11. Provides file actions for the user to choose from.

The current file actions are:

* **Allow**: Keep the file in its current location.
* **Move to Trash**: Move the file into the project's `trash/` directory.

The agent does **not** automatically delete or move files based solely on the risk score.

---

## How It Works

```text
Downloaded File
      |
      v
File Monitor
      |
      v
Processing Queue
      |
      v
File Identification
      |
      v
PDF Analysis
      |
      +------------------+
      |                  |
      v                  v
JavaScript          Embedded Files
Analysis             Analysis
      |
      +------------------+
      |
      v
URL Extraction
      |
      v
URL Analysis
      |
      +------------------+
      |                  |
      v                  v
    WHOIS               DNS
                         |
                         v
                       DNSBL
      |
      v
URL Assessment
      |
      v
Risk Engine
      |
      v
Structured Result
      |
      +-------------------+
      |                   |
      v                   v
   Terminal              GUI
                         (future)
```

---

## Architecture

The project uses a modular architecture so that individual security checks can be developed and maintained independently.

### Monitoring

The file monitor uses `watchdog` to detect newly created files.

Detected files are placed into a queue rather than being continuously scanned by a worker.

The processing worker waits on the queue when there are no files to process. This avoids unnecessary continuous filesystem scanning and keeps idle CPU usage low.

### File Identification

Before analysis, the agent collects basic file information:

* Filename
* File extension
* MIME type
* File size
* SHA-256 hash

### PDF Analysis

The current PDF analyzer checks for several security-relevant characteristics:

* Encryption
* Embedded JavaScript
* External URLs
* Embedded files
* PDF actions

### JavaScript Analysis

Embedded JavaScript is inspected for suspicious indicators.

The current implementation can identify indicators such as:

* `eval`

JavaScript findings contribute to the overall risk assessment.

### URL Analysis

URLs extracted from PDFs are analyzed separately.

The URL analyzer collects:

* URL
* Scheme
* Domain
* Port
* Path
* Query
* Fragment
* Resolved IP addresses

### WHOIS Analysis

WHOIS information is used as reputation evidence.

The current analysis includes:

* Registrar
* Domain creation date
* Domain expiration date
* Domain age

A newly registered domain is treated as a potential warning indicator, not proof of malicious activity.

### DNSBL Analysis

Resolved IPv4 addresses can be checked against Spamhaus DNSBL infrastructure using Spamhaus DQS.

A listed IP is treated as a significant reputation concern.

A non-listed IP does not prove that the associated domain is safe.

### URL Assessment

The URL assessment layer combines multiple reputation indicators, including:

* Domain age
* Domain expiration
* DNSBL results
* HTTPS usage

It produces a URL-level verdict such as:

* `LOW_RISK`
* `CAUTION`
* `SUSPICIOUS`
* `UNKNOWN`

### Risk Engine

The risk engine combines findings from the different analyzers into a single risk score.

The current risk levels are:

| Score | Level    |
| ----: | -------- |
|   0-1 | LOW      |
|   2-4 | MEDIUM   |
|   5-7 | HIGH     |
|    8+ | CRITICAL |

The risk engine evaluates evidence produced by the analyzers. It does not independently determine whether a file is malicious.

---

## Structured Processing Result

The processor produces a structured result that acts as the interface between the security backend and future user interfaces.

The structure is approximately:

```text
result
├── file
│   ├── name
│   ├── path
│   ├── extension
│   ├── mime_type
│   ├── size
│   ├── sha256
│   └── type
│
├── status
├── error
├── analysis
├── risk
├── available_actions
└── action
```

This separation allows the security engine to remain independent from the user interface.

The terminal interface currently displays this result.

A future graphical interface can consume the same result without needing to understand or modify the underlying security analysis.

---

## Project Structure

```text
download-security-agent/
│
├── source/
│   ├── analyzers/
│   │   ├── dnsbl_analyzer.py
│   │   ├── embedded_file_analyzer.py
│   │   ├── javascript_analyzer.py
│   │   ├── pdf_analyzer.py
│   │   ├── url_analyzer.py
│   │   └── whois_analyzer.py
│   │
│   ├── assessment/
│   │   └── url_assessment.py
│   │
│   ├── identification/
│   │   └── file_identifier.py
│   │
│   ├── monitor/
│   │   └── file_monitor.py
│   │
│   ├── risk/
│   │   └── risk_engine.py
│   │
│   ├── actions/
│   │   └── file_actions.py
│   │
│   ├── processor.py
│   └── main.py
│
├── tests/
│   └── test_pipeline.py
│
├── samples/
│   ├── generators/
│   └── test_downloads/
│
├── trash/
│   └── .gitkeep
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## Requirements

* Python 3.9+
* `watchdog`
* `pypdf`
* `python-whois`

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd download-security-agent
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it on macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Agent

Start the agent with:

```bash
python -m source.main
```

The agent will begin monitoring the configured download directory.

When a new file is detected, it is placed into the processing queue and analyzed by the worker.

---

## Testing

The pipeline test can be run from the project root with:

```bash
python -m tests.test_pipeline
```

The test validates the complete processing pipeline, including:

* File identification
* PDF analysis
* JavaScript detection
* Risk calculation
* Structured result generation
* Available user actions

A successful test ends with:

```text
Pipeline test passed.
```

---

## DNSBL Configuration

DNSBL checks use Spamhaus DQS.

The DQS key is read from the following environment variable:

```text
SPAMHAUS_DQS_KEY
```

Set the variable before running the agent:

```bash
export SPAMHAUS_DQS_KEY="your-key-here"
```

The key should never be committed to the repository.

If the key is not configured, DNSBL analysis reports that the check could not be performed rather than treating the IP as safe.

---

## File Actions

The project currently provides two file actions.

### Allow

Allowing a file leaves it in its current location.

No filesystem operation is performed.

### Move to Trash

The agent can move a file into:

```text
trash/
```

The project does not permanently delete the file.

Filename collisions are handled automatically:

```text
suspicious.pdf
suspicious_1.pdf
suspicious_2.pdf
```

This provides a safer recovery path than immediately deleting a potentially suspicious file.

---

## Current Limitations

The current MVP has several intentional limitations.

### PDF Only

PDF is currently the only supported file type.

The architecture is designed so additional analyzers can be added later without rewriting the monitoring and processing pipeline.

Potential future file types include:

* Office documents
* Images
* Archives
* Executables
* Scripts

### Post-Download Monitoring

The current implementation detects files after they appear in the monitored directory.

It does not intercept a network download before the file reaches the filesystem.

A future implementation could use an isolated browser download directory or another interception mechanism to provide earlier inspection.

### URL Reputation

URL assessment currently relies on available domain, DNS, DNSBL, and HTTPS indicators.

These signals provide evidence but cannot guarantee that a URL is malicious or safe.

### No Sandbox Execution

The current MVP does not execute suspicious files in a virtual machine or sandbox.

A future version could analyze suspicious URLs or files in an isolated environment.

### No Automatic Blocking

The agent does not automatically delete or quarantine files based on their risk level.

The current design keeps the final decision with the user.

### Graphical Interface

The security backend currently produces structured results and terminal output.

A graphical interface is the next major user-facing component.

---

## Future Development

Potential future improvements include:

### Graphical User Interface

A GUI will present analysis results in an easier-to-understand format.

Possible sections include:

* Risk level
* Risk score
* File information
* Why the file was flagged
* PDF analysis
* JavaScript analysis
* URL analysis
* Domain reputation
* Embedded file information
* Available actions

Users will be able to expand sections to inspect the evidence behind the risk assessment.

### Additional File Types

Additional analyzers can be added as independent modules.

The modular architecture is intended to make this possible without rewriting the core monitoring and processing system.

### Stronger URL Reputation

Future versions could incorporate additional reputation sources and signals.

### Isolated Analysis

Suspicious URLs or files could eventually be inspected in an isolated virtual machine or sandbox.

### Earlier Download Inspection

A future architecture could inspect files before they are made available to the user, potentially through an isolated download location or download interception mechanism.

### Improved Risk Scoring

The risk engine could eventually use more granular evidence and confidence levels rather than relying only on fixed weights.

---

## Security Philosophy

The project follows an **evidence-based analysis** approach.

Individual indicators are not automatically treated as proof of malicious activity.

For example:

* HTTPS does not mean a website is safe.
* A young domain is not automatically malicious.
* An IP not appearing in a DNSBL does not prove that it is safe.
* A PDF containing JavaScript is suspicious, but the presence of JavaScript alone does not establish malicious intent.

The goal is to combine multiple signals and present the evidence clearly so that a user can make an informed decision.

---

## Disclaimer

This project is an educational and portfolio project.

It should not be considered a replacement for enterprise endpoint security, malware detection, sandboxing, antivirus software, or professional security analysis.

The analysis results are indicators and should not be interpreted as definitive proof that a file or URL is safe or malicious.
