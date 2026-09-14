# Download Security Agent

A small cybersecurity project I built while exploring endpoint security and learning more about how security tools are built.

The idea was simple:

> What if a downloaded file could be checked for suspicious characteristics before a user opens it?

I wanted to take that idea and turn it into a working MVP rather than just leave it as a concept.

---

## What Does It Do?

The Download Security Agent monitors a folder for newly downloaded files and analyzes supported files for potentially suspicious characteristics.

For this MVP, the project focuses on **PDF files**.

The agent can currently:

- Monitor a folder for new files
- Analyze PDF files
- Detect embedded JavaScript
- Look for suspicious JavaScript indicators
- Detect embedded files
- Extract URLs from PDFs
- Analyze domains and IP addresses
- Perform WHOIS and DNS-related checks
- Check DNSBL reputation when configured
- Generate a preliminary risk score
- Display the results in a desktop GUI
- Let the user decide whether to keep or move a file to Trash

The agent does **not** automatically delete files based on the risk score.

---

## How It Works

At a high level, the process looks like this:

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
 JavaScript        Embedded Files
  Analysis            Analysis
      |
      v
 URL Extraction
      |
      v
 URL / Domain Analysis
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
 Risk Assessment
      |
      v
   GUI Alert
      |
      +------------------+
      |                  |
      v                  v
  Keep File        Move to Trash
````

The project uses a queue-based worker so that the agent can wait for new files instead of continuously scanning the directory.

---

## Example

For example, a PDF containing embedded JavaScript may produce a result such as:

```text
Risk: HIGH
Score: 5

Findings:
- JavaScript detected
- Suspicious JavaScript detected
- JavaScript indicator: eval
```

The GUI then lets the user inspect the findings and decide what to do with the file.

---

## The GUI

The MVP includes a simple desktop interface built with CustomTkinter.

The main dashboard shows:

* Whether protection is active
* The directory currently being monitored
* A button to manually scan a file
* Recent activity

When a file is analyzed, a security alert window shows:

* Risk level
* Risk score
* Why the file was flagged
* File information
* PDF analysis
* JavaScript analysis
* URL and domain information
* Other available analysis results

The user can then choose:

**Keep File**
Leaves the file where it is.

**Move to Trash**
Moves the file into the project's `trash/` directory instead of permanently deleting it.

---

## Why I Built This

I am interested in cybersecurity and wanted to get some hands-on experience building something rather than only learning about security concepts.

This project started as an idea and gradually became a working MVP.

While building it, I learned about things I had not worked with much before, including:

* File-system monitoring
* Queues and worker threads
* URLs and domain information
* DNS and DNSBLs
* Desktop GUI development
* Structuring a project into separate components

The main goal was to learn by actually building something and making it modular for future expansion.

---

## Current MVP

The current version supports:

* **PDF files**
* Directory monitoring
* Manual file scanning
* PDF security analysis
* URL and domain analysis
* Preliminary risk assessment
* Desktop notifications
* User-controlled file actions

This is intentionally a small MVP rather than a complete endpoint security product.

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
│   ├── gui/
│   │   ├── app.py
│   │   ├── alert_window.py
│   │   ├── widgets.py
│   │   ├── formatters.py
│   │   └── theme.py
│   │
│   ├── processor.py
│   ├── main.py
│   └── gui_main.py
│
├── tests/
│   └── test_pipeline.py
│
├── samples/
│   ├── generators/
│   └── test_downloads/
│   └── test_pdfs/
│
├── trash/
│
├── README.md
├── SCHEMA.md
├── requirements.txt
└── .gitignore
```

---

## Running the Project

### 1. Clone the repository

```bash
git clone <repository-url>
cd download-security-agent
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the GUI

```bash
python -m source.gui_main
```

The MVP currently monitors:

```text
samples/test_downloads
```
Test PDFs are provided in the 'samples/test_pdfs/' directory. 

To test the monitoring functionality, copy one of the test PDFs into 'samples/test_downloads/' and the agent will detect and analyze it.

Place a PDF into that folder to test the monitoring and analysis pipeline.

### 5. Run the tests

```bash
python -m tests.test_pipeline
```

---

## DNSBL Checks

For the DNSBL checks, this project uses **Spamhaus DQS (Data Query Service)**.

Since this is a personal project, the DNSBL implementation only makes a minimal number of DQS queries for testing purposes.

To use the DNSBL checks:

1. Go to [Spamhaus](https://www.spamhaus.com/) and sign up for a DQS account.
2. After signing up, get your **DQS Query Key**.
3. Copy the key and run the following command in your terminal before starting the project:

```bash
export SPAMHAUS_DQS_KEY="your-key-here"
```

The key should not be committed to the repository.

DNSBL checks are optional. If a key is not configured, the agent does not treat that as proof that an IP is safe.

---

## Current Limitations

There are still several things I would like to improve and implement.

### PDF Only

The current MVP only supports PDF files.

Additional file types could be added later.

### Post-Download Analysis

The current version analyzes files after they appear in the monitored folder.

It does not intercept a download before it reaches the filesystem.

### Preliminary Risk Assessment

The risk score is based on the indicators currently implemented in the project.

It should not be treated as a definitive determination that a file is malicious or safe.

### No Sandbox

The current MVP does not execute files or URLs inside a virtual machine or sandbox.

### No Automatic Blocking

The agent does not automatically delete or quarantine a file because of its risk score.

The user makes the final decision.

---

## What I'd Like to Work On Next

Now that the basic MVP is working, some areas I'd like to explore are:

* More reliable file-type identification
* Support for additional file types
* Better handling of files while they are still downloading
* More security analysis techniques
* Better testing
* Potential sandbox-based analysis

These are future improvements rather than requirements for the current MVP.

---

## Where Could This Be Implemented?

I initially imagined this as a program running directly on personal devices. However, after discussing the idea with a mentor, I realized that the same concept could potentially be implemented at an organizational level, such as a SaaS solution or an internal security service for employers.

For example, with the sandboxing approach I would like to explore in the future, downloaded files could first be sent to dedicated company servers for analysis in an isolated environment before being made available to the user.

I understand that this approach could introduce some additional delay to the downloading process, even when a file is determined to be safe. One possible solution would be to give users the option to bypass the additional analysis when they trust the source or file.

---

## What I Learned

One of the biggest things I learned from this project is that building a tool involves much more than just writing the main functionality.

When I first started this project, I mainly focused on the idea of analyzing downloaded files for suspicious characteristics. As I built it, I realized how many other pieces were involved in turning that idea into an actual working application.

I had to think about:

- How files are detected
- How work is queued and processed
- How different components communicate with each other
- How the analysis results are combined
- How results should be presented to the user
- How user actions should be handled
- What technologies and libraries are appropriate for each part of the application
- How the overall architecture should be structured
- How different parts of the application fit together

This project made me realize that there is a lot more to learn about software development, including different tech stacks, system architecture, and how larger applications are designed.

It also gave me a better understanding of what it means to take a cybersecurity idea and turn it into a working application rather than just implementing one individual security feature.

Building this MVP gave me a much better understanding of what goes into turning an idea into a working application, and it also helped me identify the areas of software development and cybersecurity that I want to learn more about next.
