# SEA Scanner Pro v5.0.0 - Installation Guide (Source Package)

This folder contains the complete **SEA Scanner Pro** source code. Use this
package if you are a developer or advanced user who wants to run the tool from
Python, customise it, or run the Command-Line Interface (CLI).

## Requirements

- **Python 3.8 or newer** (64-bit recommended).
- Windows / macOS / Linux.
- Internet access to install dependencies (first time only).

## 1. Install dependencies

Open a terminal in this folder and run:

```bash
pip install -r requirements.txt
```

Core dependencies: `requests`, `rich`, `dnspython`, `beautifulsoup4`,
`cryptography`, `PySide6` (desktop GUI), `jinja2` (HTML report).

### Optional extras

- **JavaScript-aware crawling**:
  ```bash
  pip install playwright
  playwright install chromium
  ```
- **PDF reports**:
  ```bash
  pip install weasyprint
  ```
- **Out-of-Band (OAST) testing**:
  ```bash
  pip install interactsh
  ```

## 2. Run the Desktop GUI (default)

```bash
python main.py
```

Or launch directly:

```bash
python -m gui
```

## 3. Run the Command-Line Interface

```bash
python main.py --cli
```

The CLI prompts for the target URL, JavaScript crawling preference, POST data
and report format, then writes reports to the `reports/` folder by default.

## 4. Validation

You can run the built-in validation suite to confirm the installation is
healthy:

```bash
python test_validation.py
```

A successful run reports **0 errors / 0 warnings**.

## 5. Report output

Reports are written to a `reports/` folder in the working directory by default
(HTML, JSON, Markdown, CSV, TXT). The desktop app lets you choose a report
directory and output formats in Settings.

## Authorisation

Only test web applications you own or have explicit written permission to
assess. Unauthorised scanning is illegal in most jurisdictions. You are
responsible for the lawfulness of your usage.

## Troubleshooting

- If `python` is not found, try `python3`.
- On Windows, if `PySide6` install fails, upgrade pip first:
  ```bash
  python -m pip install --upgrade pip
  ```
- See the `project_docs/` folder for architecture and development notes, and
  `CHANGELOG.md` for version history.

Version: 5.0.0