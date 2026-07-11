# Joomla Extension Checker

A Python tool that fetches Joomla extensions from the official Joomla Extensions Directory (JED) feed, stores them in a SQLite database with three tables, and compares local Joomla installations against the feed data.

## Features

- **Fetch Joomla Feed**: Retrieves extension data from `https://extensions.joomla.org/vel-feed`
- **SQLite Database Storage**: Stores feed data with three tables:
  - `feed`: Contains metadata about the latest feed (single row)
  - `items`: Contains all extension listings from the feed
  - `items_fts5`: Full-text search index using SQLite's FTS5 virtual table
- **Local Joomla Scanning**: Searches for installed extensions in standard Joomla directories:
  - `administrator/components/*//*.xml`
  - `administrator/modules/*//*.xml`
  - `modules/*//*.xml`
  - `plugins/*//`.xml (recursive)
- **Extension Comparison**: Matches local extensions against feed data
- **Risk Assessment**: Identifies vulnerable extensions with CVE IDs, CVSS scores, and recommendations

## Installation

```bash
pip install -r requirements.txt
```

Note: The `packaging` package is used for version comparison and will be installed automatically when running the tool.

## Usage

### Basic Usage

Fetch feed and scan a Joomla installation:

```bash
python main.py /path/to/joomla
```

### With Custom Database Path

```bash
python main.py /path/to/joomla --db-path ./my_extensions.db
```

### Fetch Latest Feed Before Scanning

```bash
python main.py /path/to/joomla --fetch
```

## Database Schema

The tool creates a SQLite database with the following structure:

### feed Table (1 row)

| Column | Type | Description |
|--------|------|-------------|
| api_version | TEXT | API version string |
| api_version_name | TEXT | Human-readable version name |
| timestamp | TEXT | ISO8601 timestamp of last update |
| license | TEXT | Feed data is licensed under GPL |
| checksum | TEXT | SHA256 lowercase hex digest |

### items Table (many rows)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key, feed listing ID |
| title | TEXT | Extension name with vulnerable versions |
| description | TEXT | Additional info including version notes |
| status | INTEGER | 1 = live, 2 = resolved |
| jed | TEXT | URL of JED listing if available |
| cve_id | TEXT | CVE and vulnerability tracking IDs |
| cwe_id | TEXT | CWE classification IDs |
| risk_level | TEXT | low, medium, high |
| recommendation | TEXT | User recommendations (e.g., update) |
| cvss30_base | TEXT | CVSS 3.0 vector string |
| cvss30_base_score | TEXT | CVSS 3.0 numeric score |
| start_version | TEXT | First vulnerable version |
| vulnerable_version | TEXT | Most recent vulnerable version |
| patch_version | TEXT | Version where vulnerability is patched |
| update_notice | TEXT | Developer's update notice URL |
| install_data | TEXT | JSON installation data from manifest |
| created | TEXT | ISO8601 creation date |
| modified | TEXT | ISO8601 modification date |
| statusText | TEXT | "Live" or "Resolved" |

### items_fts5 (Virtual Table)

FTS5 virtual table containing full-text index of `title` and `description` fields for fast searching.

## API Response Format

The tool expects the Joomla feed response in this format:

```json
{
  "success": true,
  "data": {
    "api_version": "...",
    "api_version_name": "...",
    "timestamp": "...",
    "license": "...",
    "items": [...]
  }
}
```

Each item contains vulnerability information and extension metadata as specified in the Joomla Extensions API documentation.

## Search Examples

### Full-Text Search

Use FTS5 to search for extensions by title or description:

```python
from joomla_feed_checker.db_manager import DbManager

db = DbManager('./database/vel_feed.db')

# Search for "contact form"
results = db.search_extensions_fts('contact form')
for item in results:
    print(f"Found: {item['title']}")
```

### Get Live Extensions Only

```python
live_extensions = db.get_live_extensions()
```

### Get Vulnerable Extensions

```python
vulnerable = db.get_vulnerable_extensions()
for ext in vulnerable:
    print(f"{ext['title']} - CVE: {ext.get('cve_id')}")
```

## Directory Structure

```
joomla-extension-checker/
├── main.py                      # Main entry point
├── requirements.txt             # Python dependencies
├── README.md                    # This file
└── src/
    └── joomla_feed_checker/
        ├── __init__.py         # Package init
        ├── feed_fetcher.py     # Feed fetching and DB population
        ├── local_scanner.py    # Local extension scanning
        └── db_manager.py       # Database operations and comparison
```

## Example Output

The tool produces comprehensive output including:

- Feed metadata (API version, timestamp, checksum)
- List of found extensions with type, name, author, version
- Risk levels for each matching extension
- CVE IDs and vulnerability information
- Recommendations for handling vulnerable extensions
- Version comparison (outdated/current status)
- FTS5 search statistics

## License

This tool is distributed under the GPL license as per the Joomla Extensions API feed.

## Notes

- Only XML files with root element `extension` are processed
- Checksum verification is performed after each fetch
- FTS5 virtual table is automatically maintained via triggers
- The tool handles NULL values gracefully for optional fields
- CVSS 3.0 scoring helps prioritize security issues
