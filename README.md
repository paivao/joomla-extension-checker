# Joomla Extension Checker

A Python tool that fetches Joomla extensions from the official Joomla Extensions Directory (JED) feed, stores them in a SQLite database with three tables, and compares local Joomla installations against the feed data.

## Features

- **Fetch Joomla Feed**: Retrieves extension data from `https://extensions.joomla.org/vel-feed`
- **SQLite Database Storage**: Stores feed data with three tables:
  - `feed`: Contains metadata about the latest feed (single row)
  - `items`: Contains all extension listings from the feed
  - `items_fts5`: Full-text search index using SQLite's FTS5 virtual table
- **Local Joomla Scanning**: Searches for installed extensions in standard Joomla directories:
  - `administrator/components/*/*.xml`
  - `administrator/modules/*/*.xml`
  - `administrator/templates/*/*/*.xml`
  - `modules/*/*.xml`
  - `components/*/*.xml`
  - `plugins/*/*/*.xml`
  - `templates/*/*/*.xml`
- **Extension Comparison**: Matches local extensions against feed data

## Installation

It only requires `requests` for now. You can install it by running

```bash
sudo apt install python3-requests
```

... or:

```bash
pip install -r requirements.txt
```

## Usage

### Help info

```
usage: main.py [-h] [--db-path DB_PATH] [--output-dir OUTPUT_DIR] [--include-core] joomla_path

Joomla Extension Checker - Compare local extensions with Joomla feed

positional arguments:
  joomla_path           Base path to Joomla installation (e.g., /var/www/html/joomla-site)

options:
  -h, --help            show this help message and exit
  --db-path DB_PATH     Path to SQLite database file (default: ./database/vel_feed.db)
  --output-dir OUTPUT_DIR
                        Directory to Output CSV files
  --include-core        Include core Joomla extensions
```

### Basic Usage

Fetch feed and scan a Joomla installation:

```bash
python3 main.py /path/to/joomla
```

### With Custom Database Path

```bash
python3 main.py /path/to/joomla --db-path ./my_extensions.db
```

### Outputing findings in CSV

Save `extensions.xml` and `findings.xml` files at `./csv-reports` (created if not exists):

```bash
python3 main.py --output-dir ./csv-reports /path/to/joomla
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
- Most entries of JED Feed doesn't came with version data, so you **MUST** check findings
