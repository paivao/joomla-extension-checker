#!/usr/bin/env python3
"""
Joomla Extension Checker - Main Entry Point

This tool fetches the Joomla extensions feed from https://extensions.joomla.org/vel-feed,
stores it in a SQLite database with three tables (feed, items, fts5), and compares
local Joomla extensions against the feed data.

Usage:
    python main.py <joomla_path> [--db-path PATH] [--fetch]

Arguments:
    joomla_path   Base path to Joomla installation (e.g., C:/xampp/htdocs/myjooml)
    --db-path     Path to SQLite database (default: ./database/vel_feed.db)
    --fetch       Fetch latest feed from URL before scanning

Examples:
    python main.py /path/to/joomla
    python main.py /path/to/joomla --db-path ./extensions.db
    python main.py /path/to/joomla --fetch
"""

import argparse
import json
import sys
from pathlib import Path

from joomla_feed_checker.feed_fetcher import get_feed
from joomla_feed_checker.local_scanner import scan_joomla_extensions
from joomla_feed_checker.db_manager import DbManager
from joomla_feed_checker.models import ExtensionMetadata, FeedItem
from joomla_feed_checker.utils import write_csv_file


def print_section_header(title: str):
    """Print a formatted section header."""
    print(f"\n{'='*80}")
    print(f" {title}")
    print('='*80)


def print_json(data: dict, indent: int = 2):
    """Pretty print JSON data."""
    print(json.dumps(data, indent=indent))


def main():
    parser = argparse.ArgumentParser(
        description='Joomla Extension Checker - Compare local extensions with Joomla feed'
    )
    parser.add_argument(
        'joomla_path',
        help='Base path to Joomla installation (e.g., C:/xampp/htdocs/myjoomla)'
    )
    parser.add_argument(
        '--db-path',
        default='./database/vel_feed.db',
        help='Path to SQLite database file (default: ./database/vel_feed.db)'
    )
    parser.add_argument(
        '--output-dir',
        help='Directory to Output CSV files'
    )

    args = parser.parse_args()

    joomla_path = Path(args.joomla_path)
    db_path = args.db_path
    output_dir = args.output_dir

    # Validate base path
    if not joomla_path.exists():
        print(f"Error: Base path does not exist: {joomla_path}")
        sys.exit(1)

    # Create database directory
    db_dir = Path(db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    # Create output_dir if exists
    if output_dir:
        output_dir = Path(output_dir)
        if not output_dir.exists():
            print(f"Creating directory {output_dir}")
            output_dir.mkdir(parents=True, exist_ok=True)
        elif not output_dir.is_dir():
            print(f"Error: {output_dir} is not a directory, ignoring...")
            output_dir = None


    # Step 1: Fetch feed if requested or always fetch for comparison
    print_section_header("STEP 1: Fetching Joomla Extensions Feed")
    print("Target URL: https://extensions.joomla.org/vel-feed")
    print(f"Database: {db_path}")

    dbm = DbManager(str(db_path))
    with dbm:
        dbm.create_database()
        feed = get_feed(dbm)
    print(f"Feed version: {feed.api_version}")

    # Step 2: Scan local Joomla extensions
    print_section_header("STEP 2: Scanning Local Joomla Extensions")
    print(f"Base Path: {joomla_path}")
    print("\nSearching directories:")
    print("  - administrator/components/*/*.xml")
    print("  - administrator/modules/*/*.xml")
    print("  - administrator/templates/*/*.xml")
    print("  - modules/*/*.xml")
    print("  - components/*/*.xml")
    print("  - plugins/*/*/*.xml")
    print("  - templates/*/*/*.xml")

    local_extensions: dict[str, ExtensionMetadata] = {}
    try:
        extensions = scan_joomla_extensions(joomla_path)
        if output_dir:
            write_csv_file(str(output_dir / "extensions.csv"), extensions)
        print(f"\n✓ Found {len(extensions)} extension(s)")

        for ext in extensions:
            local_extensions[ext.name] = ext
            print(ext.format())

        if len(extensions) == 0:
            print("\n⚠ No extensions found in the specified directories")
            print("Make sure you are pointing to a valid Joomla installation.\n")
            sys.exit(1)

    except Exception as e:
        print(f"\n✗ Error scanning extensions: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    vuln_findings: dict[str,set[tuple[FeedItem, float]]] = {}
    with dbm:
        for ext in local_extensions.values():
            vuln_findings[ext.name] = set(dbm.search_extensions_fts(ext.name))
            #if ext.author:
            #    vuln_findings[ext.name] += dbm.search_extensions_fts(ext.author)
            if ext.description:
                vuln_findings[ext.name] |= set(dbm.search_extensions_fts(ext.name))
            if len(vuln_findings[ext.name]) == 0:
                vuln_findings.pop(ext.name)

    print("Showing findings:")
    for ext, findings in vuln_findings.items():
        print(f"Found this data for extension {ext} ({local_extensions[ext].version}): {local_extensions[ext].xml_path}")
        _sorted_findings = sorted(findings, key=lambda x: x[1], reverse=True)
        for item, score in _sorted_findings:
            print(f"(score={score}) {item.format()}")
        if output_dir:
            write_csv_file(str(output_dir / "findings.csv"), [_sf[0] for _sf in _sorted_findings])

if __name__ == '__main__':
    main()
