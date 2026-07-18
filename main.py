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
from joomla_feed_checker.local_scanner import JoomlaExtensionScanner
from joomla_feed_checker.db_manager import DbManager
from joomla_feed_checker.models import CVEEntry, ExtensionMetadata, FeedItem
from joomla_feed_checker.nvd_fetcher import load_cves
from joomla_feed_checker.utils import print_section_header, write_csv_file


def print_json(data: dict, indent: int = 2):
    """Pretty print JSON data."""
    print(json.dumps(data, indent=indent))


def main():
    parser = argparse.ArgumentParser(
        description='Joomla Extension Checker - Compare local extensions with Joomla feed'
    )
    parser.add_argument(
        'joomla_path',
        help='Base path to Joomla installation (e.g., /var/www/html/joomla-site)'
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
    parser.add_argument(
        '--include-core',
        action='store_true',
        help='Include core Joomla extensions'
    )

    args = parser.parse_args()

    joomla_path = Path(args.joomla_path)
    db_path = args.db_path
    output_dir = args.output_dir
    filter_core = not args.include_core

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
        cves = load_cves(dbm)
    print(f"Feed version: {feed.api_version}")
    print(f"CVEs found: {len(cves)}")

    # Step 2: Scan local Joomla extensions
    print_section_header("STEP 2: Scanning Local Joomla Extensions")
    print(f"Base Path: {joomla_path}")

    local_extensions: dict[str, ExtensionMetadata] = {}
    try:
        scanner = JoomlaExtensionScanner(joomla_path, filter_core=filter_core)
        print(f"\n[+] Joomla! version = {scanner.get_joomla_version()}")
        extensions = scanner.scan_por_packages() + scanner.scan_for_extensions()
        if output_dir:
            write_csv_file(str(output_dir / "extensions.csv"), extensions)
        print(f"\n[+] Found {len(extensions)} packages and extensions:\n")

        for ext in extensions:
            local_extensions[ext.name] = ext
            print(ext.format(),end='\n\n')

        if len(extensions) == 0:
            print("\n⚠ No extensions found in the specified directories")
            print("Make sure you are pointing to a valid Joomla installation.\n")
            sys.exit(1)

    except Exception as e:
        print(f"\n[!] Error scanning extensions: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print_section_header("STEP 3: Searching Joomla VEL for vunerable entries")
    vuln_findings: dict[str,set[tuple[FeedItem, float]]] = {}
    with dbm:
        for ext in local_extensions.values():
            vuln_findings[ext.name] = set(dbm.search_extensions_fts(ext.name))
            #if ext.author:
            #    vuln_findings[ext.name] += dbm.search_extensions_fts(ext.author)
            if ext.description:
                vuln_findings[ext.name] |= set(dbm.search_extensions_fts(ext.description))
            if len(vuln_findings[ext.name]) == 0:
                vuln_findings.pop(ext.name)

    for ext, findings in vuln_findings.items():
        print(f"\n[+] Found this data for extension {ext} ({local_extensions[ext].version}) @ \"{local_extensions[ext].xml_path}\"\n")
        _sorted_findings = sorted(findings, key=lambda x: x[1], reverse=True)
        for item, score in _sorted_findings:
            print(f"(score={score}) {item.format()}\n")
        if output_dir:
            write_csv_file(str(output_dir / "findings.csv"), [_sf[0] for _sf in _sorted_findings])

    print_section_header("STEP 4: Searching NVD CVE for vunerable entries")
    cves_findings: dict[str,set[tuple[CVEEntry, float]]] = {}
    with dbm:
        for ext in local_extensions.values():
            cves_findings[ext.name] = set(dbm.search_cves_fts(ext.name))
            if ext.description:
                cves_findings[ext.name] |= set(dbm.search_cves_fts(ext.description))
            if len(cves_findings[ext.name]) == 0:
                cves_findings.pop(ext.name)

    for ext, findings in cves_findings.items():
        print(f"\n[+] Found this data for extension {ext} ({local_extensions[ext].version}) @ \"{local_extensions[ext].xml_path}\"\n")
        _sorted_findings = sorted(findings, key=lambda x: x[1], reverse=True)
        for item, score in _sorted_findings:
            print(f"(score={score}) [{item.id}] {item.description}\n")
        if output_dir:
            write_csv_file(str(output_dir / "cves.csv"), [_sf[0] for _sf in _sorted_findings])

    print_section_header("FINISHED: Remember to visit links and check")
    print("[*] Many entries from Joomla Vunerable Extensions Feed lack version, so comparison is not implemented yet")

if __name__ == '__main__':
    main()
