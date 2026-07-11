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
import os
import sys
from pathlib import Path

from joomla_feed_checker.feed_fetcher import fetch_and_store_feed, get_feed
from joomla_feed_checker.local_scanner import scan_joomla_extensions, JoomlaExtensionScanner
from joomla_feed_checker.db_manager import DbManager


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

    args = parser.parse_args()

    joomla_path = Path(args.joomla_path)
    db_path = args.db_path

    # Validate base path
    if not joomla_path.exists():
        print(f"Error: Base path does not exist: {joomla_path}")
        sys.exit(1)

    # Create database directory
    db_dir = Path(db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Fetch feed if requested or always fetch for comparison
    print_section_header("STEP 1: Fetching Joomla Extensions Feed")
    print("Target URL: https://extensions.joomla.org/vel-feed")
    print(f"Database: {db_path}")

    dbm = DbManager(str(db_dir))
    feed = get_feed()

    # Step 2: Scan local Joomla extensions
    print_section_header("STEP 2: Scanning Local Joomla Extensions")
    print(f"Base Path: {joomla_path}")
    print("\nSearching directories:")
    print("  - administrator/components/*//*.xml")
    print("  - administrator/modules/*//*.xml")
    print("  - modules/*//*.xml")
    print("  - plugins/*//*.xml")

    try:
        scan_result = scan_joomla_extensions(str(joomla_path))

        local_extensions = scan_result['summaries']
        raw_extensions = scan_result['raw_extensions']

        if local_extensions:
            print(f"\n✓ Found {len(local_extensions)} extension(s)")

            print_section_header("Local Extensions Found")
            for ext in local_extensions[:20]:  # Show first 20
                print(f"  [{ext['type']:8}] {ext['name']} v{ext['version'] or 'N/A'} "
                      f"by {ext['author'] or 'Unknown'}")

                if ext.get('description'):
                    desc = ext['description'][:100] + ("..." if len(ext['description']) > 100 else "")
                    print(f"    Description: {desc}")
        else:
            print("\n⚠ No extensions found in the specified directories")
            print("Make sure you are pointing to a valid Joomla installation.\n")

            # Show directory structure hint
            base_parts = joomla_path.parts[-3:]
            possible_dirs = [
                'administrator/components',
                'administrator/modules',
                'modules',
                'plugins'
            ]
            print("\nHint: Expected directory structure:")
            for part in possible_dirs:
                if part in str(joomla_path):
                    continue
                print(f"  {part}/")

    except Exception as e:
        print(f"\n✗ Error scanning extensions: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Step 3: Compare local extensions with feed data
    if fetch_result.get('success'):
        print_section_header("STEP 3: Comparing Local Extensions with Feed")

        try:
            comparison = compare_local_with_feed(local_extensions, db_path)

            print(f"Total Local Extensions: {comparison['total_local_extensions']}")
            print(f"Matched in Feed:       {comparison['matched_extensions']}")
            print(f"Not in Feed:           {comparison['not_in_feed']}")
            print(f"Feed Items:            {comparison['feed_items_count']}")

            # Show matches with risk information
            if comparison['matches']:
                print_section_header("Matched Extensions Summary")

                # Group by risk level for easier reading
                risk_groups = {
                    'High': [],
                    'Medium': [],
                    'Low': [],
                    None: []  # No known vulnerability info
                }

                for match in comparison['matches']:
                    risk_level = match.get('risk_level')
                    if risk_level and risk_level.lower() in risk_groups:
                        risk_groups[risk_level].append(match)

                # Print high risk first
                for risk_level in ['High', 'Medium', 'Low', None]:
                    if risk_level == None:
                        label = "Unknown Risk Level"
                    else:
                        label = risk_level

                    if risk_groups[label]:
                        print(f"\n--- {label} ---\n")
                        for match in risk_groups[label][:10]:  # Show first 10 per group
                            item = match['feed_item']

                            # Truncate long descriptions
                            title = match['name']
                            if item and item.get('title'):
                                title = item['title'][:80] + ("..." if len(item['title']) > 80 else "")

                            description = ""
                            if item and item.get('description'):
                                desc_text = item['description'][:120]
                                description = f"({desc_text}...)" if len(item['description']) > 120 else f"({item['description']})"

                            print(f"  * {title}")
                            if match.get('cve_id'):
                                print(f"    CVE/ID: {match['cve_id']}")
                            if match.get('risk_level'):
                                print(f"    Risk Level: {match['risk_level']}")
                            if match.get('recommendation'):
                                print(f"    Recommendation: {match['recommendation'][:60]}...")

                            # Version info
                            feed_item = item
                            if feed_item:
                                start_ver = feed_item.get('start_version') or 'all'
                                vuln_ver = feed_item.get('vulnerable_version')
                                patch_ver = feed_item.get('patch_version')
                                if vuln_ver or patch_ver:
                                    print(f"    Versions: {start_ver} - {vuln_ver or '(unknown)'} (patched: {patch_ver or 'N/A'})")

                            # Local version vs recommended
                            local_ver = match['version_local']
                            if local_ver and start_ver:
                                try:
                                    from packaging import version as pkg_version
                                    local_parsed = pkg_version.parse(local_ver)
                                    patch_parsed = pkg_version.parse(patch_ver) if patch_ver else None

                                    if patch_parsed and patch_parsed > local_parsed:
                                        print(f"    ⚠ Your version {local_ver} is OUTDATED! Update to {patch_ver}")
                                    elif patch_parsed and patch_parsed == local_parsed:
                                        print(f"    ✓ Your version {local_ver} is CURRENT")
                                except ImportError:
                                    pass

                            print()

                if len(comparison['matches']) > 20:
                    print(f"\n... and {len(comparison['matches']) - 20} more matches (showing top 20)")

                # Show CVE statistics
                cve_items = [m for m in comparison['matches'] if m.get('cve_id')]
                if cve_items:
                    print_section_header("CVE/Security Issue Summary")
                    for match in cve_items[:15]:
                        item = match['feed_item']
                        cve_ids = []
                        if item and item.get('cve_id'):
                            cve_ids.extend(item['cve_id'].split(';'))
                        print(f"  {match['name']}: {', '.join(cve_ids)}")

                    if len(cve_items) > 15:
                        print(f"\n... and {len(cve_items) - 15} more CVE entries")

            # Show not found extensions (warning only first few)
            if comparison['not_found']:
                print_section_header("Extensions Not in Feed")
                for ext in comparison['not_found'][:10]:
                    print(f"  {ext['type']}: {ext['name']} v{ext['version']} "
                          f"(author: {ext.get('author')})")

                if len(comparison['not_found']) > 10:
                    print(f"\n... and {len(comparison['not_found']) - 10} more extensions not in feed")

            # Full comparison JSON output
            print_section_header("Full Comparison Result (JSON)")
            print_json(comparison)

        except Exception as e:
            print(f"\n✗ Error during comparison: {e}")
            import traceback
            traceback.print_exc()

    # Step 4: Demonstrate FTS5 search capability
    if fetch_result.get('success') and local_extensions:
        print_section_header("STEP 4: Full-Text Search Examples")

        db_mgr = DbManager(db_path)

        test_queries = ['contact form', 'administrator', 'com_content']
        for query in test_queries:
            results = db_mgr.search_extensions_fts(query)
            if results:
                print(f"\nSearch for: '{query}' -> {len(results)} results")
                for item in results[:3]:
                    title_match = f"Title match: {item['title']}"
                    desc_match = f"Desc match: {item['description'][:60]}..." if item.get('description') else ""
                    print(f"  - {title_match}")
                    if desc_match:
                        print(f"    {desc_match}")

        # Example with user's specific term
        print("\n\nYou can search any term found in extension titles/descriptions:")
        print("  db_manager.search_extensions_fts('your_search_term')")

    # Summary
    print_section_header("Summary")
    print(f"✓ Feed: https://extensions.joomla.org/vel-feed")
    print(f"✓ Database: {db_path}")
    print(f"✓ Local Extensions Found: {len(local_extensions)}")
    print(f"✓ Feed Items Stored: {comparison['feed_items_count'] if 'comparison' in locals() else 0}")

    # FTS5 virtual table info
    if 'comparison' in locals():
        conn = DbManager(db_path).get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM items_fts5")
            count = cursor.fetchone()[0]
            print(f"✓ FTS5 Index Entries: {count}")
        finally:
            conn.close()

    print(f"\n✓ Comparison complete!")
    print(f"\nTo compare your local installations against the feed, you now have:")
    print("  - Feed data in SQLite database at: {db_path}")
    print("  - FTS5 virtual table for fast full-text search")
    print("  - Matched extensions with risk levels and recommendations")


if __name__ == '__main__':
    main()
