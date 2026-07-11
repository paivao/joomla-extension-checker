#!/usr/bin/env python3
"""
Test script for Joomla Extension Checker.
Demonstrates usage without requiring actual Joomla installation path.
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from joomla_feed_checker.feed_fetcher import fetch_and_store_feed, calculate_checksum


def print_section_header(title: str):
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def test_fetch_feed():
    """Test fetching the Joomla feed."""
    print_section_header("TEST 1: Fetch Joomla Feed")
    
    try:
        result = fetch_and_store_feed(
            db_path="./test_database/vel_feed.db",
            url="https://extensions.joomla.org/vel-feed"
        )
        
        if result.get('success'):
            print(f"\n✓ Test passed!")
            print(f"  API Version: {result['api_version']} ({result['api_version_name']})")
            print(f"  Items Count: {result['items_count']}")
            
            # Show feed info from database
            return True
        else:
            print("\n✗ Feed fetch had issues")
            return False
            
    except Exception as e:
        print(f"\n✗ Error fetching feed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_database_operations():
    """Test database operations after feed fetch."""
    if not Path("./test_database/vel_feed.db").exists():
        print_section_header("TEST 2: Database Operations (Fetch First)")
        if not test_fetch_feed():
            return False
    
    print_section_header("TEST 2: Database Operations")
    
    from joomla_feed_checker.db_manager import DbManager
    
    db_mgr = DbManager("./test_database/vel_feed.db")
    
    # Test feed info retrieval
    print("\n--- Feed Info ---")
    feed_info = db_mgr.get_feed_info()
    if feed_info:
        for key, value in feed_info.items():
            if value:
                print(f"  {key}: {value}")
    
    # Test getting live extensions count
    print("\n--- Live Extensions Count ---")
    live_extensions = db_mgr.get_live_extensions()
    print(f"  Live extensions: {len(live_extensions)}")
    
    # Test getting vulnerable extensions count
    print("\n--- Vulnerable Extensions Count ---")
    vulnerable = db_mgr.get_vulnerable_extensions()
    print(f"  Vulnerable extensions: {len(vulnerable)}")
    
    # Test FTS5 search
    print("\n--- FTS5 Search Demo ---")
    test_terms = ['content', 'contact', 'administrator']
    for term in test_terms[:1]:
        results = db_mgr.search_extensions_fts(term)
        if results and len(results) > 0:
            print(f"  Searching '{term}': found {len(results)} items")
    
    return True


def test_local_scanner_demo():
    """Demonstrate local scanner usage (without actual scan)."""
    print_section_header("TEST 3: Local Scanner Demo")
    
    # Show how to use the scanner
    from joomla_feed_checker.local_scanner import JoomlaExtensionScanner
    
    print("""
The local scanner can be used as follows:

    scanner = JoomlaExtensionScanner('/path/to/joomla')
    raw_extensions = scanner.scan_for_extensions()
    summaries = scanner.get_extension_summary(raw_extensions)
    
    for ext in summaries:
        print(f"{ext['type']:12} | {ext['name'][:40]:40} | v{ext['version']}")

Supported paths:
  - administrator/components/*//*.xml
  - administrator/modules/*//*.xml  
  - modules/*//*.xml
  - plugins/*//*.xml (recursive)
    
The scanner only processes files where the root element is 'extension'.
    """)
    
    return True


def test_full_workflow():
    """Run full workflow: fetch feed and demonstrate comparison."""
    print_section_header("TEST 4: Full Workflow Demo")
    
    from joomla_feed_checker.db_manager import DbManager
    
    # Fetch or update feed
    if not Path("./test_database/vel_feed.db").exists():
        print("Creating database and fetching feed...")
        fetch_and_store_feed(
            db_path="./test_database/vel_feed.db",
            url="https://extensions.joomla.org/vel-feed"
        )
    
    # Get comparison-ready data
    db_mgr = DbManager("./test_database/vel_feed.db")
    
    print("\n--- Database Status ---")
    feed_info = db_mgr.get_feed_info()
    if feed_info:
        print(f"  Feed version: {feed_info['api_version_name']}")
        print(f"  Items stored: {len(db_mgr.get_all_feed_items())}")
    
    return True


def main():
    """Run all tests."""
    print("="*60)
    print(" Joomla Extension Checker - Test Suite")
    print("="*60)
    
    # Clean up previous test database if exists
    db_path = Path("./test_database/vel_feed.db")
    if db_path.exists():
        try:
            import os
            os.remove(db_path)
            print(f"Removed existing test database: {db_path}")
        except Exception as e:
            print(f"Note: Could not remove existing database: {e}")
    
    # Create directories
    Path("./test_database").mkdir(exist_ok=True)
    
    tests = [
        ("Fetch Feed Test", test_fetch_feed),
        ("Database Operations", lambda: test_database_operations()),
        ("Local Scanner Demo", test_local_scanner_demo),
        ("Full Workflow", test_full_workflow),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ Test '{name}' failed with error: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print_section_header("Test Summary")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"\n  Total tests: {total}")
    print(f"  Passed:      {passed}")
    print(f"  Failed:      {total - passed}")
    
    if passed == total:
        print("\n✓ All tests completed successfully!")
    else:
        print(f"\n⚠ Some tests failed. Check output above for details.")


if __name__ == '__main__':
    main()
