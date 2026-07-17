#!/usr/bin/env python3
"""
NVD CVE Fetcher for Joomla Vulnerabilities

Fetches CVE data from NVD API v2.0 with keywordSearch="Joomla",
saves to SQLite database with FTS5 index over descriptions.
"""

import os
import sqlite3
from datetime import datetime, timedelta
import requests
import json
from typing import Optional, List, Dict, Any


# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORD_SEARCH = "Joomla"
MAX_DAYS_WINDOW = 100  # Maximum days to look back for incremental fetches
DB_PATH = "joomla_cve_database.sqlite"


def fetch_cves_from_api(
    pub_start_date: Optional[datetime] = None,
    start_index: int = 0,
    results_per_page: int = 2000,
) -> Optional[Dict[str, Any]]:
    """Fetch CVEs from NVD API with Joomla keyword search."""
    params = {
        "keywordSearch": KEYWORD_SEARCH,
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }
    if pub_start_date is not None:


    try:
        response = requests.get(NVD_API_URL, params=params, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching data from NVD API: {e}")
        return None


def get_latest_cve_published_date(
    cves_data: Dict[str, Any],
    page_size: int = 2000
) -> Optional[str]:
    """Get the latest published date from the fetched CVEs."""
    if not cves_data or "vulnerabilities" not in cves_data:
        return None

    # Sort by published date descending and get the first one
    vulns = sorted(cves_data["vulnerabilities"],
                   key=lambda x: x.get("published", ""),
                   reverse=True)

    if vulns:
        latest_cve = vulns[0]
        return latest_cve.get("published")
    return None


def process_descriptions(descriptions: List[Dict[str, str]]) -> Optional[str]:
    """
    Process descriptions to find the English one.
    Returns the value of the first English description found.
    """
    if not descriptions:
        return None

    # Look for English language variants
    english_key = "en"
    lang_map = {
        "en": "English",
        "en-US": "English (United States)",
        "en-GB": "English (United Kingdom)"
    }

    # Try to find any English variant
    for desc in descriptions:
        lang = desc.get("lang", "")
        if lang.lower() == english_key.lower():
            return desc.get("value")

        # Check for common English variants
        if lang.lower() in lang_map.values():
            return desc.get("value")

    # If no explicit English, take the first one (usually English is first)
    return descriptions[0].get("value")


def create_database(db_path: str) -> None:
    """Create SQLite database with FTS5 index on descriptions."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create table for CVE records
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cve_records (
        cve_id TEXT PRIMARY KEY,
        source_identifier TEXT,
        vuln_status TEXT,
        published DATETIME NOT NULL,
        last_modified DATETIME NOT NULL,
        evaluator_comment TEXT,
        evaluator_solution TEXT,
        evaluator_impact TEXT,
        cisa_exploit_add DATE,
        cisa_action_due DATE,
        cisa_required_action TEXT,
        cisa_vulnerability_name TEXT,
        cve_tags TEXT,
        description TEXT NOT NULL,
        references TEXT NOT NULL,
        cvss_metrics_json TEXT,
        affected_json TEXT,
        weaknesses TEXT,
        configurations TEXT,
        vendor_comments TEXT
    )
    ''')

    # Create FTS5 virtual table for full-text search on English descriptions
    cursor.execute('''
    CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts_search USING fts5(
        description,
        content='cve_records',
        content_rowid='cve_id'
    )
    ''')

    # Create trigger to automatically populate FTS5 table when a new record is added/updated
    cursor.execute('''
    CREATE TRIGGER IF NOT EXISTS cve_fts_search_ai AFTER INSERT ON cve_records BEGIN
        INSERT INTO cve_fts_search(rowid, descriptions_text)
        VALUES(NEW.rowid, NEW.descriptions_json);
    END
    ''')

    cursor.execute('''
    CREATE TRIGGER IF NOT EXISTS cve_fts_search_ad AFTER DELETE ON cve_records BEGIN
        DELETE FROM cve_fts_search WHERE rowid = OLD.rowid;
    END
    ''')

    cursor.execute('''
    CREATE TRIGGER IF NOT EXISTS cve_fts_search_ud AFTER UPDATE ON cve_records BEGIN
        DELETE FROM cve_fts_search WHERE rowid = NEW.rowid;
        INSERT INTO cve_fts_search(rowid, descriptions_text)
        VALUES(NEW.rowid, NEW.descriptions_json);
    END
    ''')

    conn.commit()
    conn.close()


def save_cve_record(conn: sqlite3.Connection, cve_data: Dict[str, Any]) -> None:
    """Insert or update a CVE record in the database."""
    cursor = conn.cursor()

    # Extract English description
    descriptions = cve_data.get("descriptions", [])
    _ = process_descriptions(descriptions)

    try:
        cursor.execute('''
        INSERT OR REPLACE INTO cve_records (
            cve_id, source_identifier, vuln_status, published, last_modified,
            evaluator_comment, evaluator_solution, evaluator_impact,
            cisa_exploit_add, cisa_action_due, cisa_required_action,
            cisa_vulnerability_name, descriptions_json, references,
            cvss_metrics_json, affected_json, weaknesses, configurations,
            vendor_comments
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cve_data.get("id"),
            cve_data.get("sourceIdentifier"),
            cve_data.get("vulnStatus"),
            cve_data.get("published"),
            cve_data.get("lastModified"),
            cve_data.get("evaluatorComment"),
            cve_data.get("evaluatorSolution"),
            cve_data.get("evaluatorImpact"),
            cve_data.get("cisaExploitAdd"),
            cve_data.get("cisaActionDue"),
            cve_data.get("cisaRequiredAction"),
            cve_data.get("cisaVulnerabilityName"),
            json.dumps(descriptions) if descriptions else None,
            json.dumps(cve_data.get("references")) if cve_data.get("references") else None,
            json.dumps(cve_data.get("metrics")) if cve_data.get("metrics") else None,
            json.dumps(cve_data.get("affected")) if cve_data.get("affected") else None,
            json.dumps(cve_data.get("weaknesses")) if cve_data.get("weaknesses") else None,
            json.dumps(cve_data.get("configurations")) if cve_data.get("configurations") else None,
            json.dumps(cve_data.get("vendorComments")) if cve_data.get("vendorComments") else None
        ))
        conn.commit()
    except sqlite3.IntegrityError as e:
        # Handle duplicate CVE IDs gracefully
        print(f"Duplicate CVE ID {cve_data.get('id')}: {e}")


def get_latest_published_from_db(conn: sqlite3.Connection) -> Optional[str]:
    """Get the latest published date from database."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT MAX(CAST(SUBSTR(published, 1, 10) AS DATE)) FROM cve_records"
    )
    result = cursor.fetchone()[0]
    return result


def fetch_incremental_cves(db_path: str) -> int:
    """
    Fetch only newer CVEs based on published date window.
    Returns the number of CVEs fetched.
    """
    conn = sqlite3.connect(db_path)

    try:
        # Get latest published date from database
        latest_db_date_str = get_latest_published_from_db(conn)

        if latest_db_date_str:
            latest_db_date = parse_date(latest_db_date_str)
            # Calculate the start date (100 days ago from latest)
            window_start = latest_db_date - timedelta(days=MAX_DAYS_WINDOW)
            window_start_str = window_start.strftime("%Y-%m-%d")
            print(f"Latest CVE in DB: {latest_db_date_str}")
            print(f"Fetching CVEs published between {window_start_str} and today...")
        else:
            print("No CVEs found in database. Fetching all available...")
            window_start_str = None
    finally:
        conn.close()

    # Fetch from API
    cve_data = fetch_cves_from_api(start_index=0, results_per_page=2000)

    if not cve_data or "vulnerabilities" not in cve_data:
        print("No new CVEs to fetch.")
        return 0

    total_results = cve_data.get("totalResults", 0)
    results_per_page = cve_data.get("resultsPerPage", 0)

    # If there are no results, we're up to date
    if total_results <= results_per_page:
        print(f"No new CVEs found. Total API results: {total_results}")
        return 0

    vulnerabilities = cve_data["vulnerabilities"]
    print(f"Fetched {len(vulnerabilities)} new CVEs")

    # Save to database
    conn = sqlite3.connect(db_path)
    for cve in vulnerabilities[:results_per_page]:
        save_cve_record(conn, cve)
    conn.close()

    return len(vulnerabilities)


def fetch_all_cves(db_path: str) -> int:
    """Fetch all CVEs and save to database."""
    print("Fetching all CVEs from NVD API...")

    # Create or ensure database exists
    create_database(db_path)

    conn = sqlite3.connect(db_path)

    cve_data = fetch_cves_from_api(start_index=0, results_per_page=2000)

    if not cve_data or "vulnerabilities" not in cve_data:
        print("Error fetching data from NVD API")
        return 0

    total_results = cve_data.get("totalResults", 0)
    results_per_page = cve_data.get("resultsPerPage", 0)

    vulnerabilities = cve_data["vulnerabilities"]

    if len(vulnerabilities) < results_per_page and total_results == len(vulnerabilities):
        # All CVEs fit in one page
        for cve in vulnerabilities:
            save_cve_record(conn, cve)
        conn.close()
        print(f"Fetched and saved {len(vulnerabilities)} CVEs")
        return len(vulnerabilities)
    else:
        # Multiple pages - fetch all
        all_vulnerabilities = []
        for start_index in range(0, total_results + 1, results_per_page):
            print(f"Fetching page starting at {start_index}...")
            cve_data = fetch_cves_from_api(start_index=start_index, results_per_page=results_per_page)
            if cve_data and "vulnerabilities" in cve_data:
                all_vulnerabilities.extend(cve_data["vulnerabilities"])
                print(f"  Retrieved {len(cve_data['vulnerabilities'])} CVEs")
            else:
                break

        conn.close()

        # Re-connect and save all
        conn = sqlite3.connect(db_path)
        for cve in all_vulnerabilities:
            save_cve_record(conn, cve)
        conn.close()

        print(f"Fetched and saved {len(all_vulnerabilities)} CVEs total")
        return len(all_vulnerabilities)


def get_statistics(db_path: str) -> Dict[str, Any]:
    """Get statistics about stored CVEs."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM cve_records")
    total_cves = cursor.fetchone()[0]

    cursor.execute("SELECT MIN(published), MAX(published) FROM cve_records")
    date_range = cursor.fetchone()

    cursor.execute("""
        SELECT COUNT(DISTINCT SUBSTR(id, 1, 7))
        FROM cve_records
        WHERE id LIKE 'CVE-%%'
    """)
    years_covered = cursor.fetchone()[0]

    conn.close()

    return {
        "total_cves": total_cves,
        "date_range": date_range if date_range else None,
        "years_covered": years_covered
    }


def search_fts(description_keyword: str, db_path: str) -> List[Dict[str, Any]]:
    """Search CVE descriptions using FTS5."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Search in the FTS5 table
    cursor.execute("""
        SELECT cve_records.id,
               SUBSTR(cve_records.published, 1, 10) as published_date,
               cve_records.cve_id
        FROM cve_fts_search
        JOIN cve_records ON cve_fts_search.rowid = cve_records.id
        WHERE cve_fts_search.descriptions_text MATCH ?
    """, ('"' + description_keyword + '"',))

    results = cursor.fetchall()
    conn.close()
    return [
        {"id": row[0], "published_date": row[1], "cve_id": row[2]}
        for row in results
    ]


def main():
    """Main entry point."""

    print("=" * 60)
    print("NVD CVE Fetcher for Joomla Vulnerabilities")
    print("=" * 60)
    print()

    if not os.path.exists(DB_PATH):
        print(f"Creating database at {DB_PATH}...")
        create_database(DB_PATH)

    # Check if we need to fetch all or just incremental
    if not os.path.exists(DB_PATH) or get_latest_published_date(DB_PATH) is None:
        print("No existing data found. Fetching all CVEs...")
        num_fetched = fetch_all_cves(DB_PATH)
    else:
        print("Existing data found. Fetching incremental updates...")
        num_fetched = fetch_incremental_cves(DB_PATH)

    if num_fetched > 0:
        stats = get_statistics(DB_PATH)
        print()
        print("Database Statistics:")
        print(f"  Total CVEs stored: {stats['total_cves']}")
        date_display = f"{stats['date_range'][0]} to {stats['date_range'][1]}" if stats['date_range'] else "N/A"
        print(f"  Date range: {date_display}")

    # Show latest CVEs
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cve_id, SUBSTR(published, 1, 10) as published_date
        FROM cve_records
        ORDER BY published DESC
        LIMIT 5
    """)
    latest_cves = cursor.fetchall()
    print()
    print("Latest CVEs in database:")
    for cve in latest_cves:
        print(f"  {cve[0]} (published: {cve[1]})")
    conn.close()


if __name__ == "__main__":
    main()
