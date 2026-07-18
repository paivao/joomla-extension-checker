# Configuration
from datetime import datetime, timedelta
from typing import Any, Optional

import requests

from joomla_feed_checker.db_manager import DbManager
from joomla_feed_checker.models import CVEEntry


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORD_SEARCH = "Joomla"
MAX_DAYS_WINDOW = 120  # Maximum days to look back for incremental fetches

def __fetch_cves_from_api(
    since: Optional[datetime] = None,
    api_key: Optional[str] = None,
    results_per_page: int = 2000,
) -> list[CVEEntry]:
    """Fetch CVEs from NVD API with Joomla keyword search."""

    params = {
        "keywordSearch": KEYWORD_SEARCH,
        "resultsPerPage": results_per_page,
        "startIndex": 0
    }
    headers = None
    if api_key is not None:
        headers = {
            "apiKey": api_key
        }
    if since is not None:
        end_time = since + timedelta(days=MAX_DAYS_WINDOW)
        params.update({
            "pubStartDate": since.isoformat(timespec='seconds'),
            "pubEndDate": end_time.isoformat(timespec='seconds')
        })

    cves = []
    print()
    try:
        while True:
            response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()
            cves += [CVEEntry.from_api(entry['cve']) for entry in data['vulnerabilities']]
            if len(cves) == data['totalResults']:
                return cves
            params["startIndex"] += results_per_page
    except requests.RequestException as e:
        print(f"Error fetching data from NVD API: {e}")
        return []

def __loop_api_fetch(
    since: Optional[datetime] = None,
    api_key: Optional[str] = None,
    results_per_page: int = 2000,
) -> list[CVEEntry]:
    if since is None:
        return __fetch_cves_from_api(since, api_key, results_per_page)
    now = datetime.now()
    cves = []
    while since < now:
        cves += __fetch_cves_from_api(since, api_key, results_per_page)
        since += timedelta(days=120)
    return cves

def load_cves(
    dbm: DbManager,
    api_key: Optional[str] = None,
    results_per_page: int = 2000
) -> list[CVEEntry]:
    with dbm:
        last_inserted = dbm.get_last_modified_cve()
        old_cves = dbm.get_cves()
        new_cves = __loop_api_fetch(last_inserted, api_key, results_per_page)
        print("[+] New CVEs:", dbm.save_cves_to_db(new_cves))
        return old_cves + new_cves
