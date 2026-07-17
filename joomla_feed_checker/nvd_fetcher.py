# Configuration
from datetime import datetime, timedelta
from typing import Any, Optional

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORD_SEARCH = "Joomla"
MAX_DAYS_WINDOW = 100  # Maximum days to look back for incremental fetches

def fetch_cves_from_api(
    pub_start_date: Optional[datetime] = None,
    results_per_page: int = 2000,
) -> tuple[list[Any], Optional[datetime]]:
    """Fetch CVEs from NVD API with Joomla keyword search."""

    params = {
        "keywordSearch": KEYWORD_SEARCH,
        "resultsPerPage": results_per_page,
        "startIndex": 0
    }
    if pub_start_date is not None:
        pub_end_date = pub_start_date + timedelta(days=MAX_DAYS_WINDOW)
        params.update({
            "pubStartDate": pub_start_date.isoformat(timespec='seconds'),
            "pubEndDate": pub_end_date.isoformat(timespec='seconds')
        })

    cves = []
    fetch_time: Optional[datetime] = None
    try:
        while True:
            response = requests.get(NVD_API_URL, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()
            cves += data['vulnerabilities']
            fetch_time = datetime.strptime(data['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z")
            if len(cves) == data['totalResults']:
                return cves, fetch_time
    except requests.RequestException as e:
        print(f"Error fetching data from NVD API: {e}")
        return [], None
