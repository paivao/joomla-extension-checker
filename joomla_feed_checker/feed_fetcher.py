"""
Feed Fetcher module for Joomla Extensions API.
Fetches the feed from https://extensions.joomla.org/vel-feed and populates SQLite database.
"""

import json
import requests
from joomla_feed_checker.db_manager import DbManager
from .models import Feed


BASE_FEED_URL = "https://extensions.joomla.org/vel-feed"
BASE_VERIFY_URL = "https://extensions.joomla.org/vel-verify"


def fetch_feed(url: str = BASE_FEED_URL) -> Feed:
    """
    Fetch the Joomla extensions feed from URL.

    Args:
        url: The feed URL to fetch (default is vel-feed)

    Returns:
        Dictionary containing success status and data from feed

    Raises:
        ValueError: If response is not successful or data format is invalid
    """
    try:
        with requests.get(url) as response:
            if response.status_code != 200:
                raise ValueError(f"Failed to fetch feed. HTTP status: {response.status_code}")

            data = response.json()

            if not data.get('success'):
                raise ValueError(f"Feed fetch failed: {data.get('data', 'Unknown error')}")

            return Feed.from_api_response(data.get('data'))

    except requests.ConnectionError as e:
        raise ValueError(f"Network error fetching feed: {e}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON response: {e}")


def fetch_checksum(url: str = BASE_VERIFY_URL) -> str:
    """
    Fetch the Joomla extensions feed from URL.

    Args:
        url: The feed URL to fetch (default is vel-feed)

    Returns:
        Dictionary containing success status and data from feed

    Raises:
        ValueError: If response is not successful or data format is invalid
    """
    try:
        with requests.get(url) as response:
            if response.status_code != 200:
                raise ValueError(f"Failed to fetch feed. HTTP status: {response.status_code}")

            data = response.json()

            if not data.get('success'):
                raise ValueError(f"Feed fetch failed: {data.get('data', 'Unknown error')}")

            return data.get('data')

    except requests.ConnectionError as e:
        raise ValueError(f"Network error fetching feed: {e}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON response: {e}")

def fetch_and_store_feed(dbm: DbManager) -> Feed:
    """
    Main function to fetch feed and store it in database.

    Args:
        db_path: Path to SQLite database file
        url: Feed URL to fetch

    Returns:
        Dictionary with summary of operation

    Raises:
        ValueError: If fetch or save fails
    """

    # Extract the inner data (without success wrapper for checksum calculation)
    feed_data = fetch_feed()
    checksum = fetch_checksum()

    if feed_data.checksum != checksum:
        raise ValueError(f"""Fetched checksum doesn't match fetched feed.
        Fetched checksum = {checksum}
        Calculated = {feed_data.checksum}""")

    # Create database if not exists
    dbm.create_database()

    print("Storing feed data in database...")
    dbm.save_feed_to_db(feed_data)

    # Print summary
    print("Feed Summary:")
    print(f"  API Version: {feed_data.api_version} ({feed_data.api_version_name})")
    print(f"  Timestamp: {feed_data.timestamp}")
    print(f"  License: {feed_data.license}")
    print(f"  Items count: {len(feed_data.items)}")
    print(f"  Checksum: {checksum}")

    return feed_data

def get_feed(dbm: DbManager) -> Feed:
    feed = dbm.get_feed()
    if feed is None:
        print("Feed not found on database, fetching...")
        return fetch_and_store_feed(dbm)
    if not feed.check_itself():
        print("Database data is corrupted, fetching...")
        return fetch_and_store_feed(dbm)
    checksum = fetch_checksum()
    if feed.checksum != checksum:
        print("Online feed is newer, fetching a new one...")
        return fetch_and_store_feed(dbm)
    return feed
