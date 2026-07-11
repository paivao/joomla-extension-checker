"""
Database Manager module for Joomla Extension Checker.
Handles database operations including comparison of feed items with local extensions.
"""

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from models import Feed, FeedItem

from joomla_feed_checker.models import Feed


class DbManager:
    """
    Database manager for Joomla extension checker.
    Handles all database operations including:
    - Feed data storage
    - Extension comparison
    - Full-text search queries
    """

    def __init__(self, db_path: str):
        """
        Initialize database manager.

        Args:
            db_path: Path to SQLite database file
        """
        self.__db_path = db_path

    def __enter__(self):
        self.__conn = sqlite3.connect(self.__db_path)


    def get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def create_database(self):
        """
        Create SQLite database with required schema.
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        try:

            # Create feed table with one row (singleton table)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feed (
                    api_version TEXT NOT NULL,
                    api_version_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    license TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    PRIMARY KEY (api_version)
                )
            """)

            # Create items table for extension listings
            # TODO: sync with feed ty
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status INTEGER,
                    jed TEXT,
                    cve_id TEXT,
                    cwe_id TEXT,
                    risk_level TEXT,
                    recommendation TEXT,
                    cvss30_base TEXT,
                    cvss30_base_score TEXT,
                    start_version TEXT,
                    vulnerable_version TEXT,
                    patch_version TEXT,
                    update_notice TEXT,
                    install_data TEXT,
                    created TEXT,
                    modified TEXT,
                    statusText TEXT
                )
            """)

            # Create FTS5 virtual table for full-text search on title and description
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS items_fts5 USING fts5(
                    title,
                    description,
                    content=items,
                    content_rowid=id
                )
            """)

            # Add trigger to populate FTS5 table when item is inserted
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS items_after_insert
                AFTER INSERT ON items
                BEGIN
                    INSERT INTO items_fts5(rowid, title, description)
                    VALUES(NEW.id, NEW.title, NEW.description);
                END
            """)

            # Add trigger to delete from FTS5 when item is deleted
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS items_after_delete
                AFTER DELETE ON items
                BEGIN
                    INSERT INTO items_fts5(items_fts5, rowid, title, description)
                    VALUES('delete', OLD.id, OLD.title, OLD.description);
                END
            """)

            # Add trigger to update FTS5 when item is updated
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS items_after_update
                AFTER UPDATE ON items
                BEGIN
                    INSERT INTO items_fts5(items_fts5, rowid, title, description)
                    VALUES('delete', OLD.id, OLD.title, OLD.description);
                    INSERT INTO items_fts5(rowid, title, description)
                    VALUES(NEW.id, NEW.title, NEW.description);
                END
            """)
            conn.commit()
        finally:
            conn.close()

    def save_feed_to_db(self, feed_data: Feed) -> int:
        """
        Save feed data to the SQLite database.

        Args:
            feed_data: The feed data dictionary (the 'data' key from response)
            checksum: SHA256 checksum of the feed

        Returns:
            Number of items inserted (or 1 for feed record)
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # Items field filtered
        insert_query = f"INSERT OR REPLACE INTO items ({', '.join(Feed._fields[:-1])} VALUES ({', '.join(['?'] * (len(Feed._fields)-1))})"
        cursor.execute(insert_query, feed_data[:-1])

        inserted_count = 0

        insert_query = f"INSERT OR REPLACE INTO items ({', '.join(FeedItem._fields)} VALUES ({', '.join(['?'] * len(FeedItem._fields))})"
        for item in feed_data.items:
            try:
                cursor.execute(insert_query, item)
                inserted_count += 1

            except sqlite3.Error as e:
                print(f"Error inserting item {item.id}: {e}")

        conn.commit()
        return inserted_count

    def get_feed(self) -> Optional[Feed]:
        """
        Get feed information from database.

        Returns:
            Dictionary with feed info or None if not found
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute(f"SELECT {Feed._fields[:-1]} FROM feed LIMIT 1")

            row = cursor.fetchone()

            if not row:
                return None
            _feed = Feed._make(row)
        finally:
            conn.close()
        return _feed._replace(items=self.get_all_feed_items())

    def get_all_feed_items(self) -> List[FeedItem]:
        """
        Get all feed items from database.

        Args:
            api_version: Specific API version to query (None for latest)

        Returns:
            List of item dictionaries
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute(f"SELECT {','.join(FeedItem._fields)} FROM items")

            return list(map(FeedItem._make, cursor.fetchall()))

        finally:
            conn.close()

    def get_item_by_id(self, item_id: int) -> Optional[FeedItem]:
        """
        Get a specific feed item by ID.

        Args:
            item_id: Item ID from feed
            api_version: Specific API version to query

        Returns:
            Item dictionary or None if not found
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute(f"SELECT {','.join(FeedItem._fields)} FROM items WHERE id = ?", (item_id,))

            row = cursor.fetchone()
            return FeedItem._make(row) if row else None

        finally:
            conn.close()

    def search_extensions_fts(self, query: str) -> List[FeedItem]:
        """
        Search extensions in the FTS5 index.

        Args:
            query: Search query string

        Returns:
            List of matching extension items
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            # Search title and description fields
            cursor.execute(f"""
                SELECT {','.join(f"i.{x}" for x in FeedItem._fields)}, f.rank FROM items i
                INNER JOIN items_fts5 f ON i.id = f.rowid
                WHERE items_fts5 MATCH ?
                ORDER BY f.rank DESC
            """, (query,))

            return [FeedItem._make(row[:-1]) for row in cursor.fetchall()]

        finally:
            conn.close()
