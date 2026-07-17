"""
Data classes for Joomla Extensions feed and items.
Based on the Joomla Extensions API response format.
"""

from datetime import datetime
import json
import sqlite3
from typing import Any, Optional, Union, NamedTuple
import html

from joomla_feed_checker.utils import calculate_checksum

class FeedItem(NamedTuple):
    """
    Represents a single item from the Joomla extensions feed.

    Attributes:
        id: The ID of the listing
        title: Name of the listing (usually extension name + vulnerable versions)
        description: Additional info including version notes
        status: 1 = live, 2 = resolved
        jed: URL of JED listing if any
        cve_id: CVE and vulnerability tracking database IDs
        cwe_id: CWE vulnerability classification IDs
        risk_level: low, medium, high
        recommendation: How to handle the subject extension
        cvss30_base: CVSS 3.0 base vector string
        cvss30_base_score: CVSS 3.0 numeric score
        start_version: First version where vulnerability is present
        vulnerable_version: Most recent vulnerable version
        patch_version: Version where vulnerability is patched
        update_notice: Developer's update notice URL
        install_data: JSON installation data from extension manifest
        created: ISO8601 creation date of the listing
        modified: ISO8601 modification date of the listing
        statusText: "Live" or "Resolved"
    """
    id: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[int] = None  # 1 = live, 2 = resolved
    jed: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    risk_level: Optional[str] = None
    recommendation: Optional[str] = None
    cvss30_base: Optional[str] = None
    cvss30_base_score: Optional[str] = None
    start_version: Optional[str] = None
    vulnerable_version: Optional[str] = None
    patch_version: Optional[str] = None
    update_notice: Optional[str] = None
    install_data: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    statusText: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary, filtering None values."""
        return {k: v for k, v in self._asdict().items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> 'FeedItem':
        """Create FeedItem from dictionary."""
        # Handle nested 'data' key in feed response
        if 'data' in data:
            data = data['data']

        if 'install_data' in data:
            data['install_data'] = str(data['install_data'])
        return cls(**{k: data.get(k) for k in cls._fields})

    def format(self, indent: int = 4) -> str:
        _indent = ' ' * indent
        _0xa = "\n"
        _format = f"[STATUS:{self.statusText}] [RISK:{self.risk_level or 'UNKNOWN'}] [ID:{self.id}] {self.title}"
        if self.created or self.modified:
            _format += f'\n{_indent}Created: {self.created}\tModified: {self.modified}'
        if des := self.description:
            _format += f'\n{_indent}-----\n{_indent}{html.unescape(des).replace(_0xa, _0xa+_indent)}\n{_indent}-----'
        if _rec := self.recommendation:
            _format += f'\n{_indent}Recommendation: {_rec}'
        if _jed := self.jed:
            _format += f'\n{_indent}JED: {_jed}'
        if self.cve_id or self.cwe_id:
            _format += f'\n{_indent}CVE: {self.cve_id}\tCWE: {self.cwe_id}'
        if self.cvss30_base or self.cvss30_base_score:
            _format += f'\n{_indent}CVS3: {self.cvss30_base} ({self.cvss30_base_score})'
        if self.start_version or self.vulnerable_version or self.patch_version:
            _format += f'\n{_indent}Start version: {self.start_version}, Vulnerable: {self.vulnerable_version}, Patched: {self.patch_version}'
        if _upd := self.update_notice:
            _format += f'\n{_indent}Update notice: {_upd}'
        if _dat := self.install_data:
            _format += f'\n{_indent}Install data: "{_dat}"'
        return _format

class Feed(NamedTuple):
    """
    Represents the Joomla extensions feed metadata.

    Attributes:
        api_version: API version string
        api_version_name: Human-readable API version name
        timestamp: ISO8601 timestamp when feed was last updated
        license: License information (GPL for this feed)
        checksum: SHA256 lowercase hex digest of feed content
        items: List of FeedItem objects
    """
    api_version: str = ""
    api_version_name: str = ""
    timestamp: str = ""
    license: str = ""  # Default to GPL as per API documentation
    checksum: str = ""
    items: list[FeedItem] = []

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        _feed = self._asdict()
        _feed['items'] = [item.to_dict() for item in self.items]
        return _feed

    @classmethod
    def from_dict(cls, data: dict) -> 'Feed':
        """Create Feed from dictionary (including nested 'data' key)."""
        # Handle nested 'data' key in feed response
        if 'data' in data:
            data = data['data']

        return cls(items=[FeedItem.from_dict(item) for item in data.get('items', [])]
            , **{k: data.get(k,'') for k in cls._fields[:-1]})

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> 'Feed':
        """
        Create Feed instance directly from API response.

        Args:
            response: Raw dictionary from Joomla Extensions API

        Returns:
            Feed object with metadata and items populated
        """
        return cls(checksum=calculate_checksum(data),
            items=[FeedItem.from_dict(item) for item in data.get('items', [])]
            , **{k: data.get(k,'') for k in cls._fields[:-2]})

    def check_itself(self) -> bool:
        _dict = self.to_dict()
        del _dict['checksum']
        return self.checksum == calculate_checksum(_dict)

    def validate(self) -> bool:
        """Validate the Feed object."""
        if not self.api_version:
            print("Warning: Feed api_version is missing")
            return False

        if not self.timestamp:
            print("Warning: Feed timestamp is missing")
            return False

        if len(self.items) == 0:
            print(f"Warning: Feed has no items (count: {len(self.items)})")

        return True


class ExtensionMetadata(NamedTuple):
    xml_path: str
    type: str
    name: str
    author: Optional[str]
    version: Optional[str]
    creation_date: Optional[str]
    description: Optional[str]
    package_name: Optional[str]

    def format(self, indent: int = 4) -> str:
        _indent = " " * indent
        _0xa = "\n"
        _package = f' [PACKAGE:{self.package_name}]' if self.package_name else ''
        _format = f'[TYPE:{self.type}] [VERSION:{self.version}]{_package} {self.name} @ "{self.xml_path}"'
        if self.author or self.creation_date:
            _format += f'\n{_indent}Author: {self.author}\tCreation date: {self.creation_date}'
        if des := self.description:
            _format += f'\n{_indent}Description: {html.unescape(des).replace(_0xa, _0xa+_indent)}'
        return _format

class CVEEntry(NamedTuple):
    id: str
    sourceIdentifier: str
    published: datetime
    lastModified: datetime
    vulnStatus: str
    description: str # Differ from descriptions
    references: list[Any]
    evaluatorComment: Optional[str] = None
    evaluatorImpact: Optional[str] = None
    evaluatorSolution: Optional[str] = None
    cisaExploitAdd: Optional[str] = None
    cisaActionDue: Optional[str] = None
    cisaRequiredAction: Optional[str] = None
    cisaVulnerabilityName: Optional[str] = None
    cveTags: list[Any] | None = None
    metrics: dict[str, Any] | None = None
    weaknesses: list[Any] | None = None
    affected: list[Any] | None = None
    configurations: list[Any] | None = None
    vendorComments: list[Any] | None = None
    ssvc: list[Any] | None = None

    @classmethod
    def get_fields(cls):
        return cls._fields[:6] + ("_references",) + cls._fields[7:]

    @classmethod
    def from_api(cls, data: dict[str, Any]):
        descriptions: list[dict[str,str]] = data.pop('descriptions') or []
        if len(descriptions) == 0:
            raise ValueError("Empty descriptions")
        data.update({
            'description': next(filter(lambda x: x['lang']=='en', descriptions),descriptions[0])['value'],
            'published': datetime.fromisoformat(data.pop('published').replace('Z', "+00:00")),
            'lastModified': datetime.fromisoformat(data.pop('lastModified').replace('Z', "+00:00")),
        })
        return cls(**data)

    def to_db(self):
        return tuple(str(i) for i in self[:6]) + (json.dumps(self.references),) + self[7:14] + tuple(json.dumps(i) for i in self[14:])

    @classmethod
    def from_db(cls, row: sqlite3.Row):
        return cls(*(row[:2] + tuple(datetime.fromisoformat(i) for i in row[2:4]) + row[4:6] + (json.loads(row['_references']),) + row[7:14] + tuple(json.loads(i) for i in row[14:])))

class NVDAPIResponse(NamedTuple):
    """
    Represents the complete API response structure.

    Attributes:
        success: Boolean indicating request success
        data: The actual feed data (Feed object) or string hash for verification
    """
    resultsPerPage: int
    startIndex: int
    totalResults: int
    format: str
    version: str
    timestamp: datetime
    vulnerabilities: list[CVEEntry]

    @classmethod
    def from_api(cls, data: dict[str, Any]):
        timestamp = datetime.fromisoformat(data.pop('timestamp').replace('Z', "+00:00"))
        vulnerabilities = [CVEEntry.from_api(entry['cve']) for entry in data.pop('vulnerabilities')]
        return cls(timestamp=timestamp, vulnerabilities=vulnerabilities, **data)
