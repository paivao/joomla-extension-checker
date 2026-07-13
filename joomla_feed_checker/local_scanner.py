"""
Local Scanner module for Joomla extensions.
Scans Joomla installation directories to find XML extension files.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from joomla_feed_checker.models import ExtensionMetadata
from .utils import find_files_recursively

JOOMLA_CORE_AUTHOR = "Joomla! Project"

class JoomlaExtensionScanner:
    """
    Scans a Joomla installation directory for extension XML files.

    Supported paths:
    - <base_path>/administrator/components/*//*.xml
    - <base_path>/administrator/modules/*//*.xml
    - <base_path>/modules/*//*.xml
    - <base_path>/plugins/*/</**.xml (recursive search)
    """

    def __init__(self, base_path: Path, joomla_core_author: str = JOOMLA_CORE_AUTHOR):
        """
        Initialize scanner with base path.

        Args:
            base_path: Root directory of Joomla installation
        """
        self.base_path = base_path.resolve()
        self.filter_author = joomla_core_author
        if not self.base_path.exists():
            raise ValueError(f"Base path does not exist: {base_path}")

    def scan_for_extensions(self, filter_core: bool = True) -> list[ExtensionMetadata]:
        """
        Scan for all extension XML files in Joomla directories.

        Args:
            filter_core: True to filter out Joomla core extensions

        Returns:
            List of dictionaries containing extension metadata
        """
        extensions = []

        # Define search paths
        search_paths = [
            (self.base_path / 'administrator' / 'components'),
            (self.base_path / 'administrator' / 'modules'),
            (self.base_path / 'administrator' / 'templates'),
            (self.base_path / 'modules'),
            (self.base_path / 'plugins'),
            (self.base_path / 'components'),
            (self.base_path / 'templates'),
        ]

        for root_dir in search_paths:
            if not root_dir.exists():
                continue

            # Find all XML files
            try:
                xml_files = find_files_recursively(root_dir)
                for xml_file in xml_files:
                    try:
                        extension_data = self.parse_extension_file(xml_file)
                        if extension_data and not (filter_core and extension_data.author == self.filter_author):
                            extensions.append(extension_data)
                    except ET.ParseError as e:
                        print(f"Warning: Could not parse XML file {xml_file}: {e}")

            except Exception as e:
                print(f"Error scanning {root_dir}: {e}")

        return extensions

    def parse_extension_file(self, xml_path: Path) -> Optional[ExtensionMetadata]:
        """
        Parse a single extension XML file and extract metadata.

        Args:
            xml_path: Path to the XML file

        Returns:
            Dictionary with extension metadata or None if not an extension
        """
        try:
            tree = ET.parse(str(xml_path))
            root = tree.getroot()

            # Only process files where root element is 'extension'
            if root.tag != 'extension':
                return None

            # Build result dictionary
            _description: Optional[str] = getattr(root.find('description'), 'text', None)
            if _description:
                _description = _description.replace("\r","").replace("\n","\\n")
            return ExtensionMetadata(
                xml_path=str(xml_path.parent),
                type=root.attrib.get('type'),
                name=getattr(root.find('name'), 'text', ''),
                author=getattr(root.find('author'), 'text', None),
                version=getattr(root.find('version'), 'text', None),
                creation_date=getattr(root.find('creationDate'), 'text', None),
                description=_description
            )

        except ET.ParseError as e:
            print(f"Warning: Could not parse XML file {xml_path}: {e}")
            return None

def scan_joomla_extensions(base_path: Path, filter_core: bool = True) -> list[ExtensionMetadata]:
    """
    Convenience function to scan Joomla extensions.

    Args:
        base_path: Base path of Joomla installation

    Returns:
        List of extension summaries
    """
    scanner = JoomlaExtensionScanner(base_path)
    return scanner.scan_for_extensions(filter_core)
