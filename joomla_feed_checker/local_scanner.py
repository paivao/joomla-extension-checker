"""
Local Scanner module for Joomla extensions.
Scans Joomla installation directories to find XML extension files.
"""

import os
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional

from joomla_feed_checker.models import ExtensionMetadata


class JoomlaExtensionScanner:
    """
    Scans a Joomla installation directory for extension XML files.

    Supported paths:
    - <base_path>/administrator/components/*//*.xml
    - <base_path>/administrator/modules/*//*.xml
    - <base_path>/modules/*//*.xml
    - <base_path>/plugins/*/</**.xml (recursive search)
    """

    def __init__(self, base_path: str):
        """
        Initialize scanner with base path.

        Args:
            base_path: Root directory of Joomla installation
        """
        self.base_path = Path(base_path).resolve()
        if not self.base_path.exists():
            raise ValueError(f"Base path does not exist: {base_path}")

    def scan_for_extensions(self) -> List[ExtensionMetadata]:
        """
        Scan for all extension XML files in Joomla directories.

        Returns:
            List of dictionaries containing extension metadata
        """
        extensions = []

        # Define search paths
        search_paths = [
            (self.base_path / 'administrator' / 'components'),
            (self.base_path / 'administrator' / 'modules'),
            (self.base_path / 'modules'),
            (self.base_path / 'plugins'),
        ]

        for root_dir in search_paths:
            if not root_dir.exists():
                continue

            # Find all XML files
            try:
                xml_files = list(root_dir.rglob('*.xml'))

                for xml_file in xml_files:
                    # Only process files directly inside extension directories (depth 1 or 2 for plugins)
                    try:
                        relative_path = str(xml_file.relative_to(self.base_path))
                        parts = relative_path.replace('\\', '/').split('/')

                        # Check if file is at appropriate depth
                        depth_ok = False

                        # For components/modules: administrator/components/*/*.xml or modules/*/*.xml
                        if 'administrator/components' in str(root_dir):
                            depth_ok = len(parts) == 4 and parts[1] == 'components'
                        elif 'administrator/modules' in str(root_dir):
                            depth_ok = len(parts) == 4 and parts[1] == 'modules'
                        # For modules: modules/*/*.xml or modules/*/*/.xml (plugins can be deeper)
                        elif 'administrator/modules' not in str(root_dir) and 'modules' in str(root_dir):
                            if len(parts) == 4 and parts[1] == 'modules':
                                depth_ok = True
                            elif len(parts) == 5 and parts[2] == 'plugins':
                                depth_ok = True
                        # For plugins: plugins/*/</**.xml (can be deeper)
                        elif 'plugins' in str(root_dir):
                            if len(parts) >= 5 and 'plugins' in parts:
                                depth_ok = True

                        if not depth_ok:
                            continue

                    except (IndexError, ValueError):
                        continue

                    try:
                        extension_data = self.parse_extension_file(xml_file)
                        if extension_data:
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
            return ExtensionMetadata(
                xml_path=str(xml_path),
                type=root.attrib.get('type'),
                author=getattr(root.find('author'), 'text', None),
                version=getattr(root.find('version'), 'text', None),
                creation_date=getattr(root.find('creationDate'), 'text', None),
                description=getattr(root.find('description'), 'text', None)
            )

        except ET.ParseError as e:
            print(f"Warning: Could not parse XML file {xml_path}: {e}")
            return None

def scan_joomla_extensions(base_path: str) -> list[ExtensionMetadata]:
    """
    Convenience function to scan Joomla extensions.

    Args:
        base_path: Base path of Joomla installation

    Returns:
        List of extension summaries
    """
    scanner = JoomlaExtensionScanner(base_path)
    return scanner.scan_for_extensions()
