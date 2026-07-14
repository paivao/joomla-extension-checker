"""
Local Scanner module for Joomla extensions.
Scans Joomla installation directories to find XML extension files.
"""

from xml.etree import ElementTree as ET
from pathlib import Path
from typing import Optional
import re

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

    __kv_rex = re.compile(r'^([A-Z0-9_.-]+)="((?:[^"]|\\")+)"$')

    def __init__(self, base_path: Path, joomla_core_author: str = JOOMLA_CORE_AUTHOR, languages=['en-GB']):
        """
        Initialize scanner with base path.

        Args:
            base_path: Root directory of Joomla installation
        """
        self.base_path = base_path.resolve()
        self.filter_author = joomla_core_author
        self.languages = languages
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
                        extension_data = self.__parse_extension_file(xml_file)
                        if extension_data and not (filter_core and extension_data.author == self.filter_author):
                            extensions.append(extension_data)
                    except ET.ParseError as e:
                        print(f"Warning: Could not parse XML file {xml_file}: {e}")

            except Exception as e:
                print(f"Error scanning {root_dir}: {e}")

        return extensions

    def __parse_extension_file(self, xml_path: Path) -> Optional[ExtensionMetadata]:
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

            language_kv = {}
            for languages_tag, lang_mid_path in ((root.find("languages"),'language'), (root.find('administration/languages'),'administrator/language')):
                if languages_tag is None:
                    continue
                for lang_tag in languages_tag.findall('language'):
                    lang = lang_tag.attrib.get('tag', 'en-GB')
                    if lang not in self.languages:
                        continue
                    lang_end_path = lang_tag.text
                    if lang_end_path is None:
                        continue
                    language_kv |= self.__parse_language_file(self.base_path / lang_mid_path / lang / Path(lang_end_path).name)

            # Build result dictionary
            _description = self.__extract_from_language(root.find('description'), language_kv)
            _description = _description.replace("\r","").replace("\n","\\n") if _description else None
            return ExtensionMetadata(
                xml_path=str(xml_path.parent),
                type=root.attrib.get('type'),
                name=self.__extract_from_language(root.find('name'), language_kv) or '',
                author=self.__extract_from_language(root.find('author'), language_kv),
                version=self.__extract_from_language(root.find('version'), language_kv),
                creation_date=self.__extract_from_language(root.find('creationDate'), language_kv),
                description=_description
            )

        except ET.ParseError as e:
            print(f"Warning: Could not parse XML file {xml_path}: {e}")
            return None

    @staticmethod
    def __extract_from_language(element: Optional[ET.Element], lang_kv: dict[str, str]) -> Optional[str]:
        if element is None:
            return None
        _text = element.text
        return lang_kv.get(_text.upper(), _text) if _text else None

    @classmethod
    def __parse_language_file(cls, language_file: Path) -> dict[str, str]:
        kv: dict[str, str] = {}
        try:
            #print(f"Opening language file: {language_file}")
            with open(language_file, "r", encoding="utf-8") as lines:
                for line in lines:
                    if _match := cls.__kv_rex.match(line.strip()):
                        kv[_match.group(1).upper()] = _match.group(2)
        except Exception:
            #print(f"Could not open language file: {language_file}")
            pass
        return kv

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
