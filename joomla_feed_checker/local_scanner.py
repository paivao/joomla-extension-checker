"""
Local Scanner module for Joomla extensions.
Scans Joomla installation directories to find XML extension files.
"""

import os.path
import re
from collections.abc import Iterator
from pathlib import Path
from xml.etree import ElementTree as ET

from joomla_feed_checker.models import ExtensionMetadata

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

    __kv_rex = re.compile(r'^([A-Z0-9_.-]+)\s*=\s*"((?:[^"]|\\")+)"$')

    def __init__(
        self,
        base_path: Path,
        filter_core: bool = True,
        joomla_core_author: str = JOOMLA_CORE_AUTHOR,
        languages: list[str] | None = None,
    ):
        """
        Initialize scanner with base path.

        Args:
            base_path: Root directory of Joomla installation
        """
        self.base_path: Path = base_path.resolve()
        self.filter_author: str = joomla_core_author
        self.languages: list[str] = languages or ["en-GB"]
        self.filter_core: bool = filter_core
        self.package_mappings: dict[str, str] = {}
        if not self.base_path.exists():
            raise ValueError(f"Base path does not exist: {base_path}")

    @staticmethod
    def __list_packages(extension: ET.Element) -> list[str]:
        packages: list[str] = []
        for tag_parent in extension.findall("files"):
            for file_tag in tag_parent.findall("file"):
                packages.append(
                    os.path.join(
                        file_tag.attrib["type"] + "s",
                        file_tag.attrib.get("group", ""),
                        file_tag.attrib["id"],
                    )
                )
        return packages

    def get_joomla_version(self) -> str:
        manifest = self.base_path / "administrator/manifests/files/joomla.xml"
        tree = ET.parse(manifest)
        root = tree.getroot()
        version = root.find("version")
        if version is None:
            raise ValueError("Joomla manifest lack version")
        return version.text or ""

    def scan_por_packages(self) -> list[ExtensionMetadata]:
        package_path = self.base_path / "administrator/manifests/packages"
        self.package_mappings = {}
        packages = []
        for xml_file in package_path.glob("*.xml"):
            extension = self.__parse_extension_file(xml_file)
            if extension is None:
                continue
            if extension.type != "package":
                continue
            packages.append(extension)
            tree = ET.parse(xml_file)
            root = tree.getroot()
            self.package_mappings.update(
                {p: extension.name for p in self.__list_packages(root)}
            )
        return packages

    def scan_for_extensions(self) -> list[ExtensionMetadata]:
        """
        Scan for all extension XML files in Joomla directories.

        Args:
            filter_core: True to filter out Joomla core extensions

        Returns:
            List of dictionaries containing extension metadata
        """
        extensions: list[ExtensionMetadata] = []

        # Define search paths
        search_paths = [
            (self.base_path / "administrator" / "components", False),
            (self.base_path / "administrator" / "modules", False),
            (self.base_path / "administrator" / "templates", False),
            (self.base_path / "modules", False),
            (self.base_path / "plugins", True),
            (self.base_path / "components", False),
            (self.base_path / "templates", False),
        ]

        for root_dir, two_levels in search_paths:
            if not root_dir.exists():
                continue

            # Find all XML files
            try:
                xml_files = self.__find_files(root_dir, two_levels)
                for xml_file in xml_files:
                    try:
                        extension_data = self.__parse_extension_file(xml_file)
                        if extension_data:
                            extensions.append(extension_data)
                    except ET.ParseError as e:
                        print(f"Warning: Could not parse XML file {xml_file}: {e}")
                    except Exception as e:
                        print(f"Unknown error at {xml_file}: {e}")

            except Exception as e:
                print(f"Error scanning {root_dir}: {e}")

        return extensions

    def __parse_extension_file(self, xml_path: Path) -> ExtensionMetadata | None:
        """
        Parse a single extension XML file and extract metadata.

        Args:
            xml_path: Path to the XML file

        Returns:
            Dictionary with extension metadata or None if not an extension
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            relative_path = xml_path.relative_to(self.base_path).parent
            relative_to_admin = (
                relative_path.relative_to("administrator")
                if relative_path.is_relative_to("administrator")
                else ""
            )

            # Only process files where root element is 'extension'
            if root.tag != "extension":
                return None

            author = root.find("author")
            _author = author.text if author is not None else None
            if self.filter_core and _author == self.filter_author:
                # print("Filtered because it is from Joomla core")
                return None

            lang_files: list[Path] = []
            for languages_tag in (
                root.find("languages"),
                root.find("administration/languages"),
            ):
                if languages_tag is None:
                    continue
                for lang_tag in languages_tag.findall("language"):
                    lang: str = lang_tag.attrib.get("tag", "en-GB")
                    if lang not in self.languages:
                        continue
                    lang_end_path = lang_tag.text
                    if lang_end_path is None:
                        continue
                    lang_files.append(Path(lang) / Path(lang_end_path).name)
            lang_files = self.__get_language_files(lang_files)

            language_kv: dict[str, str] = {}
            for file in lang_files:
                language_kv |= self.__parse_language_file(file)

            # Build result dictionary
            description = self.__extract_from_language(
                root.find("description"), language_kv
            )
            _description = (
                description.replace("\r", "").replace("\n", "\\n")
                if description is not None
                else None
            )
            name = root.find("name")
            _name = (name.text or "") if name is not None else ""
            # print(xml_path, relative_path, relative_to_admin)
            _pack = self.package_mappings.get(
                str(relative_path)
            ) or self.package_mappings.get(str(relative_to_admin))
            return ExtensionMetadata(
                xml_path=str(xml_path.parent),
                type=root.attrib.get("type") or "",
                name=self.__extract_from_language(root.find("name"), language_kv) or "",
                author=self.__extract_from_language(root.find("author"), language_kv),
                version=self.__extract_from_language(root.find("version"), language_kv),
                creation_date=self.__extract_from_language(
                    root.find("creationDate"), language_kv
                ),
                description=_description,
                package_name=_pack,
            )

        except ET.ParseError as e:
            print(f"Warning: Could not parse XML file {xml_path}: {e}")
            return None

    def __get_language_files(self, files: list[Path]) -> list[Path]:
        lang_paths: list[Path] = []
        for fil in files:
            pat = self.base_path / "language" / fil
            if pat.exists():
                lang_paths.append(pat)
            pat = self.base_path / "administrator" / "language" / fil
            if pat.exists():
                lang_paths.append(pat)
        return lang_paths

    @staticmethod
    def __find_files(path: Path, two_levels: bool) -> Iterator[Path]:
        if two_levels:
            return path.glob("*/*/*.xml")
        return path.glob("*/*.xml")

    @staticmethod
    def __extract_from_language(
        element: ET.Element|None, lang_kv: dict[str, str]
    ) -> str|None:
        if element is None:
            return None
        _text = element.text
        return lang_kv.get(_text.upper(), _text) if _text else None

    @classmethod
    def __parse_language_file(cls, language_file: Path) -> dict[str, str]:
        kv: dict[str, str] = {}
        try:
            # print(f"Opening language file: {language_file}")
            with open(language_file, "r", encoding="utf-8") as lines:
                for line in lines:
                    if _match := cls.__kv_rex.match(line.strip()):
                        kv[_match.group(1).upper()] = _match.group(2)
        except Exception:
            # print(f"Could not open language file: {language_file}")
            pass
        return kv


def scan_joomla_extensions(
    base_path: Path, filter_core: bool = True
) -> list[ExtensionMetadata]:
    """
    Convenience function to scan Joomla extensions.

    Args:
        base_path: Base path of Joomla installation

    Returns:
        List of extension summaries
    """
    scanner = JoomlaExtensionScanner(base_path, filter_core=filter_core)
    return scanner.scan_por_packages() + scanner.scan_for_extensions()
