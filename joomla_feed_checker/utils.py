import csv
import hashlib
import json
import re
from typing import Any, Iterable, NamedTuple


def calculate_checksum(data: dict[str, Any]) -> str:
    """
    Calculate SHA256 checksum for the feed data.

    Args:
        data: The feed data dictionary (without 'success' and 'data' wrapper keys, just the content)

    Returns:
        Lowercase hex digest of SHA256 hash of serialized data
    """
    # Create a JSON representation without the wrapper structure for checksum
    feed_content = (
        json.dumps(data)
        .replace("\n", "")
        .replace(" ", "")
        .replace("\t", "")
        .replace("/", "\\/")
    )
    return hashlib.sha256(feed_content.encode("utf-8")).hexdigest()


def write_csv_file(csv_path: str, data: Iterable[Any]):
    with open(csv_path, "w") as file:
        writer = csv.writer(file)
        _iter = iter(data)
        first = next(_iter)
        writer.writerow(first._fields)
        writer.writerow(first)
        for row in _iter:
            writer.writerow(row)


def print_section_header(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print("=" * 80)


VER_REX = re.compile(r"^(\d+(?:\.\d+)*)(\w+)?(?:-(\w+))?(?:\+\w+)?$")
def compare_version(v1: str, v2: str) -> int|None:
    """
    Compare version strings.

    Returs positive number if v1 > v2, negative if v1 < v2, or zero if they're equal.
    The absolute return value cannot be considered.

    Accepts version at the format "1.2.3p1-pre1+buildinfo".
    """
    if (m1 := VER_REX.match(v1)) and (m2 := VER_REX.match(v2)):
        g1, g2 = m1.groups(), m2.groups()
        dot1, dot2 = g1[0].split("."), g2[0].split(".")
        # Compare numeric dot parts
        for p1, p2 in zip(dot1, dot2):
            i1, i2 = int(p1), int(p2)
            if i1 != i2:
                return i1 - i2
        # If any version has more divisions
        if len(dot1) != len(dot2):
            return len(dot1) - len(dot2)
        # If any version has patch
        pat1, pat2 = g1[1] or '', g1[2] or ''
        if pat1 != pat2:
            return (pat1 > pat2) - (pat1 < pat2)
        # pre-release logic is inverted, if any version is not pre-release, returns it
        if g1[2] is None:
            return +(g2[2] is not None)
        if g2[2] is None:
            return -1
        return (g1[2] > g2[2]) - (g1[2] < g2[2])
    return None
