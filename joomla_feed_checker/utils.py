import json
import hashlib
from pathlib import Path
from typing import Iterable, NamedTuple
import csv

def calculate_checksum(data: dict) -> str:
    """
    Calculate SHA256 checksum for the feed data.

    Args:
        data: The feed data dictionary (without 'success' and 'data' wrapper keys, just the content)

    Returns:
        Lowercase hex digest of SHA256 hash of serialized data
    """
    # Create a JSON representation without the wrapper structure for checksum
    feed_content = json.dumps(data).replace("\n", "").replace(" ", "").replace("\t", "").replace("/", "\\/")
    return hashlib.sha256(feed_content.encode('utf-8')).hexdigest()

def find_files_recursively(path: Path, ext: str = '.xml') -> list[Path]:
    metadatas = []
    for child in path.iterdir():
        if child.suffix == ext:
            return [child]
        if child.is_dir():
            metadatas += find_files_recursively(child)
    return metadatas

def write_csv_file[T: NamedTuple](csv_path: str, data: Iterable[T]):
    with open(csv_path, "w") as file:
        writer = csv.writer(file)
        _iter = iter(data)
        first = next(_iter)
        writer.writerow(first._fields)
        writer.writerow(first)
        for row in _iter:
            writer.writerow(row)
