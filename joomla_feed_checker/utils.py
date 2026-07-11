import json
import hashlib

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
