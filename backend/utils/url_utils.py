"""URL extraction utilities"""

import re
from typing import List


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text"""
    url_pattern = r'https?://[^\s\)<>\"\']+|www\.[^\s\)<>\"\']+\.[a-z]{2,}'
    urls = []
    for match in re.finditer(url_pattern, text, re.IGNORECASE):
        url = match.group(0)
        if not url.startswith('http'):
            url = f'https://{url}'
        urls.append(url)
    return list(dict.fromkeys(urls))  # dedupe, preserve order
