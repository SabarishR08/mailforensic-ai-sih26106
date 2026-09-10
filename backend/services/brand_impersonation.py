"""
Brand Impersonation & Typosquatting Detection Engine
Detects domain spoofing, Levenshtein distance typosquatting, and display name impersonation
for major global brands (PayPal, Microsoft, Google, Apple, Amazon, Bank of America, SBI, etc.).
"""

import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Core Dictionary of Target Brands and Authorized Domains
KNOWN_BRANDS = {
    'paypal': {'domains': ['paypal.com', 'paypal.co.uk'], 'display_names': ['paypal', 'paypal security', 'paypal support']},
    'microsoft': {'domains': ['microsoft.com', 'office365.com', 'outlook.com', 'live.com'], 'display_names': ['microsoft', 'office 365', 'microsoft security', 'outlook team']},
    'google': {'domains': ['google.com', 'gmail.com'], 'display_names': ['google', 'google security', 'gmail team']},
    'apple': {'domains': ['apple.com', 'icloud.com'], 'display_names': ['apple', 'apple id', 'icloud security']},
    'amazon': {'domains': ['amazon.com', 'aws.amazon.com'], 'display_names': ['amazon', 'amazon support', 'aws security']},
    'bank of america': {'domains': ['bankofamerica.com'], 'display_names': ['bank of america', 'bofa']},
    'chase': {'domains': ['chase.com'], 'display_names': ['chase bank', 'chase security']},
    'wells fargo': {'domains': ['wellsfargo.com'], 'display_names': ['wells fargo']},
    'state bank of india': {'domains': ['sbi.co.in', 'onlinesbi.sbi'], 'display_names': ['state bank of india', 'sbi', 'onlinesbi']},
    'netflix': {'domains': ['netflix.com'], 'display_names': ['netflix', 'netflix support']},
    'meta / facebook': {'domains': ['facebook.com', 'meta.com', 'instagram.com'], 'display_names': ['facebook', 'instagram', 'meta']},
}


def lev_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return lev_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def similarity_ratio(s1: str, s2: str) -> float:
    """Compute similarity ratio (0.0 to 1.0) between two strings"""
    s1, s2 = s1.lower(), s2.lower()
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = lev_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))


def detect_brand_impersonation(from_header: str, reply_to: str = '', urls: List[str] = None) -> Dict:
    """
    Detects brand impersonation by analyzing:
    1. Display name vs actual sender domain mismatch.
    2. Typosquatting / homoglyphs in sender domain.
    3. Impersonated URLs in message body.
    """
    if urls is None:
        urls = []

    # Extract display name and email address
    display_name = ''
    sender_address = from_header
    match = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>$', from_header.strip())
    if match:
        display_name = match.group(1).strip()
        sender_address = match.group(2).strip()

    sender_domain = sender_address.split('@')[-1].lower() if '@' in sender_address else sender_address.lower()

    findings = []
    claimed_brand = None
    max_similarity = 0.0
    is_impersonation = False

    # Check 1: Display Name claims to be a brand, but sender domain is external
    for brand, data in KNOWN_BRANDS.items():
        # Check if display name mentions the brand
        brand_in_display = any(name in display_name.lower() for name in data['display_names'])
        domain_is_authorized = any(sender_domain == d or sender_domain.endswith('.' + d) for d in data['domains'])

        if brand_in_display and not domain_is_authorized:
            is_impersonation = True
            claimed_brand = brand.title()
            findings.append({
                'type': 'DISPLAY_NAME_IMPERSONATION',
                'severity': 'CRITICAL',
                'detail': f'Display name claims to be "{display_name}", but actual sender domain is "{sender_domain}".'
            })
            break

    # Check 2: Typosquatting / Homoglyph check on sender domain
    clean_sender_stem = sender_domain.split('.')[0] if '.' in sender_domain else sender_domain
    # Replace common leetspeak substitutions (0 -> o, 1 -> l, 3 -> e, 5 -> s)
    normalized_stem = clean_sender_stem.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('@', 'a')

    for brand, data in KNOWN_BRANDS.items():
        for auth_domain in data['domains']:
            auth_stem = auth_domain.split('.')[0]
            if auth_stem == clean_sender_stem:
                continue # Authorized exact match

            sim = similarity_ratio(normalized_stem, auth_stem)
            if sim > 0.75 and sim < 1.0:
                is_impersonation = True
                claimed_brand = brand.title()
                max_similarity = max(max_similarity, sim)
                findings.append({
                    'type': 'TYPOSQUATTING_DOMAIN',
                    'severity': 'CRITICAL',
                    'detail': f'Sender domain "{sender_domain}" is a typosquatted lookalike of authorized brand domain "{auth_domain}" (Similarity: {int(sim*100)}%).'
                })
                break

    # Check 3: Check extracted URLs for brand link mismatches
    suspicious_url_brands = []
    for url in urls:
        for brand, data in KNOWN_BRANDS.items():
            for auth_domain in data['domains']:
                auth_stem = auth_domain.split('.')[0]
                if auth_stem in url.lower() and not any(auth_d in url.lower() for auth_d in data['domains']):
                    suspicious_url_brands.append({'url': url, 'brand': brand.title()})
                    is_impersonation = True

    if suspicious_url_brands and not claimed_brand:
        claimed_brand = suspicious_url_brands[0]['brand']
        findings.append({
            'type': 'BRAND_URL_SPOOFING',
            'severity': 'HIGH',
            'detail': f'Email body contains URLs targeting brand "{claimed_brand}" on unauthorized domains.'
        })

    risk_level = 'CRITICAL' if is_impersonation else 'SAFE'

    return {
        'is_impersonation': is_impersonation,
        'claimed_brand': claimed_brand,
        'actual_sender_domain': sender_domain,
        'similarity_score': round(max_similarity, 2),
        'risk_level': risk_level,
        'findings': findings
    }
