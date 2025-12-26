"""
Scan Utilities Module

Common utilities for vulnerability scanning:
- Synthetic parameter generation for URLs without params
- Response similarity detection for blind vulnerability testing
- Form extraction improvements
"""

from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
import re

# Common parameter names to try when URL has no parameters
SYNTHETIC_PARAMS = [
    # Most common
    'id', 'page', 'q', 'search', 'query', 'name', 'user', 'file',
    # Identifiers
    'uid', 'pid', 'item', 'product', 'article', 'post', 'cat', 'category',
    # Actions/views
    'action', 'view', 'type', 'mode', 'cmd', 'do', 'func',
    # Input fields
    'input', 'data', 'value', 'text', 'content', 'message', 'comment',
    # URLs/paths
    'url', 'path', 'file', 'filename', 'dir', 'folder', 'redirect', 'next', 'return',
    # API-like
    'key', 'token', 'api', 'format', 'callback', 'jsonp',
    # Debug/admin
    'debug', 'test', 'admin', 'lang', 'locale',
]


def generate_synthetic_targets(url: str, params_to_try: List[str] = None) -> List[Dict[str, Any]]:
    """
    Generate synthetic targets with test parameters for URLs that have no params.

    This is useful for fuzzing endpoints that might accept parameters
    even if they're not shown in the URL.

    Args:
        url: Base URL without parameters
        params_to_try: List of parameter names to try (default: SYNTHETIC_PARAMS)

    Returns:
        List of target dicts with synthetic parameters
    """
    if params_to_try is None:
        params_to_try = SYNTHETIC_PARAMS[:15]  # Limit to top 15 by default

    targets = []
    parsed = urlparse(url)

    # Skip if URL already has parameters
    if parsed.query:
        return targets

    for param in params_to_try:
        target = {
            'url': url,
            'params': {param: 'FUZZ'},
            'method': 'GET',
            'synthetic': True,
            'synthetic_param': param
        }
        targets.append(target)

    return targets


def add_synthetic_params_to_targets(targets: List[Dict[str, Any]],
                                     max_synthetic: int = 10) -> List[Dict[str, Any]]:
    """
    Add synthetic parameter targets for URLs that have no parameters.

    Args:
        targets: List of existing targets
        max_synthetic: Maximum synthetic params to add per URL

    Returns:
        Extended list of targets including synthetic ones
    """
    extended_targets = list(targets)
    urls_without_params = set()

    # Find URLs without parameters
    for target in targets:
        url = target.get('url', '')
        params = target.get('params', {})

        if not params:
            # Extract base URL without query string
            parsed = urlparse(url)
            base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
            urls_without_params.add(base_url)

    # Generate synthetic targets for each URL without params
    for url in urls_without_params:
        synthetic = generate_synthetic_targets(url, SYNTHETIC_PARAMS[:max_synthetic])
        extended_targets.extend(synthetic)

    return extended_targets


def response_similarity(response_a: str, response_b: str) -> float:
    """
    Calculate similarity ratio between two responses.

    Uses SequenceMatcher for efficient comparison.
    Useful for detecting blind vulnerabilities by comparing
    baseline response with payload response.

    Args:
        response_a: First response text
        response_b: Second response text

    Returns:
        Similarity ratio between 0.0 (different) and 1.0 (identical)
    """
    if response_a is None or response_b is None:
        return 0.0

    if not response_a and not response_b:
        return 1.0

    if not response_a or not response_b:
        return 0.0

    # For very long responses, sample for performance
    max_len = 50000
    if len(response_a) > max_len:
        response_a = response_a[:max_len]
    if len(response_b) > max_len:
        response_b = response_b[:max_len]

    return SequenceMatcher(None, response_a, response_b).ratio()


def detect_significant_difference(baseline: str, response: str,
                                   threshold: float = 0.15) -> Tuple[bool, Dict[str, Any]]:
    """
    Detect if response is significantly different from baseline.

    Used for blind vulnerability detection:
    - Large length changes
    - Low similarity ratio
    - New error messages

    Args:
        baseline: Baseline response text
        response: Response to compare
        threshold: Minimum difference threshold (0.0-1.0)

    Returns:
        Tuple of (is_different, details_dict)
    """
    details = {
        'length_change': 0,
        'length_change_percent': 0.0,
        'similarity': 1.0,
        'new_errors': False,
        'reason': None
    }

    if not baseline and not response:
        return False, details

    baseline_len = len(baseline) if baseline else 0
    response_len = len(response) if response else 0

    # Calculate length difference
    details['length_change'] = response_len - baseline_len
    if baseline_len > 0:
        details['length_change_percent'] = abs(details['length_change']) / baseline_len

    # Calculate similarity
    details['similarity'] = response_similarity(baseline, response)

    # Check for new error indicators
    error_patterns = [
        r'error', r'exception', r'warning', r'fatal', r'failed',
        r'invalid', r'syntax', r'unexpected', r'denied', r'forbidden'
    ]

    baseline_lower = baseline.lower() if baseline else ''
    response_lower = response.lower() if response else ''

    for pattern in error_patterns:
        if re.search(pattern, response_lower) and not re.search(pattern, baseline_lower):
            details['new_errors'] = True
            break

    # Determine if difference is significant
    is_different = False

    # Check 1: Large length change (>200 chars or >15%)
    if abs(details['length_change']) > 200 or details['length_change_percent'] > threshold:
        is_different = True
        details['reason'] = f"Length changed from {baseline_len} to {response_len}"

    # Check 2: Low similarity (below 85%)
    elif details['similarity'] < (1.0 - threshold):
        is_different = True
        details['reason'] = f"Response similarity only {details['similarity']:.1%}"

    # Check 3: New error appeared
    elif details['new_errors']:
        is_different = True
        details['reason'] = "New error indicators appeared in response"

    return is_different, details


def extract_forms_enhanced(html: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Extract forms from HTML with enhanced input detection.

    Handles:
    - Standard <input> elements
    - <textarea> elements
    - <select> elements with options
    - Hidden fields and CSRF tokens

    Args:
        html: HTML content
        base_url: Base URL for resolving action URLs

    Returns:
        List of form dicts with action, method, and inputs
    """
    forms = []

    if not html:
        return forms

    # Find all forms
    form_pattern = r'<form[^>]*>(.*?)</form>'
    form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

    for i, form_html in enumerate(form_matches):
        # Get form tag for action/method extraction
        form_tag_match = re.search(r'<form([^>]*)>', html, re.IGNORECASE)
        form_attrs = form_tag_match.group(1) if form_tag_match else ''

        # Extract action
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
        action = action_match.group(1) if action_match else ''
        action = urljoin(base_url, action) if action else base_url

        # Extract method
        method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
        method = (method_match.group(1) if method_match else 'GET').upper()

        inputs = {}

        # Extract <input> elements
        input_pattern = r'<input([^>]*)/?>'
        for match in re.finditer(input_pattern, form_html, re.IGNORECASE):
            attrs = match.group(1)

            name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if not name_match:
                continue
            name = name_match.group(1)

            value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            value = value_match.group(1) if value_match else ''

            type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            input_type = type_match.group(1).lower() if type_match else 'text'

            # Store with type info
            inputs[name] = {
                'value': value,
                'type': input_type
            }

        # Extract <textarea> elements
        textarea_pattern = r'<textarea[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</textarea>'
        for match in re.finditer(textarea_pattern, form_html, re.IGNORECASE | re.DOTALL):
            name = match.group(1)
            value = match.group(2).strip()
            inputs[name] = {
                'value': value,
                'type': 'textarea'
            }

        # Extract <select> elements
        select_pattern = r'<select[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</select>'
        for match in re.finditer(select_pattern, form_html, re.IGNORECASE | re.DOTALL):
            name = match.group(1)
            select_content = match.group(2)

            # Get first option as default value
            option_match = re.search(r'<option[^>]*value\s*=\s*["\']([^"\']*)["\']',
                                      select_content, re.IGNORECASE)
            value = option_match.group(1) if option_match else ''

            inputs[name] = {
                'value': value,
                'type': 'select'
            }

        # Identify CSRF tokens
        csrf_token = None
        csrf_names = ['csrf', 'csrf_token', 'csrftoken', '_csrf', 'token', '_token',
                      'authenticity_token', 'csrfmiddlewaretoken', '__RequestVerificationToken']

        for name, data in inputs.items():
            if any(csrf in name.lower() for csrf in csrf_names):
                csrf_token = {
                    'name': name,
                    'value': data['value']
                }
                break

        forms.append({
            'action': action,
            'method': method,
            'inputs': inputs,
            'csrf_token': csrf_token,
            'source_url': base_url,
            'form_index': i
        })

    return forms


def build_url_with_params(url: str, params: Dict[str, str]) -> str:
    """
    Build URL with query parameters.

    Args:
        url: Base URL
        params: Dictionary of parameters

    Returns:
        URL with parameters appended
    """
    if not params:
        return url

    parsed = urlparse(url)

    # Merge with existing params
    existing_params = parse_qs(parsed.query)
    for key, value in params.items():
        existing_params[key] = [value]

    # Build new query string
    query = urlencode({k: v[0] for k, v in existing_params.items()})

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        query,
        parsed.fragment
    ))


def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent comparison.

    - Removes fragments
    - Sorts query parameters
    - Lowercases scheme and host

    Args:
        url: URL to normalize

    Returns:
        Normalized URL
    """
    try:
        parsed = urlparse(url)

        # Sort query parameters
        params = parse_qs(parsed.query)
        sorted_query = urlencode(sorted(params.items()), doseq=True)

        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            sorted_query,
            ''  # Remove fragment
        ))
    except:
        return url
