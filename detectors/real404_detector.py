"""
Real 404 page detector - detects when server returns 200 but content indicates 404
"""

import re
from typing import Tuple, List, Dict, Any
from difflib import SequenceMatcher

class Real404Detector:
    """Real 404 page detection logic"""
    
    @staticmethod
    def get_404_indicators() -> List[str]:
        """Get common 404 page indicators"""
        return [
            # English indicators
            'page not found', 'not found', '404', 'file not found',
            'the requested url', 'page does not exist', 'page cannot be found',
            'sorry, the page you are looking for', 'oops! page not found',
            'this page does not exist', 'requested page not found',
            'the page you requested', 'error 404', 'http 404',
            
            # Russian indicators
            'страница не найдена', 'файл не найден', 'ошибка 404',
            'запрашиваемая страница', 'страница не существует',
            
            # Generic error indicators
            'access denied', 'forbidden', 'unauthorized',
            'internal server error', 'service unavailable',
            'bad request', 'method not allowed',
            
            # Common 404 page elements
            'go back', 'return to homepage', 'home page',
            'site map', 'search our site', 'try again',
            'check the url', 'verify the address'
        ]
    
    @staticmethod
    def get_valid_content_indicators() -> List[str]:
        """Get indicators that suggest valid content (not 404)"""
        return [
            # Form elements
            '<form', '<input', '<textarea', '<select', '<button',
            
            # Content elements
            '<article', '<section', '<main', '<div class=', '<div id=',
            
            # Navigation elements
            '<nav', '<menu', '<ul', '<ol', '<li>',
            
            # Media elements
            '<img', '<video', '<audio', '<iframe',
            
            # Interactive elements
            'onclick', 'onsubmit', 'javascript:', 'function(',
            
            # Data indicators
            '<table', '<tr', '<td', '<th',
            
            # Common valid page elements
            'login', 'register', 'search', 'contact', 'about',
            'products', 'services', 'news', 'blog', 'gallery'
        ]
    
    @staticmethod
    def get_404_title_patterns() -> List[str]:
        """Get common 404 page title patterns"""
        return [
            r'404.*not.*found',
            r'not.*found.*404',
            r'page.*not.*found',
            r'file.*not.*found',
            r'error.*404',
            r'404.*error',
            r'not.*found',
            r'страница.*не.*найдена',
            r'файл.*не.*найден',
            r'ошибка.*404'
        ]
    
    @staticmethod
    def detect_real_404(response_text: str, response_code: int, content_length: int, 
                       baseline_response: str = None) -> Tuple[bool, str, float]:
        """
        Detect if response is actually a 404 page despite 200 status code
        Uses multiple detection methods for better accuracy
        Returns (is_404, evidence, confidence_score)
        """
        if response_code == 404:
            return True, f"HTTP 404 status code", 1.0
        
        if response_code != 200:
            return False, f"HTTP {response_code} - not a 200 response", 0.0
        
        # Use multiple detection methods
        methods_results = []
        
        # Method 1: Content similarity analysis
        similarity_result = Real404Detector._detect_by_similarity(response_text, baseline_response)
        methods_results.append(similarity_result)
        
        # Method 2: URL path analysis
        path_result = Real404Detector._detect_by_url_path_patterns(response_text)
        methods_results.append(path_result)
        
        # Method 3: Content structure analysis
        structure_result = Real404Detector._detect_by_content_structure(response_text, content_length)
        methods_results.append(structure_result)
        
        # Method 4: Template consistency analysis
        template_result = Real404Detector._detect_by_template_consistency(response_text)
        methods_results.append(template_result)
        
        # Combine results from all methods
        total_confidence = 0.0
        evidence_parts = []
        
        for is_404, evidence, confidence in methods_results:
            if is_404:
                total_confidence += confidence
                evidence_parts.append(evidence)
        
        # Average confidence across methods
        final_confidence = min(total_confidence / len(methods_results), 1.0)
        
        # Decision threshold
        is_404 = final_confidence >= 0.4
        
        if evidence_parts:
            combined_evidence = f"Real 404 detected (confidence: {final_confidence:.2f}): {'; '.join(evidence_parts)}"
        else:
            combined_evidence = f"Valid content detected (confidence: {1.0 - final_confidence:.2f})"
        
        return is_404, combined_evidence, final_confidence
    
    @staticmethod
    def _calculate_similarity(text1: str, text2: str) -> float:
        """Calculate similarity between two text strings"""
        return SequenceMatcher(None, text1, text2).ratio()
    
    @staticmethod
    def generate_baseline_404(base_url: str, session=None) -> Tuple[str, int]:
        """
        Generate multiple baseline 404 responses by requesting non-existent resources
        Returns (response_text, content_length) of the most representative 404
        """
        import requests
        import random
        import string
        
        baseline_responses = []
        
        # Generate multiple test URLs with different patterns
        test_patterns = [
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=15))}.html",
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}.php",
            f"nonexistent_{''.join(random.choices(string.ascii_lowercase, k=8))}.txt",
            f"missing_{''.join(random.choices(string.digits, k=6))}.asp"
        ]
        
        for pattern in test_patterns:
            test_url = f"{base_url.rstrip('/')}/{pattern}"
            
            try:
                if session:
                    response = session.get(test_url, timeout=10, verify=False)
                else:
                    response = requests.get(test_url, timeout=10, verify=False)
                
                baseline_responses.append((response.text, len(response.text)))
            except:
                continue
        
        if not baseline_responses:
            return "", 0
        
        # Return the most common response (by length similarity)
        if len(baseline_responses) == 1:
            return baseline_responses[0]
        
        # Find the most representative response
        length_counts = {}
        for text, length in baseline_responses:
            length_range = (length // 100) * 100  # Group by 100-byte ranges
            if length_range not in length_counts:
                length_counts[length_range] = []
            length_counts[length_range].append((text, length))
        
        # Return response from most common length range
        most_common_range = max(length_counts.keys(), key=lambda k: len(length_counts[k]))
        return length_counts[most_common_range][0]
    
    @staticmethod
    def is_valid_content(response_text: str, response_code: int, baseline_404: str = None) -> Tuple[bool, str]:
        """
        Check if response contains valid content (not a 404 page)
        Returns (is_valid, reason)
        """
        is_404, evidence, confidence = Real404Detector.detect_real_404(
            response_text, response_code, len(response_text), baseline_404
        )
        
        if is_404:
            return False, f"Detected as 404 page: {evidence}"
        
        # Additional checks for valid content
        if response_code == 200:
            # Check for substantial content
            text_content = re.sub(r'<[^>]+>', '', response_text).strip()
            if len(text_content) > 100:
                return True, f"Valid content with {len(text_content)} characters"
            else:
                return False, f"Insufficient content: {len(text_content)} characters"
        
        return False, f"HTTP {response_code} status code"
    
    @staticmethod
    def get_response_fingerprint(response_text: str) -> str:
        """
        Generate fingerprint of response for comparison
        """
        import hashlib
        
        # Normalize response for fingerprinting
        normalized = re.sub(r'\s+', ' ', response_text.lower())
        normalized = re.sub(r'<[^>]+>', '', normalized)  # Remove HTML tags
        normalized = normalized.strip()
        
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    @staticmethod
    def _detect_by_similarity(response_text: str, baseline_response: str = None) -> Tuple[bool, str, float]:
        """Method 1: Detect 404 by comparing with baseline response"""
        if not baseline_response:
            return False, "No baseline for comparison", 0.0
        
        similarity = Real404Detector._calculate_similarity(response_text, baseline_response)
        
        if similarity > 0.85:
            return True, f"High similarity to baseline 404: {similarity:.2f}", 0.8
        elif similarity > 0.7:
            return True, f"Moderate similarity to baseline 404: {similarity:.2f}", 0.6
        
        return False, f"Low similarity to baseline: {similarity:.2f}", 0.0
    
    @staticmethod
    def _detect_by_url_path_patterns(response_text: str) -> Tuple[bool, str, float]:
        """Method 2: Detect 404 by analyzing URL patterns in response"""
        response_lower = response_text.lower()
        
        # Look for patterns that suggest the requested path doesn't exist
        path_indicators = [
            r'["\'/][a-zA-Z0-9_-]+\.php/[a-zA-Z0-9_.-]+',  # login.php/123.php pattern
            r'invalid.*path', r'path.*not.*found', r'invalid.*url',
            r'file.*path.*error', r'directory.*not.*found'
        ]
        
        found_patterns = []
        for pattern in path_indicators:
            matches = re.findall(pattern, response_lower)
            if matches:
                found_patterns.extend(matches[:2])  # Limit to 2 matches per pattern
        
        if found_patterns:
            return True, f"Invalid path patterns found: {', '.join(found_patterns)}", 0.7
        
        return False, "No invalid path patterns detected", 0.0
    
    @staticmethod
    def _detect_by_content_structure(response_text: str, content_length: int) -> Tuple[bool, str, float]:
        """Method 3: Detect 404 by analyzing content structure and indicators"""
        response_lower = response_text.lower()
        confidence = 0.0
        evidence_parts = []
        
        # Check for 404 indicators
        indicators = Real404Detector.get_404_indicators()
        found_indicators = [ind for ind in indicators if ind.lower() in response_lower]
        
        if found_indicators:
            confidence += 0.4
            evidence_parts.append(f"404 indicators: {', '.join(found_indicators[:3])}")
        
        # Check for valid content indicators (negative evidence)
        valid_indicators = Real404Detector.get_valid_content_indicators()
        found_valid = [ind for ind in valid_indicators if ind.lower() in response_lower]
        
        if found_valid:
            confidence -= 0.3  # Reduce confidence if valid content found
            evidence_parts.append(f"Valid content found: {len(found_valid)} indicators")
        
        # Check title patterns
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response_text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip().lower()
            title_patterns = Real404Detector.get_404_title_patterns()
            
            for pattern in title_patterns:
                if re.search(pattern, title, re.IGNORECASE):
                    confidence += 0.5
                    evidence_parts.append(f"404 title pattern: '{title[:50]}'")
                    break
        
        # Content length analysis
        if content_length < 1000:
            confidence += 0.2
            evidence_parts.append(f"Short response: {content_length} bytes")
        elif content_length > 5000:
            confidence -= 0.1  # Large responses are less likely to be 404
        
        is_404 = confidence > 0.3
        
        if evidence_parts:
            evidence = '; '.join(evidence_parts)
        else:
            evidence = "No structural 404 indicators found"
        
        return is_404, evidence, max(0.0, min(1.0, confidence))
    
    @staticmethod
    def _detect_by_template_consistency(response_text: str) -> Tuple[bool, str, float]:
        """Method 4: Detect 404 by checking if response uses same template but shows error content"""
        response_lower = response_text.lower()
        
        # Look for template elements that suggest this is the same site template
        template_indicators = [
            r'<title[^>]*>.*?(test|demo|acunetix|vulnerability|scanner).*?</title>',
            r'acunetix', r'test.*demonstration', r'vulnerability.*scanner',
            r'©\d{4}.*acunetix', r'warning.*not.*real.*shop'
        ]
        
        has_template = False
        for pattern in template_indicators:
            if re.search(pattern, response_lower, re.IGNORECASE):
                has_template = True
                break
        
        if not has_template:
            return False, "Different template or no template detected", 0.0
        
        # If it has the same template, check if the main content area is missing/different
        content_indicators = [
            # Look for main content that would be present in valid pages
            r'<div[^>]*class[^>]*content', r'<main', r'<article',
            r'<div[^>]*id[^>]*content', r'<section[^>]*class[^>]*main'
        ]
        
        has_main_content = any(re.search(pattern, response_lower) for pattern in content_indicators)
        
        # Check for navigation that points to the same page (circular reference)
        nav_patterns = [
            r'<a[^>]*href[^>]*login\.php[^>]*>.*?login.*?</a>',  # Link to login.php in login page
            r'<a[^>]*href[^>]*signup\.php[^>]*>.*?signup.*?</a>'  # Self-referential links
        ]
        
        has_self_reference = any(re.search(pattern, response_lower) for pattern in nav_patterns)
        
        if has_template and not has_main_content:
            return True, "Same template but missing main content", 0.6
        elif has_template and has_self_reference:
            return True, "Template with self-referential navigation", 0.5
        
        return False, "Template with valid content structure", 0.0
