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
    def get_php_error_indicators() -> List[str]:
        """Get PHP error indicators that suggest invalid paths"""
        return [
            # PHP database errors (common when invalid paths cause SQL issues)
            'mysql_fetch_array() expects parameter 1 to be resource, null given',
            'mysql_fetch_array() expects parameter 1 to be resource',
            'mysql_query() expects parameter 1 to be string, null given',
            'mysql_num_rows() expects parameter 1 to be resource',
            'mysqli_fetch_array() expects parameter 1 to be mysqli_result',
            'mysqli_query() expects parameter 1 to be mysqli',
            
            # PHP file/path errors
            'failed to open stream: no such file or directory',
            'include(): failed opening',
            'require(): failed opening',
            'fopen(): failed to open stream',
            'file_get_contents(): failed to open stream',
            
            # PHP undefined variable/index errors (common with invalid parameters)
            'undefined index:', 'undefined variable:',
            'undefined offset:', 'undefined property:',
            
            # PHP function errors
            'call to undefined function',
            'fatal error:', 'parse error:',
            'warning:', 'notice:', 'strict standards:',
            
            # ASP.NET errors
            'server error in', 'runtime error',
            'compilation error', 'parser error',
            
            # General application errors
            'application error', 'system error',
            'database error', 'connection error'
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
                       baseline_response: str = None, baseline_size: int = 0) -> Tuple[bool, str, float]:
        """
        Detect if response is actually a 404 page despite 200 status code
        Uses baseline patterns and size analysis for accurate detection
        Returns (is_404, evidence, confidence_score)
        """
        if response_code == 404:
            return True, f"HTTP 404 status code", 1.0
        
        if response_code != 200:
            return False, f"HTTP {response_code} - not a 200 response", 0.0
        
        # If no baseline, use basic detection
        if not baseline_response:
            return Real404Detector._detect_without_baseline(response_text, content_length)
        
        # Size-based detection (high priority)
        size_confidence = Real404Detector._analyze_size_similarity(content_length, baseline_size)
        if size_confidence > 0.9:
            return True, f"Size match with 404 baseline: {content_length} bytes (baseline: {baseline_size})", size_confidence
        
        # Primary method: Compare with established 404 baseline
        current_fingerprint = Real404Detector.get_response_fingerprint(response_text)
        baseline_fingerprint = Real404Detector.get_response_fingerprint(baseline_response)
        
        # Exact fingerprint match = definitely 404
        if current_fingerprint == baseline_fingerprint:
            return True, f"Exact match with 404 baseline (fingerprint: {current_fingerprint})", 1.0
        
        # Calculate detailed similarity
        similarity = Real404Detector._calculate_similarity(response_text, baseline_response)
        
        # Combine size and content similarity for better accuracy
        combined_confidence = (similarity + size_confidence) / 2
        
        # High combined confidence = likely 404
        if combined_confidence > 0.85:
            return True, f"High combined confidence: content={similarity:.3f}, size={size_confidence:.3f}", combined_confidence
        elif similarity > 0.8:
            return True, f"High content similarity to 404 baseline: {similarity:.3f}", 0.85
        elif similarity > 0.7:
            return True, f"Moderate content similarity to 404 baseline: {similarity:.3f}", 0.75
        
        # Use additional detection methods for edge cases
        methods_results = []
        
        # Method 1: URL path analysis (for path injection patterns)
        path_result = Real404Detector._detect_by_url_path_patterns(response_text)
        methods_results.append(path_result)
        
        # Method 2: Content structure analysis (PHP errors, etc.)
        structure_result = Real404Detector._detect_by_content_structure(response_text, content_length)
        methods_results.append(structure_result)
        
        # Method 3: Template consistency analysis
        template_result = Real404Detector._detect_by_template_consistency(response_text)
        methods_results.append(template_result)
        
        # Combine additional methods
        additional_confidence = 0.0
        evidence_parts = []
        
        for is_404, evidence, confidence in methods_results:
            if is_404:
                additional_confidence += confidence
                evidence_parts.append(evidence)
        
        # Average additional confidence
        if methods_results:
            additional_confidence = additional_confidence / len(methods_results)
        
        # Final decision combining all factors
        final_confidence = (similarity + size_confidence + additional_confidence) / 3
        
        if final_confidence > 0.6:
            combined_evidence = f"Combined analysis: content={similarity:.3f}, size={size_confidence:.3f}, additional={additional_confidence:.3f}"
            if evidence_parts:
                combined_evidence += f" - {'; '.join(evidence_parts)}"
            return True, combined_evidence, final_confidence
        
        # Not a 404
        return False, f"Valid content (similarity: {similarity:.3f}, size_match: {size_confidence:.3f})", 0.0
    
    @staticmethod
    def _calculate_similarity(text1: str, text2: str) -> float:
        """Calculate similarity between two text strings"""
        return SequenceMatcher(None, text1, text2).ratio()
    
    @staticmethod
    def generate_baseline_404(base_url: str, session=None) -> Tuple[str, int]:
        """
        Generate baseline 404 patterns by making 10 different fake requests
        Returns (most_common_404_response, content_length)
        """
        import requests
        import random
        import string
        from collections import Counter
        
        print(f"    [REAL404] Generating 10 fake requests to establish 404 patterns...")
        
        baseline_responses = []
        response_fingerprints = []
        
        # Generate 10 different fake request patterns
        fake_patterns = [
            # Random files with different extensions
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=20))}.php",
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=18))}.html",
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}.txt",
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=14))}.asp",
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}.jsp",
            
            # Fake directories
            f"nonexistent_{''.join(random.choices(string.ascii_lowercase, k=10))}/",
            f"missing_{''.join(random.choices(string.ascii_lowercase, k=8))}/index.php",
            
            # Path traversal style (should be 404)
            f"../{''.join(random.choices(string.ascii_lowercase, k=12))}.php",
            f"./fake_{''.join(random.choices(string.digits, k=8))}.html",
            
            # Completely random path
            f"{''.join(random.choices(string.ascii_lowercase + string.digits + '_-', k=25))}"
        ]
        
        successful_requests = 0
        
        for i, pattern in enumerate(fake_patterns, 1):
            test_url = f"{base_url.rstrip('/')}/{pattern}"
            
            try:
                print(f"    [REAL404] Fake request {i}/10: {pattern[:30]}...")
                
                if session:
                    response = session.get(test_url, timeout=10, verify=False)
                else:
                    response = requests.get(test_url, timeout=10, verify=False)
                
                # Store response data
                response_data = {
                    'text': response.text,
                    'length': len(response.text),
                    'status_code': response.status_code,
                    'url': test_url
                }
                
                baseline_responses.append(response_data)
                
                # Generate fingerprint for pattern matching
                fingerprint = Real404Detector.get_response_fingerprint(response.text)
                response_fingerprints.append(fingerprint)
                
                successful_requests += 1
                
                print(f"    [REAL404] Response {i}: {response.status_code} - {len(response.text)} bytes - {fingerprint}")
                
            except Exception as e:
                print(f"    [REAL404] Failed request {i}: {e}")
                continue
        
        if successful_requests == 0:
            print(f"    [REAL404] No successful fake requests - cannot establish baseline")
            return "", 0
        
        print(f"    [REAL404] Completed {successful_requests}/10 fake requests")
        
        # Analyze patterns in responses
        fingerprint_counts = Counter(response_fingerprints)
        most_common_fingerprint = fingerprint_counts.most_common(1)[0][0]
        
        print(f"    [REAL404] Most common fingerprint: {most_common_fingerprint} (appears {fingerprint_counts[most_common_fingerprint]} times)")
        
        # Calculate average size for size-based detection
        sizes = [r['length'] for r in baseline_responses]
        average_size = sum(sizes) / len(sizes) if sizes else 0
        
        print(f"    [REAL404] Size analysis: min={min(sizes)}, max={max(sizes)}, avg={average_size:.0f}")
        
        # Find response with most common fingerprint
        for response_data in baseline_responses:
            if Real404Detector.get_response_fingerprint(response_data['text']) == most_common_fingerprint:
                print(f"    [REAL404] Selected baseline: {response_data['status_code']} - {response_data['length']} bytes")
                return response_data['text'], int(average_size)
        
        # Fallback: return first response with average size
        if baseline_responses:
            fallback = baseline_responses[0]
            print(f"    [REAL404] Using fallback baseline: {fallback['status_code']} - {int(average_size)} bytes (avg)")
            return fallback['text'], int(average_size)
        
        return "", 0
    
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
        Uses multiple characteristics for better pattern matching
        """
        import hashlib
        
        # Extract key characteristics for fingerprinting
        characteristics = []
        
        # 1. Content length range
        length_range = (len(response_text) // 500) * 500  # Group by 500-byte ranges
        characteristics.append(f"len:{length_range}")
        
        # 2. Title content (normalized)
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response_text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = re.sub(r'\s+', ' ', title_match.group(1).strip().lower())
            characteristics.append(f"title:{title[:50]}")
        
        # 3. Main text content (without HTML, normalized)
        text_content = re.sub(r'<[^>]+>', '', response_text)
        text_content = re.sub(r'\s+', ' ', text_content.lower()).strip()
        
        # Take first and last parts of content for fingerprint
        if len(text_content) > 200:
            content_start = text_content[:100]
            content_end = text_content[-100:]
            characteristics.append(f"start:{content_start}")
            characteristics.append(f"end:{content_end}")
        else:
            characteristics.append(f"full:{text_content}")
        
        # 4. Error patterns (PHP errors, etc.)
        php_errors = Real404Detector.get_php_error_indicators()
        found_errors = [err for err in php_errors if err.lower() in response_text.lower()]
        if found_errors:
            characteristics.append(f"errors:{','.join(found_errors[:3])}")
        
        # 5. Template indicators
        if 'acunetix' in response_text.lower():
            characteristics.append("template:acunetix")
        
        # Create fingerprint from characteristics
        fingerprint_data = '|'.join(characteristics)
        return hashlib.md5(fingerprint_data.encode()).hexdigest()[:16]
    
    @staticmethod
    def _analyze_size_similarity(current_size: int, baseline_size: int) -> float:
        """
        Analyze size similarity between current response and baseline 404
        Returns confidence score (0.0 to 1.0)
        """
        if baseline_size == 0:
            return 0.0
        
        # Calculate size difference percentage
        size_diff = abs(current_size - baseline_size)
        size_diff_percent = size_diff / baseline_size if baseline_size > 0 else 1.0
        
        # Very close sizes (within 5%) = high confidence
        if size_diff_percent <= 0.05:
            return 0.95
        # Close sizes (within 10%) = good confidence  
        elif size_diff_percent <= 0.10:
            return 0.80
        # Moderate difference (within 20%) = medium confidence
        elif size_diff_percent <= 0.20:
            return 0.60
        # Large difference (within 50%) = low confidence
        elif size_diff_percent <= 0.50:
            return 0.30
        # Very different sizes = no confidence
        else:
            return 0.0
    
    @staticmethod
    def _detect_without_baseline(response_text: str, content_length: int) -> Tuple[bool, str, float]:
        """
        Fallback detection method when no baseline is available
        """
        confidence = 0.0
        evidence_parts = []
        
        # Check for obvious 404 indicators
        indicators = Real404Detector.get_404_indicators()
        found_indicators = [ind for ind in indicators if ind.lower() in response_text.lower()]
        
        if found_indicators:
            confidence += 0.6
            evidence_parts.append(f"404 indicators: {', '.join(found_indicators[:3])}")
        
        # Check for PHP errors (strong indicator)
        php_errors = Real404Detector.get_php_error_indicators()
        found_php_errors = [err for err in php_errors if err.lower() in response_text.lower()]
        
        if found_php_errors:
            confidence += 0.8
            evidence_parts.append(f"PHP errors: {', '.join(found_php_errors[:2])}")
        
        # Enhanced content length analysis
        if content_length < 500:
            confidence += 0.4
            evidence_parts.append(f"Very short response: {content_length} bytes")
        elif content_length < 1000:
            confidence += 0.2
            evidence_parts.append(f"Short response: {content_length} bytes")
        elif content_length > 10000:
            confidence -= 0.3  # Large responses are less likely to be 404
            evidence_parts.append(f"Large response: {content_length} bytes (likely valid)")
        
        # Check for valid content indicators (reduce confidence)
        valid_indicators = Real404Detector.get_valid_content_indicators()
        found_valid = [ind for ind in valid_indicators if ind.lower() in response_text.lower()]
        
        if found_valid and len(found_valid) > 3:
            confidence -= 0.4
            evidence_parts.append(f"Valid content indicators: {len(found_valid)} found")
        
        is_404 = confidence > 0.5
        
        if evidence_parts:
            evidence = f"No baseline - fallback detection: {'; '.join(evidence_parts)}"
        else:
            evidence = "No baseline - no clear 404 indicators found"
        
        return is_404, evidence, max(0.0, min(confidence, 1.0))
    
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
        
        # Check for PHP/application error indicators (high confidence for 404)
        php_errors = Real404Detector.get_php_error_indicators()
        found_php_errors = [err for err in php_errors if err.lower() in response_lower]
        
        if found_php_errors:
            confidence += 0.7  # High confidence - technical errors usually indicate invalid paths
            evidence_parts.append(f"PHP/App errors: {', '.join(found_php_errors[:2])}")
        
        # Check for valid content indicators (negative evidence)
        valid_indicators = Real404Detector.get_valid_content_indicators()
        found_valid = [ind for ind in valid_indicators if ind.lower() in response_lower]
        
        if found_valid and not found_php_errors:  # Don't reduce confidence if we have PHP errors
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
        
        # Check for PHP errors in template (strong indicator of 404)
        php_error_patterns = [
            r'warning:.*mysql_fetch_array\(\).*expects parameter 1 to be resource',
            r'warning:.*mysql_.*\(\).*expects parameter',
            r'warning:.*failed to open stream',
            r'fatal error:', r'parse error:', r'notice:.*undefined'
        ]
        
        has_php_errors = any(re.search(pattern, response_lower, re.IGNORECASE) 
                           for pattern in php_error_patterns)
        
        if has_template and has_php_errors:
            return True, "Template with PHP errors (invalid path)", 0.8
        
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
