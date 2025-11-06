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
        Returns (is_404, evidence, confidence_score)
        """
        if response_code == 404:
            return True, f"HTTP 404 status code", 1.0
        
        if response_code != 200:
            return False, f"HTTP {response_code} - not a 200 response", 0.0
        
        confidence_score = 0.0
        evidence_parts = []
        
        response_lower = response_text.lower()
        
        # Check for 404 indicators in content
        indicators = Real404Detector.get_404_indicators()
        found_indicators = []
        
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
                confidence_score += 0.1
        
        if found_indicators:
            evidence_parts.append(f"Found 404 indicators: {', '.join(found_indicators[:5])}")
        
        # Check title for 404 patterns
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response_text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            title_patterns = Real404Detector.get_404_title_patterns()
            
            for pattern in title_patterns:
                if re.search(pattern, title, re.IGNORECASE):
                    evidence_parts.append(f"404 pattern in title: '{title}'")
                    confidence_score += 0.3
                    break
        
        # Check for very short responses (likely error pages)
        if content_length < 500:
            evidence_parts.append(f"Very short response: {content_length} bytes")
            confidence_score += 0.2
        
        # Check for common 404 page structure
        if '<h1' in response_lower and any(ind in response_lower for ind in ['404', 'not found', 'error']):
            evidence_parts.append("404 error in heading structure")
            confidence_score += 0.2
        
        # Compare with baseline response if available
        if baseline_response:
            similarity = Real404Detector._calculate_similarity(response_text, baseline_response)
            if similarity > 0.8:  # Very similar to baseline 404
                evidence_parts.append(f"High similarity to baseline 404: {similarity:.2f}")
                confidence_score += 0.4
        
        # Check for redirect indicators
        if any(word in response_lower for word in ['redirect', 'moved', 'location']):
            evidence_parts.append("Contains redirect indicators")
            confidence_score += 0.1
        
        # Check for empty or minimal content
        text_content = re.sub(r'<[^>]+>', '', response_text).strip()
        if len(text_content) < 100:
            evidence_parts.append(f"Minimal text content: {len(text_content)} characters")
            confidence_score += 0.2
        
        # Determine if this is likely a 404
        is_404 = confidence_score >= 0.5
        
        if evidence_parts:
            evidence = f"Real 404 detected (confidence: {confidence_score:.2f}): {'; '.join(evidence_parts)}"
        else:
            evidence = f"No 404 indicators found (confidence: {confidence_score:.2f})"
        
        return is_404, evidence, confidence_score
    
    @staticmethod
    def _calculate_similarity(text1: str, text2: str) -> float:
        """Calculate similarity between two text strings"""
        return SequenceMatcher(None, text1, text2).ratio()
    
    @staticmethod
    def generate_baseline_404(base_url: str, session=None) -> Tuple[str, int]:
        """
        Generate baseline 404 response by requesting non-existent resource
        Returns (response_text, content_length)
        """
        import requests
        import random
        import string
        
        # Generate random non-existent filename
        random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        test_url = f"{base_url.rstrip('/')}/{random_name}.html"
        
        try:
            if session:
                response = session.get(test_url, timeout=10, verify=False)
            else:
                response = requests.get(test_url, timeout=10, verify=False)
            
            return response.text, len(response.text)
        except:
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
        """
        import hashlib
        
        # Normalize response for fingerprinting
        normalized = re.sub(r'\s+', ' ', response_text.lower())
        normalized = re.sub(r'<[^>]+>', '', normalized)  # Remove HTML tags
        normalized = normalized.strip()
        
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
