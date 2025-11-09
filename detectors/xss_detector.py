"""
Enhanced XSS vulnerability detection with context analysis and DOM XSS support
"""

import re
import html
from typing import Dict, Any, List, Tuple
from urllib.parse import unquote

class XSSDetector:
    """Enhanced XSS vulnerability detection logic"""
    
    @staticmethod
    def detect_reflected_xss(payload: str, response_text: str, response_code: int) -> Dict[str, Any]:
        """
        Enhanced XSS detection with context analysis and confidence scoring
        Returns: {
            'vulnerable': bool,
            'xss_type': str,
            'detection_method': str,
            'confidence': float,
            'context': str,
            'evidence': str
        }
        """
        try:
            # Skip error responses that are likely unrelated
            if response_code >= 500:
                return {
                    'vulnerable': False,
                    'xss_type': 'None',
                    'detection_method': 'server_error',
                    'confidence': 0.0,
                    'context': 'error',
                    'evidence': f'HTTP {response_code} server error response'
                }
            
            # Check for payload reflection with various encodings
            reflection_result = XSSDetector._analyze_payload_reflection(payload, response_text)
            
            if not reflection_result['reflected']:
                return {
                    'vulnerable': False,
                    'xss_type': 'None',
                    'detection_method': 'no_reflection',
                    'confidence': 0.0,
                    'context': 'not_reflected',
                    'evidence': 'Payload not reflected in response'
                }
            
            # Analyze the context where payload appears
            context_analysis = XSSDetector._analyze_xss_context(payload, response_text, reflection_result['positions'])
            
            # Check for DOM XSS indicators
            dom_analysis = XSSDetector._analyze_dom_xss(payload, response_text)
            
            # Check for false positives
            if XSSDetector._is_likely_false_positive(payload, response_text):
                # Reduce confidence for potential false positives
                context_analysis['confidence'] *= 0.6
                context_analysis['evidence'] += " (potential false positive detected)"
            
            # Determine XSS type and confidence
            if context_analysis['is_dangerous'] and context_analysis['confidence'] >= 0.5:
                xss_type = 'Reflected XSS'
                confidence = context_analysis['confidence']
                detection_method = f"context_analysis_{context_analysis['context']}"
                evidence = context_analysis['evidence']
            elif dom_analysis['vulnerable'] and dom_analysis['confidence'] >= 0.4:
                xss_type = 'DOM XSS'
                confidence = dom_analysis['confidence']
                detection_method = 'dom_analysis'
                evidence = dom_analysis['evidence']
            else:
                # Check for potential XSS based on payload characteristics
                potential_result = XSSDetector._analyze_potential_xss(payload, response_text)
                if potential_result['potential'] and potential_result['confidence'] >= 0.3:
                    xss_type = 'Potential XSS'
                    confidence = potential_result['confidence']
                    detection_method = 'potential_analysis'
                    evidence = potential_result['evidence']
                else:
                    return {
                        'vulnerable': False,
                        'xss_type': 'None',
                        'detection_method': 'safe_context',
                        'confidence': context_analysis.get('confidence', 0.0),
                        'context': context_analysis.get('context', 'safe'),
                        'evidence': 'Payload reflected in safe context'
                    }
            
            return {
                'vulnerable': True,
                'xss_type': xss_type,
                'detection_method': detection_method,
                'confidence': confidence,
                'context': context_analysis.get('context', 'unknown'),
                'evidence': evidence
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'xss_type': 'None',
                'detection_method': 'detection_error',
                'confidence': 0.0,
                'context': 'error',
                'evidence': f'Detection error: {e}'
            }
    
    @staticmethod
    def _analyze_payload_reflection(payload: str, response_text: str) -> Dict[str, Any]:
        """Analyze if and how payload is reflected in response"""
        positions = []
        
        # Check various encodings of the payload
        payload_variants = [
            payload,  # Original
            html.escape(payload),  # HTML encoded
            html.escape(payload, quote=False),  # HTML encoded without quotes
            payload.replace('<', '&lt;').replace('>', '&gt;'),  # Manual HTML encoding
            payload.replace('"', '&quot;').replace("'", '&#x27;'),  # Quote encoding
            payload.replace('<', '%3C').replace('>', '%3E'),  # URL encoding
            unquote(payload),  # URL decoded
            payload.lower(),  # Lowercase
            payload.upper(),  # Uppercase
        ]
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variants = []
        for variant in payload_variants:
            if variant not in seen:
                seen.add(variant)
                unique_variants.append(variant)
        
        # Find all positions where payload variants appear
        for variant in unique_variants:
            start = 0
            while True:
                pos = response_text.find(variant, start)
                if pos == -1:
                    break
                positions.append({
                    'position': pos,
                    'variant': variant,
                    'length': len(variant)
                })
                start = pos + 1
        
        return {
            'reflected': len(positions) > 0,
            'positions': positions,
            'variants_found': len(positions)
        }
    
    @staticmethod
    def _analyze_xss_context(payload: str, response_text: str, positions: List[Dict]) -> Dict[str, Any]:
        """Analyze the context where XSS payload appears"""
        if not positions:
            return {
                'is_dangerous': False,
                'context': 'not_found',
                'confidence': 0.0,
                'evidence': 'Payload not found in response'
            }
        
        max_confidence = 0.0
        best_context = 'unknown'
        best_evidence = ''
        
        for pos_info in positions:
            pos = pos_info['position']
            variant = pos_info['variant']
            
            # Get context around payload (300 chars before and after)
            context_start = max(0, pos - 300)
            context_end = min(len(response_text), pos + len(variant) + 300)
            context = response_text[context_start:context_end].lower()
            
            # Analyze different contexts
            context_analysis = XSSDetector._analyze_context_type(context, variant, pos - context_start)
            
            if context_analysis['confidence'] > max_confidence:
                max_confidence = context_analysis['confidence']
                best_context = context_analysis['context']
                best_evidence = context_analysis['evidence']
        
        return {
            'is_dangerous': max_confidence >= 0.5,
            'context': best_context,
            'confidence': max_confidence,
            'evidence': best_evidence
        }
    
    @staticmethod
    def _analyze_context_type(context: str, variant: str, relative_pos: int) -> Dict[str, Any]:
        """Analyze specific context type and danger level"""
        variant_lower = variant.lower()
        
        # Script tag context (highest confidence)
        if '<script' in context and '</script>' in context:
            script_start = context.find('<script')
            script_end = context.find('</script>') + 9
            if script_start < relative_pos < script_end:
                return {
                    'context': 'script_tag',
                    'confidence': 0.98,
                    'evidence': 'Payload injected inside script tag - critical XSS'
                }
        
        # Event handler contexts
        event_patterns = [
            (r'<[^>]*\s+on\w+\s*=\s*["\']?[^"\']*' + re.escape(variant), 'event_handler', 0.95),
            (r'<[^>]*\s+onclick\s*=\s*["\']?[^"\']*' + re.escape(variant), 'onclick_handler', 0.95),
            (r'<[^>]*\s+onload\s*=\s*["\']?[^"\']*' + re.escape(variant), 'onload_handler', 0.95),
            (r'<[^>]*\s+onerror\s*=\s*["\']?[^"\']*' + re.escape(variant), 'onerror_handler', 0.95),
            (r'<[^>]*\s+onmouseover\s*=\s*["\']?[^"\']*' + re.escape(variant), 'onmouseover_handler', 0.90),
        ]
        
        for pattern, context_name, confidence in event_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return {
                    'context': context_name,
                    'confidence': confidence,
                    'evidence': f'Payload injected in {context_name.replace("_", " ")} - high risk XSS'
                }
        
        # JavaScript URL context
        if re.search(r'javascript:[^"\']*' + re.escape(variant), context, re.IGNORECASE):
            return {
                'context': 'javascript_url',
                'confidence': 0.90,
                'evidence': 'Payload in javascript: URL context - high risk XSS'
            }
        
        # HTML attribute contexts
        attribute_patterns = [
            (r'<[^>]*\s+href\s*=\s*["\']?[^"\']*' + re.escape(variant), 'href_attribute', 0.75),
            (r'<[^>]*\s+src\s*=\s*["\']?[^"\']*' + re.escape(variant), 'src_attribute', 0.80),
            (r'<[^>]*\s+action\s*=\s*["\']?[^"\']*' + re.escape(variant), 'action_attribute', 0.70),
            (r'<[^>]*\s+\w+\s*=\s*["\']?[^"\']*' + re.escape(variant), 'generic_attribute', 0.60),
        ]
        
        for pattern, context_name, confidence in attribute_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return {
                    'context': context_name,
                    'confidence': confidence,
                    'evidence': f'Payload injected in {context_name.replace("_", " ")}'
                }
        
        # JavaScript variable context
        js_contexts = [
            (r'var\s+\w+\s*=\s*["\']?[^"\']*' + re.escape(variant), 'javascript_variable', 0.70),
            (r'function\s*\([^)]*\)\s*{[^}]*' + re.escape(variant), 'javascript_function', 0.75),
            (r'eval\s*\([^)]*' + re.escape(variant), 'javascript_eval', 0.95),
            (r'settimeout\s*\([^)]*' + re.escape(variant), 'javascript_settimeout', 0.90),
            (r'setinterval\s*\([^)]*' + re.escape(variant), 'javascript_setinterval', 0.90),
        ]
        
        for pattern, context_name, confidence in js_contexts:
            if re.search(pattern, context, re.IGNORECASE):
                return {
                    'context': context_name,
                    'confidence': confidence,
                    'evidence': f'Payload in {context_name.replace("_", " ")} context'
                }
        
        # HTML tag context
        if re.search(r'<[^>]*' + re.escape(variant) + r'[^>]*>', context, re.IGNORECASE):
            return {
                'context': 'html_tag',
                'confidence': 0.65,
                'evidence': 'Payload injected in HTML tag'
            }
        
        # CSS context
        css_indicators = ['<style', 'style=', 'expression(', 'url(']
        if any(css_indicator in context for css_indicator in css_indicators):
            return {
                'context': 'css',
                'confidence': 0.60,
                'evidence': 'Payload in CSS context'
            }
        
        # Check if payload contains dangerous XSS characters
        dangerous_chars = ['<', '>', '"', "'", '(', ')', ';', 'script', 'alert', 'javascript']
        dangerous_count = sum(1 for char in dangerous_chars if char.lower() in variant_lower)
        
        if dangerous_count >= 3:
            return {
                'context': 'text_with_xss_chars',
                'confidence': 0.40,
                'evidence': f'Payload with {dangerous_count} XSS indicators reflected in text'
            }
        elif dangerous_count >= 1:
            return {
                'context': 'text_with_some_xss_chars',
                'confidence': 0.25,
                'evidence': f'Payload with some XSS characters reflected in text'
            }
        
        # Safe text context
        return {
            'context': 'safe_text',
            'confidence': 0.10,
            'evidence': 'Payload reflected in safe text context'
        }
    
    @staticmethod
    def _analyze_dom_xss(payload: str, response_text: str) -> Dict[str, Any]:
        """Analyze for DOM-based XSS vulnerabilities"""
        response_lower = response_text.lower()
        
        # DOM XSS sources (where data comes from)
        dom_sources = [
            'location.search',
            'location.hash',
            'location.href',
            'document.url',
            'document.referrer',
            'window.name',
            'document.cookie',
            'document.location',
            'window.location',
            'document.baseuri',
        ]
        
        # DOM XSS sinks (where data goes to)
        dom_sinks = [
            'document.write(',
            'document.writeln(',
            'innerhtml',
            'outerhtml',
            'insertadjacenthtml',
            'eval(',
            'settimeout(',
            'setinterval(',
            'function(',
            'execscript(',
            'createelement(',
            'appendchild(',
        ]
        
        sources_found = [source for source in dom_sources if source in response_lower]
        sinks_found = [sink for sink in dom_sinks if sink in response_lower]
        
        # Calculate confidence based on sources and sinks found
        confidence = 0.0
        evidence_parts = []
        
        if sources_found and sinks_found:
            confidence = min(0.85, 0.4 + (len(sources_found) * 0.15) + (len(sinks_found) * 0.15))
            evidence_parts.append(f"DOM sources: {sources_found[:3]}")
            evidence_parts.append(f"DOM sinks: {sinks_found[:3]}")
        elif sources_found:
            confidence = min(0.50, 0.2 + (len(sources_found) * 0.1))
            evidence_parts.append(f"DOM sources found: {sources_found[:3]}")
        elif sinks_found:
            confidence = min(0.40, 0.15 + (len(sinks_found) * 0.1))
            evidence_parts.append(f"DOM sinks found: {sinks_found[:3]}")
        
        # Check for specific DOM XSS patterns
        dom_patterns = [
            r'document\.write\s*\(\s*[^)]*location',
            r'innerHTML\s*=\s*[^;]*location',
            r'eval\s*\(\s*[^)]*location',
            r'setTimeout\s*\(\s*[^)]*location',
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                confidence = max(confidence, 0.80)
                evidence_parts.append(f"DOM XSS pattern detected: {pattern}")
                break
        
        evidence = "; ".join(evidence_parts) if evidence_parts else "No DOM XSS indicators found"
        
        return {
            'vulnerable': confidence >= 0.3,
            'confidence': confidence,
            'evidence': evidence
        }
    
    @staticmethod
    def _analyze_potential_xss(payload: str, response_text: str) -> Dict[str, Any]:
        """Analyze for potential XSS based on payload characteristics"""
        # XSS indicators to look for
        xss_indicators = [
            '<script', 'javascript:', 'onerror=', 'onload=', 'onclick=',
            'onmouseover=', 'onfocus=', 'alert(', 'confirm(', 'prompt(',
            '<img', '<svg', '<iframe', '<object', '<embed', 'eval(',
            'settimeout(', 'setinterval(', 'document.write'
        ]
        
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        # Count XSS indicators in payload
        payload_indicators = [indicator for indicator in xss_indicators if indicator in payload_lower]
        
        # Count XSS indicators in response
        response_indicators = [indicator for indicator in xss_indicators if indicator in response_lower]
        
        if payload_indicators and response_indicators:
            # Check if same indicators appear in both
            common_indicators = set(payload_indicators) & set(response_indicators)
            if common_indicators:
                confidence = min(0.70, 0.3 + (len(common_indicators) * 0.1))
                return {
                    'potential': True,
                    'confidence': confidence,
                    'evidence': f'XSS indicators reflected: {list(common_indicators)[:3]}'
                }
        
        # Check for partial reflection of XSS payloads
        if payload_indicators:
            partial_matches = 0
            for indicator in payload_indicators:
                if indicator[:4] in response_lower:  # Check first 4 chars
                    partial_matches += 1
            
            if partial_matches > 0:
                confidence = min(0.50, 0.2 + (partial_matches * 0.05))
                return {
                    'potential': True,
                    'confidence': confidence,
                    'evidence': f'Partial XSS indicator reflection detected ({partial_matches} matches)'
                }
        
        return {
            'potential': False,
            'confidence': 0.0,
            'evidence': 'No XSS potential detected'
        }
    
    @staticmethod
    def _is_likely_false_positive(payload: str, response_text: str) -> bool:
        """Check if XSS detection is likely a false positive"""
        response_lower = response_text.lower()
        
        # Common false positive patterns
        false_positive_patterns = [
            # Error messages that might contain payload
            'error', 'exception', 'warning', 'notice',
            'invalid', 'malformed', 'syntax error',
            
            # SQL error messages
            'mysql', 'sql syntax', 'query failed',
            'you have an error in your sql syntax',
            
            # Generic application errors
            'application error', 'system error', 'server error',
            'internal error', 'processing error', 'fatal error'
        ]
        
        # Check if response is primarily an error message
        error_indicators = sum(1 for pattern in false_positive_patterns if pattern in response_lower)
        
        # If response has many error indicators and is short, likely false positive
        if error_indicators >= 3 and len(response_text) < 1500:
            return True
        
        # Check if payload appears only in error context
        payload_pos = response_text.lower().find(payload.lower())
        if payload_pos != -1:
            # Get context around payload
            context_start = max(0, payload_pos - 150)
            context_end = min(len(response_text), payload_pos + len(payload) + 150)
            context = response_text[context_start:context_end].lower()
            
            # Check if context suggests error message
            error_context_indicators = ['error', 'invalid', 'failed', 'exception', 'warning']
            error_context_count = sum(1 for indicator in error_context_indicators if indicator in context)
            
            if error_context_count >= 2:
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str, xss_result: Dict[str, Any]) -> str:
        """Get detailed evidence for XSS vulnerability"""
        evidence_parts = []
        
        # Add XSS type and detection method
        xss_type = xss_result.get('xss_type', 'Unknown')
        detection_method = xss_result.get('detection_method', 'unknown')
        confidence = xss_result.get('confidence', 0.0)
        
        evidence_parts.append(f"{xss_type} detected via {detection_method} (confidence: {confidence:.2f})")
        
        # Add context information
        context = xss_result.get('context', 'unknown')
        evidence_parts.append(f"Context: {context}")
        
        # Add payload information
        payload_snippet = payload[:100] + ('...' if len(payload) > 100 else '')
        evidence_parts.append(f"Payload: {payload_snippet}")
        
        # Add specific evidence from detection
        if 'evidence' in xss_result and xss_result['evidence']:
            evidence_parts.append(xss_result['evidence'])
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet for XSS"""
        # Find where payload appears in response
        payload_pos = response_text.find(payload)
        if payload_pos == -1:
            # Try HTML encoded version
            encoded_payload = html.escape(payload)
            payload_pos = response_text.find(encoded_payload)
        
        if payload_pos != -1:
            # Get context around payload
            start = max(0, payload_pos - 150)
            end = min(len(response_text), payload_pos + len(payload) + 150)
            snippet = response_text[start:end]
            
            # Clean up snippet
            snippet = snippet.replace('\n', ' ').replace('\r', ' ')
            snippet = re.sub(r'\s+', ' ', snippet).strip()
            
            return snippet
        
        # Fallback to beginning of response
        snippet = response_text[:400]
        snippet = snippet.replace('\n', ' ').replace('\r', ' ')
        snippet = re.sub(r'\s+', ' ', snippet).strip()
        
        return snippet + ("..." if len(response_text) > 400 else "")
    
    @staticmethod
    def get_xss_indicators() -> List[str]:
        """Get XSS indicators for detection"""
        return [
            '<script', 'javascript:', 'onerror=', 'onload=', 'onclick=',
            'onmouseover=', 'onfocus=', 'onblur=', 'onchange=', 'onsubmit=',
            'alert(', 'confirm(', 'prompt(', 'eval(', 'settimeout(',
            '<img', '<svg', '<iframe', '<object', '<embed', '<video',
            '<audio', '<canvas', '<form', '<input', '<textarea',
            'document.write', 'innerhtml', 'outerhtml', 'insertadjacenthtml'
        ]
