# ROTATION 3 - CRITICAL FIXES

## 1. PHP Object Injection - 100% Precision

### Problems:
- METHOD 3 uses `url` variable that doesn't exist in scope (line 204)
- Still detecting on non-PHP targets (testasp.vulnweb.com)
- Confidence threshold too low (0.60)

### Solution:
1. Pass `url` parameter to `_detect_php_object_injection()`
2. **DISABLE METHOD 3 completely** - it causes all false positives
3. Only rely on METHOD 1 (error-based) and METHOD 2 (indicator-based)
4. Increase confidence thresholds to 0.85+
5. Add PHP-specific checks (must have `.php` in URL or `PHP` in response headers)

### Code Changes:
```python
def _detect_php_object_injection(self, payload: str, response: Any,
                                baseline_text: str, baseline_length: int,
                                url: str = '') -> tuple:  # ADD url parameter
    """
    Detect PHP Object Injection vulnerability
    """
    response_text = getattr(response, 'text', '')
    response_length = len(response_text)

    # PRE-CHECK: Must be PHP application
    if url:
        is_php = (
            '.php' in url.lower() or
            'php' in response.headers.get('X-Powered-By', '').lower() or
            'php' in response.headers.get('Server', '').lower()
        )
        if not is_php:
            return False, 0.0, ""

    # METHOD 1: Error-based detection (MOST RELIABLE)
    error_found = None
    for error_pattern in self.error_patterns:
        if error_pattern in response_text and error_pattern not in baseline_text:
            error_found = error_pattern
            break

    if error_found:
        # INCREASED confidence from 0.80 to 0.90
        confidence = 0.90

        # Even higher if multiple errors
        error_count = sum(1 for err in self.error_patterns if err in response_text)
        if error_count >= 2:
            confidence = 0.95

        evidence = f"PHP unserialize() error detected: '{error_found}'. "
        evidence += "Application attempts to deserialize user input. "
        evidence += BaseDetector.get_evidence(error_found, response_text, context_size=200)

        return True, confidence, evidence

    # METHOD 2: Deserialization indicator detection
    indicators_found = []
    for indicator in self.deserialization_indicators:
        if indicator in response_text and indicator not in baseline_text:
            indicators_found.append(indicator)

    if len(indicators_found) >= 2:
        # INCREASED confidence from 0.70 to 0.85
        confidence = 0.85

        # Check if serialization format is reflected
        if 'O:' in payload and ('object(' in response_text or 'stdClass' in response_text):
            confidence = 0.90

        evidence = f"Deserialization indicators detected: {', '.join(indicators_found)}. "
        evidence += "Application may be deserializing user input without validation."

        return True, confidence, evidence

    # METHOD 3: COMPLETELY DISABLED - causes false positives
    # This method was detecting on any length change, which is unreliable

    return False, 0.0, ""
```

### Also Update Call Site:
```python
# Line ~115 in scan() method
detected, confidence, evidence = self._detect_php_object_injection(
    payload, response, baseline_text, baseline_length,
    url=url  # ADD url parameter
)
```

---

## 2. SSTI - Stronger Detection

### Problem:
- `7*7=49` too weak - number 49 can appear naturally on pages
- Need unique payloads that can't appear naturally

### Solution:
Use unique multi-digit calculations + template-specific syntax:

```python
# modules/ssti/payloads.txt - ADD THESE:

# Strong mathematical payloads (unlikely to appear naturally)
{{7*7*7}}
{{199*3}}
{{1337+1337}}
${7*7*7}
${999*3}
${1234+5678}

# Unique strings
{{self.__dict__}}
${pageContext.request.contextPath}
{{config.items()}}
${7*'7'}

# Extremely unique calculations
{{13*37}}
{{73*73}}
{{999+1}}
```

### Detection Logic:
```python
def _detect_ssti(self, payload, response, baseline_text):
    """Enhanced SSTI detection with unique results"""

    response_text = getattr(response, 'text', '')

    # Map payloads to UNIQUE expected results
    unique_checks = {
        '{{7*7*7}}': ['343'],
        '{{199*3}}': ['597'],
        '{{1337+1337}}': ['2674'],
        '{{13*37}}': ['481'],
        '{{73*73}}': ['5329'],
        '${999*3}': ['2997'],
        '${1234+5678}': ['6912'],
    }

    for test_payload, expected_results in unique_checks.items():
        if test_payload in payload or payload == test_payload:
            for expected in expected_results:
                # Check if result appears (and wasn't in baseline)
                if expected in response_text and expected not in baseline_text:
                    # VERIFY it's not just random occurrence
                    # Check context around the number
                    import re
                    pattern = rf'\b{expected}\b'  # Word boundary
                    if re.search(pattern, response_text):
                        return True, 0.95, f"SSTI detected: {test_payload} = {expected}"

    # Fallback to original detection
    # ...
```

---

## 3. OOB Detection - Add Proof URLs

### Problem:
- OOB callbacks работают, но в evidence нет ссылки на proof
- Нельзя вручную проверить что callback пришёл

### Solution:
Add callback URLs to evidence:

```python
# In modules that use OOB (cmdi, ssrf, sqli)

if oob_callback:
    # Generate OOB URL
    oob_url = oob_detector.generate_callback_url(unique_id)

    # Test with OOB
    response = test_with_oob(oob_url)

    # Check if callback received
    if oob_detector.check_callback(unique_id):
        # ADD PROOF URLS TO EVIDENCE
        requestbin_proof = f"http://requestbin.cn/15y70i81?inspect (search for: {unique_id})"
        pipedream_proof = f"https://eo8l8qkj6l1mfjp.m.pipedream.net (Event ID: {unique_id})"

        evidence = f"OOB callback received!\\n\\n"
        evidence += f"Callback ID: {unique_id}\\n"
        evidence += f"Requestbin Proof: {requestbin_proof}\\n"
        evidence += f"Pipedream Proof: {pipedream_proof}\\n\\n"
        evidence += f"Vulnerable payload: {payload}"

        return True, 1.0, evidence
```

---

## PRIORITY FOR ROTATION 3:

1. **FIX PHP Object Injection** - DISABLE METHOD 3, add PHP checks
2. **UPGRADE SSTI** - unique payloads (7*7*7=343, 13*37=481, etc)
3. **ADD OOB PROOF** - requestbin/pipedream links in evidence

---

## Expected Results After ROTATION 3:

- PHP Object Injection: 0 false positives (100% precision)
- SSTI: Stronger detection with unique results
- OOB: Full proof URLs for manual verification
- Overall coverage: 75-85% (up from ~65%)
