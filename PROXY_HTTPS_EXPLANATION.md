# Proxy & HTTPS - Current Behavior Explanation

## ✅ What Currently Works

### HTTP Sites (Full Visibility)
When you visit plain HTTP sites (like `http://testphp.vulnweb.com`):
- ✅ Full request visibility (GET, POST, PUT, DELETE, etc.)
- ✅ All headers visible
- ✅ Request/response bodies visible
- ✅ Can intercept and modify
- ✅ Shows in history with full details

### HTTPS Sites (Tunneled)
When you visit HTTPS sites (like `https://google.com`):
- ✅ Connection works (you can browse normally)
- ⚠️ Shows as "CONNECT google.com:443" in history
- ⚠️ Request bodies are encrypted (not visible)
- ⚠️ Cannot intercept individual requests
- ✅ Site loads normally in browser

## 🔍 Why HTTPS Shows as CONNECT

### The CONNECT Method
When your browser wants to visit `https://google.com`:

1. Browser sends: `CONNECT google.com:443`
2. Proxy establishes tunnel to Google's server
3. Proxy responds: `200 Connection Established`
4. Browser and server exchange **encrypted** SSL/TLS data
5. Proxy just forwards encrypted bytes (cannot see content)

```
Browser ←→ Proxy ←→ Google Server
         (encrypted tunnel)
```

### What You See in History
```
Method: CONNECT
URL: https://google.com:443
Body: [HTTPS - Encrypted]
Status: 200 Connection Established
```

This is **EXPECTED and NORMAL behavior** for HTTPS without SSL inspection.

## 🚫 Current Limitations

### Cannot See Inside HTTPS Traffic
- ❌ Cannot see actual GET/POST/PUT requests inside HTTPS
- ❌ Cannot see request headers (Authorization, Cookie, etc.)
- ❌ Cannot see request/response bodies
- ❌ Cannot intercept and modify HTTPS requests
- ❌ Cannot perform passive scanning on HTTPS content

### Why This Happens
HTTPS traffic is **end-to-end encrypted** between browser and server.
The proxy sees only encrypted bytes, like:
```
\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03...
```

Without SSL certificate installation, the proxy cannot decrypt this.

## ✅ How to Test HTTP Features

### Use HTTP Test Sites
To see full proxy functionality, use HTTP (not HTTPS) sites:

1. **DVWA** - `http://127.0.0.1/dvwa`
2. **bWAPP** - `http://127.0.0.1/bWAPP`
3. **TestPHP Vulnweb** - `http://testphp.vulnweb.com`
4. **Local servers** - `http://localhost:8000`

### What You'll See
```
✅ Method: GET
✅ URL: http://testphp.vulnweb.com/artists.php?artist=1
✅ Headers:
   Host: testphp.vulnweb.com
   User-Agent: Mozilla/5.0...
   Cookie: session=abc123
   Accept: text/html...
✅ Body: (if POST) name=value&param=data
✅ Response: Full HTML visible
```

## 🔐 Future: SSL Inspection (Planned)

### What Would Be Needed

**1. Generate Root CA Certificate**
```python
# Create self-signed Certificate Authority
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -out ca.crt
```

**2. Install CA in Browser**
- Add `ca.crt` to Chromium's trusted certificates
- Browser now trusts certificates signed by our CA

**3. Generate Per-Domain Certificates**
- When `CONNECT google.com:443` arrives
- Generate certificate for `google.com` signed by our CA
- Wrap connection with SSL using our certificate

**4. Man-in-the-Middle Decryption**
```
Browser ←[SSL with our cert]→ Proxy ←[SSL with real cert]→ Google
        (we decrypt here)              (encrypted again)
```

### Implementation Complexity
- ⚠️ Requires OpenSSL/cryptography library
- ⚠️ Certificate generation for each domain
- ⚠️ SSL socket wrapping
- ⚠️ Certificate trust chain management
- ⚠️ Handling certificate errors gracefully

### Estimated Effort
- **3-5 days** of development
- Complex SSL/TLS implementation
- Cross-platform certificate installation
- Testing with various sites

## 🎯 Recommended Workflow (Current)

### For Testing Web Applications

**1. If site has HTTP version:**
```
✅ Use HTTP (http://site.com)
✅ Full request visibility
✅ Full interception capability
✅ Full passive scanning
```

**2. If site is HTTPS-only:**
```
⚠️ Use 'Send to Scanner' feature
⚠️ Manually copy cookies from DevTools
⚠️ Configure authentication in Scanner settings
⚠️ Run scans with authenticated session
```

**3. For API testing:**
```
✅ Use Repeater Tab directly
✅ Manually construct requests
✅ Add Bearer tokens, cookies, headers
✅ Test authenticated endpoints
```

### For Authenticated Scanning

**Workflow:**
1. Visit HTTPS site in browser
2. Login normally (tunnel works)
3. Open DevTools → Application → Cookies
4. Copy session cookies
5. Use "Send to Scanner" or manual configuration
6. Scanner uses cookies for authenticated requests

## 📊 Comparison with Burp Suite

### Burp Suite Pro
- ✅ Full SSL inspection (with CA certificate)
- ✅ HTTPS requests fully visible
- ✅ Can intercept and modify HTTPS
- ❌ Costs $449/year
- ❌ Requires Java

### Dominator (Current)
- ✅ Free and open source
- ✅ HTTP fully supported
- ✅ HTTPS tunneling works (browsing OK)
- ⚠️ HTTPS inspection not yet implemented
- ✅ Portable Chromium integration
- ✅ Send to Scanner with cookies/headers

### Dominator (Future - with SSL inspection)
- ✅ Free and open source
- ✅ HTTP fully supported
- ✅ HTTPS fully inspected
- ✅ Full Burp-like functionality
- ✅ Portable Chromium integration

## ❓ FAQ

### Q: Why do I only see CONNECT in history?
**A:** You're visiting HTTPS sites. CONNECT is the tunnel establishment.
The actual requests (GET, POST) are encrypted inside the tunnel.

### Q: Why can't I intercept Google.com requests?
**A:** Google.com is HTTPS-only. Without SSL inspection, we cannot
decrypt the traffic to see individual requests.

### Q: Does the proxy work?
**A:** Yes! The proxy works perfectly for HTTP. For HTTPS, it tunnels
the encrypted traffic, allowing browsing to work normally.

### Q: Why does http://testphp.vulnweb.com show full details?
**A:** It's HTTP (not HTTPS), so traffic is unencrypted and fully visible.

### Q: Can I test my HTTPS web app?
**A:** Yes, but with limitations:
- Browse normally through proxy
- Use DevTools to get cookies
- Use "Send to Scanner" with cookies
- Or test with HTTP during development

### Q: Will SSL inspection be added?
**A:** Yes, it's planned! It's a complex feature requiring:
- Certificate generation
- SSL wrapping
- Cross-platform installation
- Estimated 3-5 days development

## 🔧 Workarounds (Until SSL Inspection)

### 1. Use HTTP for Testing
```bash
# If you control the server
python -m http.server 8000
# Test at http://localhost:8000
```

### 2. Disable HTTPS Redirect Temporarily
```nginx
# Nginx - comment out redirect
# return 301 https://$server_name$request_uri;
```

### 3. Use Repeater Tab Directly
```
1. Open Repeater tab
2. Enter URL: https://api.example.com/users
3. Add headers: Authorization: Bearer token
4. Send request manually
5. Full control without proxy
```

### 4. Use Send to Scanner
```
1. Login through browser
2. Copy session cookie from DevTools
3. Go to Scanner → Cookies field
4. Paste: session=abc123; token=xyz
5. Run authenticated scan
```

## 📝 Summary

**Current State:**
- ✅ HTTP: Fully functional (Burp-like features)
- ⚠️ HTTPS: Tunneling only (browsing works, no inspection)
- ✅ Workarounds available for HTTPS testing

**Future State (with SSL inspection):**
- ✅ HTTP: Fully functional
- ✅ HTTPS: Fully inspected (Burp-like features)
- ✅ Complete web app testing solution

**For Now:**
- Use HTTP sites for full proxy testing
- Use Repeater for HTTPS API testing
- Use Send to Scanner for authenticated HTTPS scans
- Wait for SSL inspection feature (planned)
