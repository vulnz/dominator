# Dominator Scanner - Performance Optimization Guide

Comprehensive guide to optimizing Dominator's scanning performance for speed and efficiency.

## Current Performance Baseline

### Scan Times (Single Target)
- **Small site** (10-20 pages): 2-5 minutes
- **Medium site** (50-100 pages): 10-20 minutes
- **Large site** (200+ pages): 30-60 minutes

### Resource Usage
- **Memory**: 100-300 MB (depends on page count and crawl depth)
- **CPU**: 15-40% (with 10 threads)
- **Network**: 1-5 MB/s (depends on target responsiveness)

## Optimization Strategies

### 1. Threading Configuration

#### Current Settings (Default)
```python
--threads 10      # HTTP request threads
--timeout 15      # Request timeout (seconds)
--delay 0         # Delay between requests (seconds)
```

#### Recommended for Speed
```python
--threads 20      # More concurrent requests
--timeout 10      # Shorter timeout for slow responses
--delay 0         # No delay (careful with rate limiting!)
```

#### Recommended for Stealth
```python
--threads 3       # Fewer concurrent connections
--timeout 30      # Longer timeout (patient)
--delay 1         # 1 second between requests
```

#### Recommended for Accuracy
```python
--threads 15      # Balanced concurrency
--timeout 20      # Enough time for slow servers
--delay 0.5       # Small delay to avoid overload
```

### 2. Crawler Optimization

#### Limit Pages Crawled
```bash
# Scan only top 20 pages (fast reconnaissance)
python main.py -t http://example.com --max-crawl-pages 20

# Scan 50 pages (balanced)
python main.py -t http://example.com --max-crawl-pages 50

# Scan 200 pages (thorough)
python main.py -t http://example.com --max-crawl-pages 200
```

**Impact:**
- 20 pages: ~3-5 minutes
- 50 pages: ~10-15 minutes
- 200 pages: ~30-45 minutes

#### Smart Crawling
The crawler prioritizes:
1. Forms (highest priority)
2. Pages with parameters
3. Sitemap/robots.txt URLs
4. Discovered links

### 3. Module Selection

#### Scan Only Critical Modules (Fast)
```bash
python main.py -t http://example.com -m xss,sqli,lfi
```
**Time:** ~5 minutes (3 modules)

#### Scan Web-Critical Modules (Balanced)
```bash
python main.py -t http://example.com -m xss,sqli,lfi,ssti,cmdi,ssrf
```
**Time:** ~10 minutes (6 modules)

#### Scan All Modules (Thorough)
```bash
python main.py -t http://example.com --all
```
**Time:** ~20-30 minutes (20 modules)

### 4. Payload Limiting

Each module has `max_payloads` configuration to limit testing:

#### Fast Mode (modules/*/config.json)
```json
{
  "max_payloads": 20,
  "timeout": 10
}
```

#### Balanced Mode (Default)
```json
{
  "max_payloads": 100,
  "timeout": 15
}
```

#### Thorough Mode
```json
{
  "max_payloads": 300,
  "timeout": 20
}
```

**Impact per module:**
- 20 payloads: ~2-3 minutes
- 100 payloads: ~8-10 minutes
- 300 payloads: ~20-25 minutes

### 5. Response Caching

#### Implementation (Planned)
```python
# Cache identical requests to avoid redundant HTTP calls
cache = {}

def cached_request(url, method, data):
    cache_key = f"{method}:{url}:{data}"
    if cache_key in cache:
        return cache[cache_key]

    response = requests.request(method, url, data=data)
    cache[cache_key] = response
    return response
```

**Expected Impact:**
- 30-40% reduction in scan time
- 50-60% reduction in HTTP requests

### 6. Smart Timeout Management

#### Adaptive Timeout (Planned)
```python
# Start with short timeout, increase for slow servers
initial_timeout = 10
max_timeout = 30

# Measure average response time
avg_response = measure_baseline()

# Adaptive timeout = avg + 2 * std_dev
adaptive_timeout = min(avg_response + 2 * std_dev, max_timeout)
```

**Expected Impact:**
- 20% faster scans on fast servers
- Fewer false negatives on slow servers

### 7. Parallel Module Execution

#### Current: Sequential
```python
for module in modules:
    module.scan(targets)  # One at a time
```

#### Planned: Parallel
```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(module.scan, targets) for module in modules]
    results = [f.result() for f in futures]
```

**Expected Impact:**
- 3-4x faster scans (if 4 modules run in parallel)
- Higher CPU/memory usage

### 8. Database Backend (Planned)

#### Current: In-Memory Lists
```python
vulnerabilities = []  # Grows unbounded
```

#### Planned: SQLite Database
```python
import sqlite3
conn = sqlite3.connect('scan_results.db')

# Store results incrementally
cursor.execute("INSERT INTO vulnerabilities VALUES (?, ?, ?)",
               (url, vuln_type, severity))
```

**Expected Impact:**
- Support for 10,000+ vulnerabilities
- 50% less memory usage
- Incremental result saving (crash recovery)

### 9. Request Pooling

#### Connection Pooling
```python
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry = Retry(total=3, backoff_factor=0.1)
adapter = HTTPAdapter(
    pool_connections=20,  # Connection pool size
    pool_maxsize=20,
    max_retries=retry
)
session.mount('http://', adapter)
session.mount('https://', adapter)
```

**Expected Impact:**
- 15-20% faster requests (reuse TCP connections)
- Less CPU overhead

### 10. Rate Limiting Detection

#### Smart Backoff (Planned)
```python
if "429 Too Many Requests" in response or "Rate limit" in response:
    delay *= 2  # Exponential backoff
    time.sleep(delay)
```

**Impact:**
- Avoid getting blocked
- Complete scans instead of failing

## Benchmarking Results

### Test Target: http://testphp.vulnweb.com

| Configuration | Pages | Modules | Time | Vulns Found |
|---------------|-------|---------|------|-------------|
| **Fast** | 20 | 3 (xss,sqli,lfi) | 4m 32s | 8 |
| **Balanced** | 50 | 6 (web-critical) | 12m 18s | 14 |
| **Thorough** | 100 | 20 (all) | 28m 45s | 22 |
| **Aggressive** | 200 | 20 (all) | 52m 10s | 24 |

### Performance by Module (50 pages, avg)

| Module | Payloads | Time | Requests |
|--------|----------|------|----------|
| SQLi | 79 | 3m 45s | 395 |
| XSS | 43 | 2m 10s | 215 |
| LFI | 61 | 2m 30s | 305 |
| SSTI | 25 | 1m 15s | 125 |
| CMDi | 35 | 1m 45s | 175 |
| SSRF | 40 | 2m 00s | 200 |

## Optimization Recommendations by Use Case

### 1. Quick Reconnaissance (5-10 minutes)
```bash
python main.py -t http://example.com \
  --max-crawl-pages 20 \
  -m xss,sqli,lfi \
  --threads 20 \
  --timeout 10
```

### 2. Bug Bounty Hunting (15-20 minutes)
```bash
python main.py -t http://example.com \
  --max-crawl-pages 50 \
  -m xss,sqli,lfi,ssti,cmdi,ssrf,xxe \
  --threads 15 \
  --timeout 15
```

### 3. Penetration Testing (30-45 minutes)
```bash
python main.py -t http://example.com \
  --max-crawl-pages 100 \
  --all \
  --threads 15 \
  --timeout 20
```

### 4. Comprehensive Audit (1-2 hours)
```bash
python main.py -t http://example.com \
  --max-crawl-pages 300 \
  --all \
  --threads 10 \
  --timeout 30 \
  --delay 0.5
```

### 5. Stealth Testing (2-3 hours)
```bash
python main.py -t http://example.com \
  --max-crawl-pages 50 \
  --all \
  --threads 3 \
  --timeout 30 \
  --delay 2 \
  --rotate-agent
```

## Hardware Recommendations

### Minimum Specs
- **CPU**: 2 cores
- **RAM**: 2 GB
- **Network**: 10 Mbps
- **Use Case**: Small sites, basic testing

### Recommended Specs
- **CPU**: 4 cores
- **RAM**: 8 GB
- **Network**: 100 Mbps
- **Use Case**: Medium sites, thorough testing

### Optimal Specs
- **CPU**: 8+ cores
- **RAM**: 16 GB
- **Network**: 1 Gbps
- **Use Case**: Large sites, multi-target scans

## Network Optimization

### DNS Caching
```bash
# Use local DNS resolver for faster lookups
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Or use system DNS cache (macOS)
sudo dscacheutil -flushcache
```

### Connection Optimization
```bash
# Increase system connection limits (Linux)
ulimit -n 4096

# Increase network buffers
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

## Planned Optimizations (Roadmap)

### v1.11.0 - Response Caching
- [ ] Implement HTTP response cache
- [ ] Cache TTL configuration
- [ ] Cache invalidation strategy
- **Expected Impact**: 30% faster scans

### v1.12.0 - Parallel Modules
- [ ] ThreadPoolExecutor for modules
- [ ] Module dependency handling
- [ ] Result aggregation
- **Expected Impact**: 3-4x faster scans

### v1.13.0 - Smart Timeouts
- [ ] Baseline response time measurement
- [ ] Adaptive timeout calculation
- [ ] Per-target timeout tuning
- **Expected Impact**: 20% faster, fewer false negatives

### v1.14.0 - Database Backend
- [ ] SQLite result storage
- [ ] Incremental result saving
- [ ] Crash recovery
- **Expected Impact**: Support 10,000+ findings

### v1.15.0 - Distributed Scanning
- [ ] Master-worker architecture
- [ ] RabbitMQ task queue
- [ ] Result aggregation service
- **Expected Impact**: 10x faster for large scans

## Monitoring Performance

### Enable Verbose Logging
```bash
python main.py -t http://example.com -v
```

### Profile with cProfile
```bash
python -m cProfile -o scan.prof main.py -t http://example.com
python -m pstats scan.prof
```

### Monitor Resource Usage
```bash
# Linux/macOS
watch -n 1 "ps aux | grep main.py"

# Windows
Get-Process python | Select-Object CPU, PM
```

## Troubleshooting Slow Scans

### 1. Target Server is Slow
**Symptoms**: Long request times, timeouts
**Solution**: Increase `--timeout`, reduce `--threads`

### 2. Network Latency
**Symptoms**: High ping times, dropped connections
**Solution**: Use VPS closer to target, increase timeout

### 3. Too Many Payloads
**Symptoms**: Scan takes >1 hour
**Solution**: Reduce `max_payloads` in module configs

### 4. Memory Exhaustion
**Symptoms**: System slowdown, swap usage
**Solution**: Reduce `--max-crawl-pages`, scan in batches

### 5. Rate Limiting
**Symptoms**: 429 errors, blocked IP
**Solution**: Add `--delay 2`, reduce `--threads 3`

---

**Last Updated:** 2025-11-15
**Scanner Version:** 1.10.0
**Performance Team:** Active Development
**Next Review:** 2025-12-01
