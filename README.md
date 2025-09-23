# hopgoblin

`hopgoblin` is a scanner for Adobe Experience Manager (AEM) instances.  
It automates a handful of checks that we frequently perform manually during security assessments.

---

## Features

- Detects exposed QueryBuilder endpoints:
  - `/bin/querybuilder.json`
  - `/bin/querybuilder.feed`
- Abuses QueryBuilder to:
  - enumerate `rep:User` objects and leaked password hashes
  - identify writable JCR nodes
- SSRF via `/services/accesstoken/verify`
- Blind XXE in Jackrabbit package manager (`/crx/packmgr/service/exec.json`)
- Expression Language (EL) injection in cloudsettings import
- Path mutation strategies to catch endpoints behind lenient parsing
- Concurrency with progress bar (`tqdm`)
- Proxy support (`--proxy`) for use with Burp/ZAP
- Writes results to timestamped file with proof-of-concept URLs

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourorg/hopgoblin.git
cd hopgoblin
pip install -r requirements.txt
```

Requirements:
- Python 3.8+
- `requests`
- `tqdm`

---

## Usage

### Single target

```bash
python hopgoblin.py https://aem-target.example
```

Example output:

```
[.] Output will be saved to: hopgoblin_aem-target.example_20250923_123456.txt
Scanning https://aem-target.example
[+] Exposed JSON query builder - /bin/querybuilder.json
POC URL: https://aem-target.example/bin/querybuilder.json

summary
------------------------------------------------------------
https://aem-target.example
  exposed json query builder
------------------------------------------------------------
```

### Multiple targets

```bash
python hopgoblin.py -f targets.txt --threads 25 --ssrf-target collab.example.com
```

### With proxy and debug

```bash
python hopgoblin.py -f targets.txt --proxy http://127.0.0.1:8080 --debug
```

---

## Options

```
usage: hopgoblin.py [-h] [-f FILE | url] [-t SSRF_TARGET] [-d] [-p PROXY] [--threads THREADS]

positional arguments:
  url                   Single target URL

optional arguments:
  -f, --file FILE       File containing target URLs (one per line)
  -t, --ssrf-target     Callback domain for SSRF/XXE checks
  -d, --debug           Enable debug output
  -p, --proxy           Proxy URL (e.g., http://127.0.0.1:8080)
  --threads THREADS     Number of threads (default: 10)
```

---
