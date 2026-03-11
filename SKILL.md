---
name: virustotal-api
description: >
  Comprehensive reference for the VirusTotal API v3, covering authentication, rate limits,
  endpoint usage, and the critical differences between Free (Public) and Premium (Enterprise) tiers.
  Use this skill whenever a user asks about VirusTotal, VT API, scanning files or URLs with
  VirusTotal, threat intelligence lookups, IoC enrichment, YARA hunting, Retrohunt, Livehunt,
  VT Intelligence search, VT Graph, VT Monitor, VT Feeds, private scanning, malware analysis
  via VirusTotal, or building integrations with the VirusTotal API. Also trigger when the user
  mentions "VT", "virustotal", hash lookups, file reputation checks, URL scanning services,
  sandbox detonation reports, or any workflow involving programmatic interaction with VirusTotal's
  threat intelligence platform — even if they don't say "API" explicitly.
---

# VirusTotal API v3 — Agent Skill

## Quick Orientation

VirusTotal (VT) is a threat intelligence platform that aggregates 70+ antivirus engines, 10+
dynamic analysis sandboxes, and numerous other security tools. Its REST API (v3) is the primary
programmatic interface. The API is inspired by the JSON:API specification and returns JSON for
all requests and responses, including errors.

**Base URL:** `https://www.virustotal.com/api/v3`

**Authentication:** Every request must include the header `x-apikey: <YOUR_API_KEY>`. Your key
is found at https://www.virustotal.com/gui/my-apikey after signing into VirusTotal Community.
Never pass the key as a query parameter — always use the header.

```
# Example: Get a file report by SHA-256
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{sha256} \
  --header 'x-apikey: YOUR_API_KEY' \
  --header 'accept: application/json'
```

```python
# Python equivalent
import requests

url = "https://www.virustotal.com/api/v3/files/{sha256}"
headers = {"accept": "application/json", "x-apikey": "YOUR_API_KEY"}
response = requests.get(url, headers=headers)
print(response.json())
```

---

## Free vs Enterprise — The Most Important Distinction

Almost every decision about what you can build with the VT API depends on which tier you have.
The two tiers are **Public API** (free) and **Premium API** (paid, also called "Private API"
or "VT Enterprise"). Throughout this skill and the VT docs, a 🔒 icon marks enterprise-only
endpoints or relationships.

### Public API (Free Tier)

| Aspect               | Detail                                                      |
|----------------------|--------------------------------------------------------------|
| **Cost**             | Free — sign up at virustotal.com                             |
| **Rate limit**       | 4 requests per minute                                        |
| **Daily quota**      | 500 requests per day                                         |
| **Rate limit scope** | Enforced per (IP address, API key) tuple                     |
| **Commercial use**   | Prohibited                                                   |
| **File download**    | Not available                                                |
| **Search**           | Basic search only (exact hash, URL, domain, IP)              |
| **Hunting**          | IoC Stream only (no Livehunt, no Retrohunt)                  |
| **Feeds**            | Not available                                                |
| **Private scanning** | Not available                                                |
| **Relationships**    | Subset — many relationship types are 🔒 enterprise-only      |
| **File attributes**  | Subset — fields like exiftool, malware_config are 🔒         |

**Restrictions to emphasize:**
- Cannot be used in commercial products or services.
- Cannot be used in business workflows that do not contribute new files.
- Registering multiple accounts to circumvent limits is prohibited.

### Premium API (Enterprise Tier)

| Aspect               | Detail                                                      |
|----------------------|--------------------------------------------------------------|
| **Cost**             | Paid — contact VT sales for pricing based on usage           |
| **Rate limit**       | Governed by your licensed service step (no fixed public cap)  |
| **Daily quota**      | Governed by your license                                     |
| **Commercial use**   | Allowed per agreement                                        |
| **File download**    | Yes — download samples, PCAPs, memory dumps, EVTX            |
| **Search**           | VT Intelligence advanced corpus search with full modifiers   |
| **Hunting**          | Livehunt (real-time YARA) + Retrohunt (historical YARA)     |
| **Feeds**            | Full intelligence feeds (file, URL, domain, IP, sandbox)     |
| **Private scanning** | Yes — scan files/URLs without contributing to public corpus   |
| **Relationships**    | Full set including embedded_domains, itw_urls, similar_files  |
| **File attributes**  | Full set including exiftool, malware_config, office_info      |

**Additional enterprise capabilities:**
- First/last submission dates, submission countries, file prevalence metadata.
- Sandbox behavior reports for Windows PE, DMG, Mach-O, APK.
- Rich relationships: embedded domains/IPs/URLs, carbonblack parents/children, etc.
- VT Graph API for link analysis.
- VT Monitor for software publishers and AV partners.
- User/group/quota management and audit logs.
- Service account management.

---

## Response Format

Successful requests return HTTP 200 with this structure:

```json
{
  "data": <response_data>
}
```

Where `<response_data>` is typically an object like:

```json
{
  "type": "file",
  "id": "<sha256>",
  "links": { "self": "https://www.virustotal.com/api/v3/files/<sha256>" },
  "attributes": { ... }
}
```

For collections (lists), the response includes pagination:

```json
{
  "data": [ ... ],
  "meta": { "cursor": "..." },
  "links": { "self": "...", "next": "..." }
}
```

### Error Format

Errors return the appropriate HTTP status code (4xx for client errors, 5xx for server errors):

```json
{
  "error": {
    "code": "NotFoundError",
    "message": "Resource \"xyz\" not found"
  }
}
```

Common error codes:
- `AuthenticationRequiredError` — missing or invalid x-apikey header
- `WrongCredentialsError` — API key is not valid
- `ForbiddenError` — insufficient privileges (e.g., free key hitting enterprise endpoint)
- `NotFoundError` — resource does not exist in VT dataset
- `QuotaExceededError` — rate limit or daily quota exceeded
- `TooManyRequestsError` — too many requests in a short period
- `TransientError` — temporary server issue, retry with backoff

---

## Core Endpoint Categories

For the full endpoint reference with request/response details, read:
- `references/endpoints-free.md` — All endpoints available to free-tier users
- `references/endpoints-enterprise.md` — Enterprise-only endpoints (🔒)
- `references/objects-and-relationships.md` — API object schemas and relationship types

### Endpoints Available to Free Users

These are the bread-and-butter endpoints most integrations use:

**Files**
- `POST /files` — Upload a file for scanning (max 32MB; use upload URL for larger)
- `GET /files/upload_url` — Get a URL for uploading files >32MB (up to 650MB)
- `GET /files/{id}` — Get a file report by hash (MD5, SHA-1, or SHA-256)
- `POST /files/{id}/analyse` — Request a rescan of a known file
- `GET /files/{id}/comments` — Get comments on a file
- `POST /files/{id}/comments` — Add a comment to a file
- `GET /files/{id}/votes` — Get votes on a file
- `POST /files/{id}/votes` — Cast a vote on a file
- `GET /files/{id}/relationships/{relationship}` — Get related objects

**URLs**
- `POST /urls` — Submit a URL for scanning
- `GET /urls/{id}` — Get a URL report (id = base64url of the URL without padding)
- `POST /urls/{id}/analyse` — Request a rescan
- Comments, votes, and relationships follow the same pattern as files

**Domains**
- `GET /domains/{domain}` — Get a domain report
- `POST /domains/{domain}/rescan` — Request a rescan
- Comments, votes, relationships

**IP Addresses**
- `GET /ip_addresses/{ip}` — Get an IP address report
- `POST /ip_addresses/{ip}/rescan` — Request a rescan
- Comments, votes, relationships

**Comments** (global)
- `GET /comments` — Get latest comments across VT
- `GET /comments/{id}` — Get a specific comment
- `DELETE /comments/{id}` — Delete your own comment

**Analyses & Submissions**
- `GET /analyses/{id}` — Get status/results of a scan analysis
- `GET /submissions/{id}` — Get a submission object

**Search (basic)**
- `GET /search?query={query}` — Basic search for files, URLs, domains, IPs, comments

### Enterprise-Only Endpoints (🔒)

These require a premium API key. Attempting them with a free key returns `ForbiddenError`.

**VT Intelligence (Advanced Search)**
- `GET /intelligence/search?query={query}` — Full corpus search with modifiers
- `GET /intelligence/search/snippets/{id}` — Content search snippets

**File Downloads**
- `GET /files/{id}/download_url` — Get a time-limited download URL
- `GET /files/{id}/download` — Download the actual file bytes

**VT Hunting**
- Livehunt: CRUD for YARA rulesets, notification retrieval, file downloads
- Retrohunt: Create/manage retrohunt jobs, retrieve matches

**VT Feeds**
- File, URL, domain, IP, and sandbox analysis feeds (per-minute and hourly batches)

**Private Scanning**
- Upload and scan files/URLs privately (results not shared with VT community)

**Collections (advanced)**
- List all collections, export IOCs, export aggregations, search within collections

**Zipping Files**
- Create password-protected ZIPs of VT files for bulk download

**Administration**
- User/group/quota management, service accounts, audit logs

**VT Monitor**
- Software publisher and AV partner endpoints

**VT Graph**
- Create, search, update, delete graphs; manage viewer/editor permissions

---

## Practical Examples

### Example 1: Check if a file hash is malicious (Free)

```python
import requests

API_KEY = "your_api_key_here"
FILE_HASH = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file MD5

url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"
headers = {"x-apikey": API_KEY}
response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    print(f"Malicious: {stats['malicious']}, Undetected: {stats['undetected']}")
elif response.status_code == 404:
    print("File not found in VT database")
else:
    print(f"Error: {response.status_code} - {response.json()}")
```

### Example 2: Submit a URL for scanning (Free)

```python
import requests, base64

API_KEY = "your_api_key_here"
TARGET_URL = "https://example.com"

# Step 1: Submit the URL
headers = {"x-apikey": API_KEY, "content-type": "application/x-www-form-urlencoded"}
response = requests.post(
    "https://www.virustotal.com/api/v3/urls",
    headers=headers,
    data=f"url={TARGET_URL}"
)
analysis_id = response.json()["data"]["id"]

# Step 2: Poll for results
import time
time.sleep(30)  # Wait for analysis to complete

headers = {"x-apikey": API_KEY}
result = requests.get(
    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
    headers=headers
)
print(result.json()["data"]["attributes"]["stats"])

# Alternative: look up the URL directly
url_id = base64.urlsafe_b64encode(TARGET_URL.encode()).decode().rstrip("=")
report = requests.get(
    f"https://www.virustotal.com/api/v3/urls/{url_id}",
    headers=headers
)
```

### Example 3: Upload a file for scanning (Free)

```python
import requests

API_KEY = "your_api_key_here"
FILE_PATH = "/path/to/suspicious_file.exe"

# For files <= 32MB, use the direct upload endpoint
with open(FILE_PATH, "rb") as f:
    response = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers={"x-apikey": API_KEY},
        files={"file": (FILE_PATH, f)}
    )
print(response.json()["data"]["id"])  # Analysis ID to poll later

# For files > 32MB, first get an upload URL
upload_url_resp = requests.get(
    "https://www.virustotal.com/api/v3/files/upload_url",
    headers={"x-apikey": API_KEY}
)
upload_url = upload_url_resp.json()["data"]
# Then POST the file to that URL instead
```

### Example 4: VT Intelligence search (🔒 Enterprise)

```python
import requests

API_KEY = "your_premium_api_key"

# Search for recently submitted PE files detected by 10+ engines
query = "type:peexe positives:10+ fs:2025-05-01+"
response = requests.get(
    "https://www.virustotal.com/api/v3/intelligence/search",
    headers={"x-apikey": API_KEY},
    params={"query": query, "limit": 20}
)

for item in response.json()["data"]:
    sha256 = item["id"]
    detections = item["attributes"]["last_analysis_stats"]["malicious"]
    print(f"{sha256}: {detections} detections")

# Paginate with cursor
next_link = response.json().get("links", {}).get("next")
if next_link:
    next_page = requests.get(next_link, headers={"x-apikey": API_KEY})
```

### Example 5: Download a malware sample (🔒 Enterprise)

```python
import requests

API_KEY = "your_premium_api_key"
SHA256 = "abc123..."

# Option A: Get download URL (time-limited)
resp = requests.get(
    f"https://www.virustotal.com/api/v3/files/{SHA256}/download_url",
    headers={"x-apikey": API_KEY}
)
download_url = resp.json()["data"]

# Option B: Direct download
resp = requests.get(
    f"https://www.virustotal.com/api/v3/files/{SHA256}/download",
    headers={"x-apikey": API_KEY}
)
with open(f"{SHA256}.bin", "wb") as f:
    f.write(resp.content)
```

### Example 6: Retrieve sandbox behavior for a file (Free, but richer with Enterprise)

```python
import requests

API_KEY = "your_api_key"
SHA256 = "abc123..."

# Get summary of all behavior reports
resp = requests.get(
    f"https://www.virustotal.com/api/v3/files/{SHA256}/behaviour_summary",
    headers={"x-apikey": API_KEY}
)
summary = resp.json()["data"]

# Get individual sandbox reports
resp = requests.get(
    f"https://www.virustotal.com/api/v3/files/{SHA256}/behaviours",
    headers={"x-apikey": API_KEY}
)
for report in resp.json()["data"]:
    sandbox = report["attributes"].get("sandbox_name", "unknown")
    print(f"Sandbox: {sandbox}")
```

---

## Rate Limiting Best Practices

For free-tier users (4 req/min, 500 req/day):

1. **Cache aggressively** — VT reports don't change every second. Cache results for at least
   15-60 minutes depending on your use case.
2. **Batch with sleep** — When processing multiple hashes, add a `time.sleep(15)` between
   requests to stay safely under 4/min.
3. **Check before scanning** — Always GET a report first before POSTing a new scan. The file
   or URL may already be in the database.
4. **Use the analysis endpoint wisely** — After submitting a scan, poll `/analyses/{id}`
   rather than repeatedly hitting the file/URL endpoint.

For enterprise users:
- Your limits are defined by your license. Check `GET /users/{id}/api_usage` for current
  consumption.
- Use concurrent requests and the feeds endpoints for large-scale processing.
- Use `descriptors_only=true` on search endpoints when you only need hashes.

---

## Key Concepts

**Objects** — Everything in VT is an object with a `type`, `id`, `attributes`, and `links`.
Object types include: file, url, domain, ip_address, comment, analysis, etc.

**Relationships** — Objects link to each other through relationships. For example, a file has
relationships like `contacted_domains`, `dropped_files`, `behaviours`. Many relationship types
are enterprise-only (🔒).

**Collections** — Ordered lists of objects returned by endpoints that produce multiple results.
Collections support cursor-based pagination via the `cursor` parameter.

**Descriptors** — Lightweight references to objects (just type + id) used for efficient listing
without fetching full attributes.

---

## When to Read the Reference Files

Read `references/endpoints-free.md` when you need:
- Exact endpoint paths, HTTP methods, and parameters for free-tier endpoints
- Request/response examples for specific operations
- Relationship types available on each object for free users

Read `references/endpoints-enterprise.md` when you need:
- Enterprise-only endpoint details (Intelligence search, Hunting, Feeds, Private Scanning)
- Administration endpoints (user/group/quota management)
- VT Monitor and VT Graph specifics

Read `references/objects-and-relationships.md` when you need:
- Full attribute schemas for each object type
- Complete relationship map showing which relationships are free vs enterprise
- File object attribute details (PE info, sandbox verdicts, YARA results, etc.)
