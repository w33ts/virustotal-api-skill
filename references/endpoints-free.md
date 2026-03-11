# VirusTotal API v3 — Free (Public) Tier Endpoints

This reference covers all endpoints accessible with a free VirusTotal Community API key.
Rate limit: 4 requests/minute, 500 requests/day.

---

## Table of Contents

1. [Files](#files)
2. [URLs](#urls)
3. [Domains](#domains)
4. [IP Addresses](#ip-addresses)
5. [Comments](#comments)
6. [Analyses, Submissions & Operations](#analyses-submissions--operations)
7. [File Behaviours](#file-behaviours)
8. [Attack Tactics & Techniques](#attack-tactics--techniques)
9. [Popular Threat Categories](#popular-threat-categories)
10. [Search (Basic)](#search-basic)
11. [YARA Rules (Crowdsourced)](#yara-rules-crowdsourced)
12. [IoC Stream](#ioc-stream)
13. [Saved Searches](#saved-searches)
14. [VT Graphs](#vt-graphs)
15. [Code Insights](#code-insights)
16. [VT Augment Widget](#vt-augment-widget)

---

## Files

### Upload a file
```
POST /api/v3/files
Content-Type: multipart/form-data
```
Body: form field `file` containing the binary. Max 32MB via this endpoint.

**Response:** 200 with analysis object containing `id` (analysis ID) and `type: "analysis"`.

### Get upload URL for large files
```
GET /api/v3/files/upload_url
```
Returns a one-time-use URL for uploading files up to 650MB. POST the file to the returned URL
using the same multipart format.

### Get a file report
```
GET /api/v3/files/{id}
```
`{id}` can be an MD5, SHA-1, or SHA-256 hash. Returns the full file object with attributes
including `last_analysis_stats`, `last_analysis_results`, `type_description`, `size`, `names`,
`sha256`, `md5`, `sha1`, etc.

**Example response shape:**
```json
{
  "data": {
    "type": "file",
    "id": "<sha256>",
    "attributes": {
      "last_analysis_stats": {
        "malicious": 45,
        "suspicious": 0,
        "undetected": 25,
        "harmless": 0,
        "timeout": 1,
        "type-unsupported": 3,
        "failure": 0
      },
      "last_analysis_results": {
        "Kaspersky": {
          "category": "malicious",
          "engine_name": "Kaspersky",
          "engine_version": "22.0.1.28",
          "result": "Trojan.Win32.Generic",
          "method": "exact",
          "engine_update": "20250510"
        }
      },
      "sha256": "...",
      "md5": "...",
      "size": 123456,
      "type_description": "Win32 EXE",
      "meaningful_name": "setup.exe",
      "reputation": -45,
      "tags": ["peexe", "overlay"]
    }
  }
}
```

### Request a file rescan
```
POST /api/v3/files/{id}/analyse
```
Queues a rescan using the latest AV engine versions. Returns an analysis object.

### Comments on files
```
GET  /api/v3/files/{id}/comments         # List comments
POST /api/v3/files/{id}/comments         # Add a comment (body: {"data":{"type":"comment","attributes":{"text":"..."}}})
```

### Votes on files
```
GET  /api/v3/files/{id}/votes            # List votes
POST /api/v3/files/{id}/votes            # Vote (body: {"data":{"type":"vote","attributes":{"verdict":"malicious"|"harmless"}}})
```

### File relationships (free subset)
```
GET /api/v3/files/{id}/{relationship}
```

Free relationship types include:
- `behaviours` — sandbox behavior reports
- `bundled_files` — files contained within archives/bundles
- `collections` — collections containing this file
- `comments` — comments on this file
- `contacted_domains` — domains contacted during sandbox execution
- `contacted_ips` — IPs contacted during sandbox execution
- `contacted_urls` — URLs contacted during sandbox execution
- `dropped_files` — files dropped during sandbox execution
- `execution_parents` — files that executed this file
- `graphs` — VT graphs containing this file
- `pe_resource_children` / `pe_resource_parents` — PE resource relationships
- `sigma_analysis` — Sigma rule analysis results
- `votes` — community votes

🔒 Enterprise-only file relationships (will return ForbiddenError on free key):
`analyses`, `carbonblack_children`, `carbonblack_parents`, `compressed_parents`,
`email_attachments`, `email_parents`, `embedded_domains`, `embedded_ips`, `embedded_urls`,
`itw_domains`, `itw_ips`, `itw_urls`, `overlay_children`, `overlay_parents`,
`pcap_children`, `pcap_parents`, `related_references`, `related_threat_actors`,
`screenshots`, `similar_files`, `submissions`, `urls_for_embedded_js`

### Get Sigma / YARA rules for a file
```
GET /api/v3/sigma_analyses/{id}          # Get a Sigma rule analysis
GET /api/v3/yara_rulesets/{id}           # Get a YARA ruleset
```

---

## URLs

URL IDs in the v3 API are the base64url encoding of the URL (without trailing `=` padding).

```python
import base64
url_id = base64.urlsafe_b64encode("https://example.com".encode()).decode().rstrip("=")
# Result: "aHR0cHM6Ly9leGFtcGxlLmNvbQ"
```

### Scan a URL
```
POST /api/v3/urls
Content-Type: application/x-www-form-urlencoded
Body: url=https://example.com
```
Returns an analysis object. Poll `/analyses/{id}` for results.

### Get a URL report
```
GET /api/v3/urls/{id}
```

### Rescan a URL
```
POST /api/v3/urls/{id}/analyse
```

### Comments, votes, relationships
Same pattern as files. Free relationship types include:
`collections`, `comments`, `graphs`, `last_serving_ip_address`, `network_location`,
`related_comments`, `votes`

🔒 Enterprise-only URL relationships:
`analyses`, `communicating_files`, `contacted_domains`, `contacted_ips`, `downloaded_files`,
`embedded_js_files`, `redirecting_urls`, `redirects_to`, `referrer_files`, `referrer_urls`,
`related_references`, `related_threat_actors`, `submissions`,
`urls_related_by_tracker_id`

---

## Domains

### Get a domain report
```
GET /api/v3/domains/{domain}
```

### Rescan a domain
```
POST /api/v3/domains/{domain}/rescan
```

### Free domain relationships
`collections`, `comments`, `communicating_files`, `graphs`, `historical_ssl_certificates`,
`historical_whois`, `immediate_parent`, `parent`, `referrer_files`, `related_comments`,
`resolutions`, `siblings`, `subdomains`, `votes`

🔒 Enterprise-only: `caa_records`, `cname_records`, `downloaded_files`, `mx_records`,
`ns_records`, `related_references`, `related_threat_actors`, `soa_records`, `urls`

---

## IP Addresses

### Get an IP address report
```
GET /api/v3/ip_addresses/{ip}
```

### Rescan an IP
```
POST /api/v3/ip_addresses/{ip}/rescan
```

### Free IP relationships
`collections`, `comments`, `communicating_files`, `graphs`, `historical_ssl_certificates`,
`historical_whois`, `related_comments`, `referrer_files`, `resolutions`, `votes`

🔒 Enterprise-only: `downloaded_files`, `related_references`, `related_threat_actors`, `urls`

---

## Comments

### Global comment endpoints
```
GET    /api/v3/comments                  # Latest comments across VT
GET    /api/v3/comments/{id}             # Get a specific comment
DELETE /api/v3/comments/{id}             # Delete your own comment
GET    /api/v3/comments/{id}/{rel}       # Comment relationships
POST   /api/v3/comments/{id}/votes       # Vote on a comment
```

---

## Analyses, Submissions & Operations

### Get an analysis
```
GET /api/v3/analyses/{id}
```
Returns status and results of a scan/rescan. The `attributes.status` field will be `queued`,
`in-progress`, or `completed`. Once completed, `attributes.stats` contains detection counts.

### Get a submission
```
GET /api/v3/submissions/{id}
```

### Get an operation
```
GET /api/v3/operations/{id}
```
Operations represent long-running tasks and can be polled for completion.

---

## File Behaviours

```
GET /api/v3/files/{id}/behaviour_summary          # Summary of all sandbox reports
GET /api/v3/files/{id}/behaviour_mitre_trees       # MITRE ATT&CK summary
GET /api/v3/files/{id}/behaviours                  # All individual sandbox reports
GET /api/v3/file_behaviours/{id}                   # Specific sandbox report by ID
GET /api/v3/file_behaviours/{id}/html              # Detailed HTML report
GET /api/v3/file_behaviours/{id}/evtx              # Windows event log from sandbox
GET /api/v3/file_behaviours/{id}/pcap              # Network capture from sandbox
GET /api/v3/file_behaviours/{id}/memdump           # Memory dump from sandbox
```

Behaviour reports include: DNS lookups, HTTP conversations, IP traffic, processes tree,
files dropped, files copied, registry keys, mutexes, and more.

---

## Attack Tactics & Techniques

```
GET /api/v3/attack_tactics/{id}                    # Get a MITRE tactic
GET /api/v3/attack_tactics/{id}/{relationship}     # Related techniques
GET /api/v3/attack_techniques/{id}                 # Get a MITRE technique
GET /api/v3/attack_techniques/{id}/{relationship}  # Related tactics, subtechniques, etc.
```

🔒 The `threat_actors` relationship on attack techniques is enterprise-only.

---

## Popular Threat Categories

```
GET /api/v3/popular_threat_categories              # List popular threat categories
```

---

## Search (Basic)

```
GET /api/v3/search?query={query}
```

The basic search endpoint accepts exact indicators: file hashes (MD5/SHA-1/SHA-256), URLs,
domains, IP addresses, and tags. It does NOT support the full VT Intelligence search modifiers.
For advanced search with modifiers, you need the enterprise `/intelligence/search` endpoint.

---

## YARA Rules (Crowdsourced)

```
GET /api/v3/yara_rulesets                          # List crowdsourced YARA rulesets
GET /api/v3/yara_rulesets/{id}                     # Get a specific ruleset
GET /api/v3/yara_rulesets/{id}/{relationship}      # Related objects
```

These are community-contributed YARA rules, not your own Livehunt rules (which are 🔒).

---

## IoC Stream

The IoC Stream delivers notifications about IoCs matching your monitoring criteria.

```
GET /api/v3/ioc_stream                             # Get IoC Stream objects
GET /api/v3/ioc_stream_notifications/{id}          # Get a specific notification
DELETE /api/v3/ioc_stream_notifications/{id}       # Delete a notification
DELETE /api/v3/ioc_stream_notifications             # Delete all notifications
```

---

## Saved Searches

```
GET    /api/v3/intelligence/saved_searches          # List saved searches
GET    /api/v3/intelligence/saved_searches/{id}     # Get a saved search
POST   /api/v3/intelligence/saved_searches          # Create a saved search
PATCH  /api/v3/intelligence/saved_searches/{id}     # Update a saved search
DELETE /api/v3/intelligence/saved_searches/{id}     # Delete a saved search
POST   /api/v3/intelligence/saved_searches/{id}/share           # Share
DELETE /api/v3/intelligence/saved_searches/{id}/revoke_access    # Revoke access
```

---

## VT Graphs

```
GET    /api/v3/graphs                               # Search graphs
POST   /api/v3/graphs                               # Create a graph
GET    /api/v3/graphs/{id}                           # Get a graph
PATCH  /api/v3/graphs/{id}                           # Update a graph
DELETE /api/v3/graphs/{id}                           # Delete a graph
```

Permissions endpoints for viewers and editors are also available.

---

## Code Insights

```
POST /api/v3/code_insights                          # Analyze code blocks
```
Sends code blocks for AI-powered analysis and explanation.

---

## VT Augment Widget

```
GET /api/v3/widget/url?query={indicator}            # Get widget rendering URL
GET /api/v3/widget/html/{token}                     # Get widget HTML content
```

The widget provides an embeddable threat context panel for third-party applications.
Theming is available via the `/widget/theme` endpoint.
