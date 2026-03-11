# VirusTotal API v3 — Enterprise (Premium) Tier Endpoints 🔒

All endpoints in this file require a premium/enterprise API key. Attempting these with a free
key returns HTTP 403 `ForbiddenError`.

---

## Table of Contents

1. [VT Intelligence — Advanced Search](#vt-intelligence--advanced-search)
2. [File Downloads](#file-downloads)
3. [VT Hunting — Livehunt](#vt-hunting--livehunt)
4. [VT Hunting — Retrohunt](#vt-hunting--retrohunt)
5. [VT Feeds](#vt-feeds)
6. [Private Scanning](#private-scanning)
7. [Collections (Advanced)](#collections-advanced)
8. [Zipping Files](#zipping-files)
9. [Administration](#administration)
10. [VT Monitor](#vt-monitor)

---

## VT Intelligence — Advanced Search

The crown jewel of the enterprise API. Allows full corpus search across all VT entities
using rich search modifiers.

### Advanced corpus search
```
GET /api/v3/intelligence/search?query={query}&limit={n}&order={order}&descriptors_only={bool}
```

The query uses VT Intelligence search modifier syntax. Entity types: `file`, `url`, `domain`,
`ip_address`, `collection`.

**Common search modifiers (files):**
- `type:peexe` — file type
- `positives:10+` — minimum detection count
- `size:1MB+` — minimum file size
- `fs:2025-01-01+` — first submission date
- `ls:2025-05-01+` — last submission date
- `tag:signed` — tagged attributes
- `name:"invoice.pdf"` — filename
- `behaviour_network:"malicious.com"` — sandbox network activity
- `content:"hello world"` — content search (with snippet retrieval)
- `engines:"Kaspersky:Trojan.Win32"` — specific AV detection
- `submitter:US` — submission country
- `entity:url` / `entity:domain` / `entity:ip` — search other entity types

**Searching other entities:**
- `entity:url url:"example.com"` — search URLs
- `entity:domain dns:1.2.3.4` — domains resolving to an IP
- `entity:ip asn:12345` — IPs in an ASN
- `entity:collection threat_actor:apt29` — collections by threat actor

**Ordering:**
- `first_submission_date+` / `first_submission_date-`
- `positives+` / `positives-`
- `size+` / `size-`
- `last_analysis_date+` / `last_analysis_date-`

**Pagination:** Use the `cursor` from `links.next` to paginate. Max 300 results per query chain.

**Example — Find recent Emotet samples:**
```python
import requests

headers = {"x-apikey": "PREMIUM_KEY"}
params = {
    "query": 'type:peexe tag:emotet fs:2025-05-01+ positives:15+',
    "limit": 20,
    "order": "first_submission_date-"
}
resp = requests.get(
    "https://www.virustotal.com/api/v3/intelligence/search",
    headers=headers, params=params
)
for item in resp.json()["data"]:
    print(item["id"], item["attributes"]["meaningful_name"])
```

### Content search snippets
```
GET /api/v3/intelligence/search/snippets/{id}
```
When using `content:` searches, this returns the matching code/text snippets within files.

### Get VT metadata
```
GET /api/v3/metadata
```
Returns platform-wide metadata including fresh_data_timestamp and other system info.

---

## File Downloads

### Get download URL
```
GET /api/v3/files/{id}/download_url
```
Returns a time-limited URL for downloading the file.

### Direct download
```
GET /api/v3/files/{id}/download
```
Returns the raw file bytes. Use appropriate precautions when downloading malware.

**Example — Download and save a sample:**
```python
import requests

headers = {"x-apikey": "PREMIUM_KEY"}
sha256 = "abc123def456..."

resp = requests.get(
    f"https://www.virustotal.com/api/v3/files/{sha256}/download",
    headers=headers
)
with open(f"samples/{sha256}", "wb") as f:
    f.write(resp.content)
```

---

## VT Hunting — Livehunt

Livehunt lets you deploy YARA rules that run against every file submitted to VT in real time.

### Rulesets
```
GET    /api/v3/intelligence/hunting_rulesets          # List your rulesets
POST   /api/v3/intelligence/hunting_rulesets          # Create a new ruleset
GET    /api/v3/intelligence/hunting_rulesets/{id}     # Get a ruleset
PATCH  /api/v3/intelligence/hunting_rulesets/{id}     # Update a ruleset
DELETE /api/v3/intelligence/hunting_rulesets/{id}     # Delete a ruleset
DELETE /api/v3/intelligence/hunting_rulesets           # Delete ALL rulesets
```

**Create ruleset body:**
```json
{
  "data": {
    "type": "hunting_ruleset",
    "attributes": {
      "name": "detect_emotet",
      "enabled": true,
      "rules": "rule emotet_loader {\n  strings:\n    $s1 = \"RegOpenKeyExW\"\n    $s2 = \"VirtualAlloc\"\n  condition:\n    all of them\n}"
    }
  }
}
```

### Notifications
```
GET    /api/v3/intelligence/hunting_notifications          # List notifications
GET    /api/v3/intelligence/hunting_notifications/{id}     # Get a notification
DELETE /api/v3/intelligence/hunting_notifications/{id}     # Delete a notification
DELETE /api/v3/intelligence/hunting_notifications           # Delete all notifications
GET    /api/v3/intelligence/hunting_notifications/{id}/files  # Files for notification
```

### Permissions
```
GET    /api/v3/intelligence/hunting_rulesets/{id}/editors
POST   /api/v3/intelligence/hunting_rulesets/{id}/editors
DELETE /api/v3/intelligence/hunting_rulesets/{id}/editors/{user_or_group}
GET    /api/v3/intelligence/hunting_rulesets/{id}/editors/{user_or_group}
POST   /api/v3/intelligence/hunting_rulesets/{id}/transfer  # Transfer to another user
```

---

## VT Hunting — Retrohunt

Retrohunt runs a YARA rule against VT's historical file corpus (billions of files).

```
GET    /api/v3/intelligence/retrohunt_jobs               # List retrohunt jobs
POST   /api/v3/intelligence/retrohunt_jobs               # Create a new job
GET    /api/v3/intelligence/retrohunt_jobs/{id}          # Get job status
DELETE /api/v3/intelligence/retrohunt_jobs/{id}          # Delete a job
POST   /api/v3/intelligence/retrohunt_jobs/{id}/abort    # Abort a running job
GET    /api/v3/intelligence/retrohunt_jobs/{id}/matching_files  # Get matches
```

**Create retrohunt body:**
```json
{
  "data": {
    "type": "retrohunt_job",
    "attributes": {
      "rules": "rule test { strings: $a = \"malware\" condition: $a }",
      "notification_email": "analyst@example.com"
    }
  }
}
```

Jobs run asynchronously. Poll the job endpoint to check `attributes.status`:
`queued` → `starting` → `running` → `completed`

---

## VT Feeds

Intelligence feeds provide a continuous stream of all items processed by VT. Useful for
building local mirrors or feeding SIEMs.

### File feed
```
GET /api/v3/feeds/files/{time}                     # Per-minute batch (format: YYYYMMDDhhmm)
GET /api/v3/feeds/files/hourly/{time}              # Hourly batch (format: YYYYMMDDhh)
GET /api/v3/feeds/files/{id}/download              # Download a file from the feed
```

### Sandbox analysis feed
```
GET /api/v3/feeds/file-behaviours/{time}           # Per-minute batch
GET /api/v3/feeds/file-behaviours/hourly/{time}    # Hourly batch
GET /api/v3/feeds/file-behaviours/{id}/evtx        # EVTX from feed item
GET /api/v3/feeds/file-behaviours/{id}/pcap        # PCAP from feed item
GET /api/v3/feeds/file-behaviours/{id}/memdump     # Memory dump from feed item
GET /api/v3/feeds/file-behaviours/{id}/html        # HTML report from feed item
```

### Domain, IP, and URL feeds
```
GET /api/v3/feeds/domains/{time}                   # Per-minute domain batch
GET /api/v3/feeds/domains/hourly/{time}            # Hourly domain batch
GET /api/v3/feeds/ip-addresses/{time}              # Per-minute IP batch
GET /api/v3/feeds/ip-addresses/hourly/{time}       # Hourly IP batch
GET /api/v3/feeds/urls/{time}                      # Per-minute URL batch
GET /api/v3/feeds/urls/hourly/{time}               # Hourly URL batch
```

All feed responses are bzip2-compressed tarballs containing one JSON object per line.

---

## Private Scanning

Private scanning analyzes files/URLs without contributing them to the public VT corpus.
Results are only visible to your organization.

### Private files
```
POST   /api/v3/private/files                       # Upload a private file
GET    /api/v3/private/files                        # List private files
GET    /api/v3/private/files/upload_url             # Upload URL for large files
POST   /api/v3/private/files/{id}/analyse           # Rescan a private file
GET    /api/v3/private/files/{id}                   # Get private file report
DELETE /api/v3/private/files/{id}                   # Delete private file report
GET    /api/v3/private/files/{id}/{relationship}    # Related objects
```

### Private analyses
```
GET /api/v3/private/analyses                        # List private analyses
GET /api/v3/private/analyses/{id}                   # Get a private analysis
```

### Private file behaviours
```
GET /api/v3/private/file_behaviours/{id}                   # Specific sandbox report
GET /api/v3/private/files/{id}/behaviours                   # All reports for a file
GET /api/v3/private/files/{id}/behaviour_summary            # Summary
GET /api/v3/private/files/{id}/behaviour_mitre_trees        # MITRE ATT&CK
GET /api/v3/private/file_behaviours/{id}/html               # HTML report
GET /api/v3/private/file_behaviours/{id}/evtx               # EVTX
GET /api/v3/private/file_behaviours/{id}/pcap               # PCAP
GET /api/v3/private/file_behaviours/{id}/memdump            # Memory dump
```

### Private URLs
```
POST /api/v3/private/urls                           # Submit URL for private scan
GET  /api/v3/private/urls/{id}                      # Get private URL report
```

### Zipping private files
```
POST /api/v3/private/files/zip                      # Create ZIP of private files
GET  /api/v3/private/files/zip/{id}                 # Check ZIP status
GET  /api/v3/private/files/zip/{id}/download_url    # Get download URL
GET  /api/v3/private/files/zip/{id}/download        # Download ZIP
```

---

## Collections (Advanced)

While basic collection operations are available to free users, these are enterprise-only:

```
GET    /api/v3/collections                          # List all collections
GET    /api/v3/collections/{id}/export_iocs         # Export IOCs
GET    /api/v3/collections/{id}/export_iocs/{rel}   # Export IOCs from relationship
GET    /api/v3/collections/{id}/export_aggregations # Export aggregations
GET    /api/v3/collections/{id}/search_iocs         # Search IOCs within collection
```

---

## Zipping Files

```
POST /api/v3/intelligence/zip_files                 # Create password-protected ZIP
GET  /api/v3/intelligence/zip_files/{id}            # Check ZIP status
GET  /api/v3/intelligence/zip_files/{id}/download_url  # Get download URL
GET  /api/v3/intelligence/zip_files/{id}/download   # Download ZIP
```

**Create ZIP body:**
```json
{
  "data": {
    "hashes": ["sha256_hash_1", "sha256_hash_2"],
    "password": "infected"
  }
}
```

---

## Administration

### User management
```
GET    /api/v3/users/{id}                           # Get user object
PATCH  /api/v3/users/{id}                           # Update user
DELETE /api/v3/users/{id}                           # Delete user
GET    /api/v3/users/{id}/{relationship}            # User relationships
```

### Group management
```
GET    /api/v3/groups/{id}                          # Get group
PATCH  /api/v3/groups/{id}                          # Update group
GET    /api/v3/groups/{id}/administrators            # Group admins
PATCH  /api/v3/groups/{id}/users/roles               # Manage roles
GET    /api/v3/groups/{id}/users                     # List group users
POST   /api/v3/groups/{id}/users                     # Add users
DELETE /api/v3/groups/{id}/users/{user_id}           # Remove user
```

### Quota management
```
GET /api/v3/users/{id}/api_usage                    # User API usage
GET /api/v3/groups/{id}/api_usage                   # Group API usage
GET /api/v3/groups/{id}/usage                       # Group usage per feature
```

### Service accounts
```
POST /api/v3/groups/{id}/service_accounts           # Create service account
GET  /api/v3/groups/{id}/service_accounts           # List service accounts
GET  /api/v3/service_accounts/{id}                  # Get service account
```

### Audit log
```
GET /api/v3/activity_log                            # Get activity logs
```

---

## VT Monitor

### Software publishers
```
GET    /api/v3/monitor/items?filter={path|tag}      # List monitor items
POST   /api/v3/monitor/items                         # Upload file or create folder
GET    /api/v3/monitor/items/upload_url              # Upload URL for >32MB files
GET    /api/v3/monitor/items/{id}                    # Get item attributes
DELETE /api/v3/monitor/items/{id}                    # Delete item
PATCH  /api/v3/monitor/items/{id}                    # Configure item
GET    /api/v3/monitor/items/{id}/download           # Download file
GET    /api/v3/monitor/items/{id}/download_url       # Get download URL
GET    /api/v3/monitor/items/{id}/analyses           # Latest analyses
GET    /api/v3/monitor/items/{id}/owner              # Owning user
GET    /api/v3/monitor/items/{id}/comments           # Partner comments
GET    /api/v3/monitor/statistics                    # Analysis statistics
GET    /api/v3/monitor/events                        # Historical events
```

### Antivirus partners
```
GET    /api/v3/monitor/partner/hashes                       # Detected hashes
GET    /api/v3/monitor/partner/hashes/{sha256}/analyses     # Analyses for hash
GET    /api/v3/monitor/partner/hashes/{sha256}/items        # Items with hash
POST   /api/v3/monitor/partner/hashes/{sha256}/comments     # Create comment
GET    /api/v3/monitor/partner/hashes/{sha256}/comments     # Get comments
PATCH  /api/v3/monitor/partner/hashes/{sha256}/comments/{id}  # Update comment
DELETE /api/v3/monitor/partner/hashes/{sha256}/comments/{id}  # Delete comment
GET    /api/v3/monitor/partner/hashes/{sha256}/download     # Download file
GET    /api/v3/monitor/partner/hashes/{sha256}/download_url # Download URL
GET    /api/v3/monitor/partner/detections_bundle/download   # Daily bundle
GET    /api/v3/monitor/partner/detections_bundle/download_url
GET    /api/v3/monitor/partner/statistics                   # Partner statistics
```
