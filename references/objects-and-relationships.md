# VirusTotal API v3 — Objects & Relationships Reference

This reference documents the main API object types, their key attributes, and relationship
mappings. Items marked 🔒 require enterprise access.

---

## Table of Contents

1. [Object Structure](#object-structure)
2. [File Object](#file-object)
3. [URL Object](#url-object)
4. [Domain Object](#domain-object)
5. [IP Address Object](#ip-address-object)
6. [Comment Object](#comment-object)
7. [Analysis Object](#analysis-object)
8. [File Behaviour Object](#file-behaviour-object)
9. [Graph Object](#graph-object)
10. [Hunting Objects](#hunting-objects)
11. [Other Objects](#other-objects)
12. [Relationship Access Matrix](#relationship-access-matrix)

---

## Object Structure

Every VT API object follows this pattern:

```json
{
  "type": "<object_type>",
  "id": "<unique_identifier>",
  "links": {
    "self": "https://www.virustotal.com/api/v3/<type>/<id>"
  },
  "attributes": { ... },
  "relationships": { ... }
}
```

Relationships are not included by default. Request them explicitly:
```
GET /api/v3/files/{id}?relationships=contacted_domains,dropped_files
```

Or fetch them separately:
```
GET /api/v3/files/{id}/contacted_domains
```

---

## File Object

**Type:** `file`
**ID:** SHA-256 hash

### Key attributes

| Attribute | Description |
|-----------|-------------|
| `sha256`, `sha1`, `md5` | File hashes |
| `size` | File size in bytes |
| `type_description` | Human-readable file type |
| `type_tag` | Short type tag (e.g., `peexe`, `pdf`, `doc`) |
| `meaningful_name` | Most meaningful filename from submissions |
| `names` | All known filenames |
| `tags` | Auto-generated tags |
| `creation_date` | File creation timestamp |
| `first_submission_date` | When first submitted to VT |
| `last_submission_date` | When last submitted |
| `last_analysis_date` | When last analyzed |
| `last_analysis_stats` | Detection summary counts |
| `last_analysis_results` | Per-engine results |
| `reputation` | Community reputation score |
| `total_votes` | Vote counts (harmless/malicious) |
| `popular_threat_classification` | Categorized threat type |
| `sigma_analysis_stats` | Sigma rule match statistics |
| `sigma_analysis_results` | Sigma rule matches |
| `crowdsourced_yara_results` | YARA rule matches |
| `crowdsourced_ids_results` | IDS (Snort/Suricata) results |
| `sandbox_verdicts` | Sandbox detection verdicts |
| `pe_info` | PE header information (for executables) |
| `elf_info` | ELF header information (for Linux binaries) |
| `macho_info` | Mach-O information (for macOS binaries) |
| `pdf_info` | PDF structure information |
| `androguard` | Android APK analysis |
| `signature_info` | Digital signature details |
| `ssdeep`, `tlsh`, `telfhash` | Fuzzy hashes for similarity matching |
| `detectiteasy` | Detect-It-Easy packer/compiler identification |
| `magic` | File magic string |
| 🔒 `exiftool` | ExifTool metadata |
| 🔒 `malware_config` | Extracted malware configuration |
| 🔒 `office_info` | Office document details |
| 🔒 `openxml_info` | OpenXML document details |
| 🔒 `rtf_info` | RTF document details |

### File relationships

**Free access:**
- `behaviours` — Sandbox behavior reports
- `bundled_files` — Files inside archives/bundles
- `collections` — VT collections containing this file
- `comments` — Community comments
- `contacted_domains` — Domains contacted in sandbox
- `contacted_ips` — IPs contacted in sandbox
- `contacted_urls` — URLs contacted in sandbox
- `dropped_files` — Files dropped during execution
- `execution_parents` — Files that spawned this file
- `graphs` — VT Graph references
- `pe_resource_children` / `pe_resource_parents` — PE resource links
- `sigma_analysis` — Sigma rule analysis
- `memory_pattern_domains` / `memory_pattern_ips` / `memory_pattern_urls` — Memory-extracted IOCs
- `votes` — Community votes

**🔒 Enterprise only:**
- `analyses` — Submission analyses history
- `carbonblack_children` / `carbonblack_parents` — Carbon Black telemetry
- `compressed_parents` — Archives containing this file
- `email_attachments` / `email_parents` — Email relationships
- `embedded_domains` / `embedded_ips` / `embedded_urls` — Statically embedded IOCs
- `itw_domains` / `itw_ips` / `itw_urls` — In-the-wild distribution infrastructure
- `overlay_children` / `overlay_parents` — PE overlay relationships
- `pcap_children` / `pcap_parents` — PCAP relationships
- `related_references` — Threat intelligence references
- `related_threat_actors` — Associated threat actors
- `screenshots` — Sandbox execution screenshots
- `similar_files` — Structurally similar files
- `submissions` — Submission history with metadata
- `urls_for_embedded_js` — URLs hosting embedded JavaScript

---

## URL Object

**Type:** `url`
**ID:** Base64url-encoded URL (no padding)

### Key attributes

| Attribute | Description |
|-----------|-------------|
| `url` | The actual URL string |
| `last_http_response_content_length` | Response size |
| `last_http_response_content_sha256` | SHA-256 of response body |
| `last_http_response_code` | HTTP status code |
| `last_analysis_stats` | Detection summary |
| `last_analysis_results` | Per-engine results |
| `last_analysis_date` | When last analyzed |
| `reputation` | Community reputation score |
| `total_votes` | Vote counts |
| `tags` | Auto-generated tags |
| `categories` | Categorization by various vendors |
| `title` | Page title |
| `html_meta` | HTML meta tags |
| `trackers` | Detected tracking technologies |
| `last_final_url` | URL after redirects |

---

## Domain Object

**Type:** `domain`
**ID:** Domain name string

### Key attributes

| Attribute | Description |
|-----------|-------------|
| `last_analysis_stats` | Detection summary |
| `last_analysis_results` | Per-engine results |
| `registrar` | Domain registrar |
| `creation_date` | Domain registration date |
| `last_dns_records` | Current DNS records |
| `last_https_certificate` | Current SSL certificate |
| `popularity_ranks` | Rankings from various services |
| `categories` | Categorization by vendors |
| `whois` | WHOIS data |
| `reputation` | Community reputation |
| `total_votes` | Vote counts |
| `tags` | Auto-generated tags |

---

## IP Address Object

**Type:** `ip_address`
**ID:** IP address string

### Key attributes

| Attribute | Description |
|-----------|-------------|
| `last_analysis_stats` | Detection summary |
| `last_analysis_results` | Per-engine results |
| `asn` | Autonomous System Number |
| `as_owner` | AS owner name |
| `country` | Country code |
| `continent` | Continent code |
| `network` | CIDR network |
| `regional_internet_registry` | RIR (ARIN, RIPE, etc.) |
| `last_https_certificate` | Current SSL cert |
| `whois` | WHOIS data |
| `reputation` | Community reputation |
| `total_votes` | Vote counts |
| `tags` | Auto-generated tags |

---

## Comment Object

**Type:** `comment`
**ID:** Comment ID string

### Key attributes
- `text` — Comment body (supports VT's hashtag and IoC linking syntax)
- `date` — Creation timestamp
- `votes` — Vote counts on the comment
- `html` — Rendered HTML version

### Relationships
- `author` — User who wrote the comment

---

## Analysis Object

**Type:** `analysis`
**ID:** Analysis ID (returned by scan/rescan endpoints)

### Key attributes
- `status` — `queued`, `in-progress`, or `completed`
- `stats` — Detection count summary (when completed)
- `results` — Per-engine results (when completed)
- `date` — Analysis timestamp

### Relationships
- `item` — The file or URL that was analyzed

---

## File Behaviour Object

**Type:** `file_behaviour`

### Key attributes
- `sandbox_name` — Name of the sandbox that produced the report
- `analysis_date` — When the analysis was performed
- `tags` — Behavior tags
- `verdicts` — Sandbox verdicts
- `dns_lookups` — DNS queries made
- `http_conversations` — HTTP request/response pairs
- `ip_traffic` — Network traffic to IPs
- `processes_tree` — Process execution tree
- `files_dropped` — Files created during execution
- `files_copied` — Files copied
- `files_opened` / `files_written` / `files_deleted` — File system activity
- `registry_keys_opened` / `registry_keys_set` / `registry_keys_deleted` — Registry activity
- `mutexes_created` / `mutexes_opened` — Synchronization primitives
- `command_executions` — Commands executed
- `modules_loaded` — DLLs/modules loaded
- `services_created` / `services_started` — Windows services
- `permissions_checked` — Android permissions
- `sms_sent` — SMS messages (Android)

### Relationships
- `file` — The analyzed file
- `attack_techniques` — MITRE ATT&CK techniques observed

---

## Graph Object

**Type:** `graph`
**ID:** Graph ID string

### Key attributes
- `graph_data` — JSON structure of nodes and links
- `label` — Graph name
- `owner` — Creator user ID

### Relationships
- `comments`, `editors`, `group`, `items`, `owner`, `viewers`

---

## Hunting Objects

### Hunting Ruleset (🔒)
- `type: "hunting_ruleset"`
- Attributes: `name`, `enabled`, `rules` (YARA source), `limit`, `match_object_type`
- Relationships: `owner`, `editors`, `viewers`, `hunting_notification_files`

### Hunting Notification (🔒)
- `type: "hunting_notification"`
- Attributes: `date`, `source_key`, `rule_name`, `tags`

### Retrohunt Job (🔒)
- `type: "retrohunt_job"`
- Attributes: `rules`, `status`, `progress`, `scanned_bytes`, `matching_files`
- Relationships: `matching_files`, `owner`

---

## Other Objects

| Object | Type | Description |
|--------|------|-------------|
| Resolution | `resolution` | DNS resolution record (domain ↔ IP) |
| SSL Certificate | `ssl_certificate` | TLS/SSL certificate details |
| Submission | `submission` | File/URL submission metadata |
| Whois | `whois` | Historical WHOIS records |
| Sigma Rule | `sigma_rule` | Sigma detection rule |
| YARA Rule | `yara_rule` | YARA detection rule |
| YARA Ruleset | `yara_ruleset` | Collection of YARA rules |
| Vote | `vote` | Community vote (malicious/harmless) |
| Operation | `operation` | Async operation status |
| 🔒 Private File | `private_file` | Privately scanned file |
| 🔒 Private Analysis | `private_analysis` | Private scan result |
| 🔒 Activity Log | `activity_log` | Audit log entry |
| 🔒 Service Account | `service_account` | Programmatic access account |

---

## Relationship Access Matrix

This matrix shows which relationship types are available at each tier for the four main
object types.

### Legend
- ✅ Free — available with public API key
- 🔒 Enterprise — requires premium API key
- 🧑‍💻 Authenticated — requires any API key with appropriate user context

### File relationships
| Relationship | Access |
|-------------|--------|
| behaviours | ✅ |
| bundled_files | ✅ |
| collections | ✅ |
| comments | ✅ |
| contacted_domains | ✅ |
| contacted_ips | ✅ |
| contacted_urls | ✅ |
| dropped_files | ✅ |
| execution_parents | ✅ |
| graphs | ✅ |
| pe_resource_children | ✅ |
| pe_resource_parents | ✅ |
| sigma_analysis | ✅ |
| memory_pattern_domains | ✅ |
| memory_pattern_ips | ✅ |
| memory_pattern_urls | ✅ |
| user_votes | 🧑‍💻 |
| votes | ✅ |
| analyses | 🔒 |
| carbonblack_children | 🔒 |
| carbonblack_parents | 🔒 |
| compressed_parents | 🔒 |
| email_attachments | 🔒 |
| email_parents | 🔒 |
| embedded_domains | 🔒 |
| embedded_ips | 🔒 |
| embedded_urls | 🔒 |
| itw_domains | 🔒 |
| itw_ips | 🔒 |
| itw_urls | 🔒 |
| overlay_children | 🔒 |
| overlay_parents | 🔒 |
| pcap_children | 🔒 |
| pcap_parents | 🔒 |
| related_references | 🔒 |
| related_threat_actors | 🔒 |
| screenshots | 🔒 |
| similar_files | 🔒 |
| submissions | 🔒 |
| urls_for_embedded_js | 🔒 |

### Domain relationships
| Relationship | Access |
|-------------|--------|
| collections | ✅ |
| comments | ✅ |
| communicating_files | ✅ |
| graphs | ✅ |
| historical_ssl_certificates | ✅ |
| historical_whois | ✅ |
| immediate_parent | ✅ |
| parent | ✅ |
| referrer_files | ✅ |
| related_comments | ✅ |
| resolutions | ✅ |
| siblings | ✅ |
| subdomains | ✅ |
| user_votes | 🧑‍💻 |
| votes | ✅ |
| caa_records | 🔒 |
| cname_records | 🔒 |
| downloaded_files | 🔒 |
| mx_records | 🔒 |
| ns_records | 🔒 |
| related_references | 🔒 |
| related_threat_actors | 🔒 |
| soa_records | 🔒 |
| urls | 🔒 |

### IP Address relationships
| Relationship | Access |
|-------------|--------|
| collections | ✅ |
| comments | ✅ |
| communicating_files | ✅ |
| graphs | ✅ |
| historical_ssl_certificates | ✅ |
| historical_whois | ✅ |
| related_comments | ✅ |
| referrer_files | ✅ |
| resolutions | ✅ |
| user_votes | 🧑‍💻 |
| votes | ✅ |
| downloaded_files | 🔒 |
| related_references | 🔒 |
| related_threat_actors | 🔒 |
| urls | 🔒 |

### URL relationships
| Relationship | Access |
|-------------|--------|
| collections | ✅ |
| comments | ✅ |
| graphs | ✅ |
| last_serving_ip_address | ✅ |
| network_location | ✅ |
| related_comments | ✅ |
| user_votes | 🧑‍💻 |
| votes | ✅ |
| analyses | 🔒 |
| communicating_files | 🔒 |
| contacted_domains | 🔒 |
| contacted_ips | 🔒 |
| downloaded_files | 🔒 |
| embedded_js_files | 🔒 |
| redirecting_urls | 🔒 |
| redirects_to | 🔒 |
| referrer_files | 🔒 |
| referrer_urls | 🔒 |
| related_references | 🔒 |
| related_threat_actors | 🔒 |
| submissions | 🔒 |
| urls_related_by_tracker_id | 🔒 |
