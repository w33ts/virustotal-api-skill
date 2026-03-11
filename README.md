# VirusTotal API v3 - Agent Skill

An agent skill for the VirusTotal API v3 — file/URL/domain scanning,
threat intelligence lookups, and IoC enrichment. Works with Claude,
Claude Code, OpenAI Codex CLI, and any agent that supports the
Agent Skills standard.

## What This Skill Does

When your agent is working on a task involving VirusTotal, such as scanning a file
hash, checking a URL, writing an integration, handling rate limits, it will
automatically load this skill and give you accurate, complete answers without
needing to look up the docs.

## Install

**Claude Code (via plugin marketplace):**
`/plugin marketplace add w33ts/virustotal-api-skill`

**Manual install (Claude.ai or Claude Code):**
1. Download `virustotal-api.skill` from [Releases](https://github.com/w33ts/virustotal-api-skill/releases)
2. In Claude.ai: Settings → Skills → Upload skill file
3. In Claude Code: Extract to `~/.claude/skills/`

## What's Covered

- **Free vs Enterprise** - Clear distinction between Public API (4 req/min, 500/day)
  and Premium API capabilities
- **All core endpoints** - Files, URLs, Domains, IP addresses, Comments, Analyses
- **Enterprise endpoints** - VT Intelligence search, Livehunt, Retrohunt, Feeds,
  File Downloads, VT Graph
- **Rate limiting best practices** - Caching strategies, backoff patterns
- **Ready-to-run Python examples** - 6 practical examples from hash lookup to
  sandbox behavior analysis

## Triggering Examples

The agent automatically uses this skill when you ask things like:
- "Check if this SHA-256 hash is malicious"
- "Write a Python script to scan URLs with VirusTotal"
- "What's the difference between VT free and enterprise API?"
- "How do I handle QuotaExceededError in VirusTotal?"
- "Set up a Livehunt rule for YARA hunting"

## Requirements

- A VirusTotal API key (free at virustotal.com)
- For enterprise features: a VT Premium subscription

## License

MIT