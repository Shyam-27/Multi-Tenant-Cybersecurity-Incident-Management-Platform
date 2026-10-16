# Phase 6 Architecture: Threat Intelligence Feeds, SIEM Alerting & Incident Response Playbooks

## 1. Overview & Objectives

Phase 6 extends the Multi-Tenant Cybersecurity Incident Management Platform (SentinelOps) with three enterprise automation capabilities:
1. **Module A: Threat Intelligence & IOC Management**: Normalized storage, multi-provider enrichment (VirusTotal v3, AbuseIPDB v2, AlienVault OTX), caching TTLs, confidence aggregation, and false-positive handling.
2. **Module B: Real-Time SIEM & Webhook Dispatcher**: Destination management for Splunk HEC, Elastic SIEM, Microsoft Teams, Slack, and generic webhooks, featuring SSRF protection against private IP spaces and cloud metadata, exponential backoff retries, and synthetic testing.
3. **Module C: Automated Incident Response Playbooks**: Workflow execution engine with simulation mode (Dry Run), credential session revocation with anti-privilege escalation, simulated endpoint containment, and dual-authorization approval with anti-self-approval enforcement.

---

## 2. Threat Intelligence Subsystem

### 2.1 IOC Normalization & Canonical Format
All indicators are normalized and validated prior to database persistence:
- **IPv4 / IPv6**: Canonical string format via Python's standard `ipaddress.ip_address`.
- **Domain**: Lowercased, stripped of trailing dots and protocol prefixes, validated against domain regex.
- **URL**: Lowercased scheme and host, stripped whitespace, validated with standard URL regex.
- **File Hashes**: Hexadecimal lowercased format for SHA-256 (64 hex characters), SHA-1 (40 hex characters), and MD5 (32 hex characters).

### 2.2 Provider Adapters & Verdict Aggregation
Enrichment queries third-party threat intelligence APIs through abstract `ThreatIntelProvider` adapters:
- `VirusTotalProvider`: Queries `/api/v3/{ip_addresses,domains,urls,files}/{value}`. Computes malicious and suspicious detection counts.
- `AbuseIPDBProvider`: Queries `/api/v2/check` for IPv4 and IPv6 addresses. Extracts `abuseConfidenceScore` and reporter telemetry.
- `AlienVaultOTXProvider`: Queries `/api/v1/indicators/{IPv4,domain,url,file}/{value}/general` for threat pulse counts and malware families.

### 2.3 Verdict Scoring Algorithm
```python
if total_malicious >= 3 or abuse_score >= 50 or otx_pulses >= 5:
    verdict = ThreatVerdict.MALICIOUS
    confidence = min(0.99, max(0.65, (total_malicious / 10.0)))
elif total_malicious >= 1 or total_suspicious >= 2 or abuse_score >= 20:
    verdict = ThreatVerdict.SUSPICIOUS
    confidence = min(0.75, max(0.40, (abuse_score / 100.0)))
elif harmless >= 10:
    verdict = ThreatVerdict.BENIGN
    confidence = 0.85
else:
    verdict = ThreatVerdict.UNKNOWN
```

### 2.4 Caching TTL
A 24-hour cache TTL (`THREAT_INTEL_CACHE_HOURS = 24`) ensures indicators are not queried repeatedly if refreshed recently, conserving API quotas while keeping data current.

---

## 3. SIEM & Webhook Dispatcher

### 3.1 Server-Side Request Forgery (SSRF) Defense
Outbound webhook destinations are validated before persistence and before dispatch:
- **URL Scheme**: Enforced `https` in production (allows `http` in test/development).
- **DNS Resolution**: The host is resolved to an IP address.
- **Blocked Address Ranges**:
  - `127.0.0.0/8` (Loopback)
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private RFC 1918)
  - `169.254.169.254` and `169.254.0.0/16` (AWS/Azure/GCP Cloud Metadata)
  - `::1`, `fc00::/7`, `fe80::/10` (IPv6 loopback, unique local, link-local)

### 3.2 Platform-Specific Payload Formatters
- **Splunk HEC**: Formatted as JSON event payload `{ "time": epoch, "event": { ... } }` with `Authorization: Splunk <token>`.
- **Elastic SIEM**: Formatted with ECS (Elastic Common Schema) fields: `@timestamp`, `event.category`, `event.action`, `message`.
- **Microsoft Teams**: Formatted as an Adaptive Card with summary facts and accent colors.
- **Slack**: Formatted with `blocks` section, mrkdwn formatting, and header accessories.

### 3.3 Delivery Reliability
- Webhook dispatches are executed with timeout controls and exponential backoff retry tracking.
- Webhook dispatch failures do not roll back platform incident creation or note additions.
- All delivery attempts are audited in the `webhook_deliveries` table.

---

## 4. Incident Response Playbook Engine

### 4.1 Safety Architecture & Simulation (Dry Run)
Every playbook defaults to `is_dry_run = True`. During dry-run execution:
- Actions simulate effects and produce realistic log traces with status `SIMULATED`.
- No active sessions are terminated, no network rules are altered.
- Live mode (`is_dry_run = False`) requires administrative privileges and explicit parameter overrides.

### 4.2 Security Constraints
1. **Anti-Privilege Escalation**:
   - `SECURITY_ANALYST` users cannot revoke sessions of `TENANT_ADMIN` or `SUPER_ADMIN` accounts.
   - Any attempt to target a user of equal or higher privilege raises a 400 Bad Request error.
2. **Loopback & Infrastructure Shielding**:
   - Simulated IP blocklists and endpoint isolations strictly disallow `127.0.0.1`, `::1`, and loopback domains (`localhost`), preventing self-inflicted SOC denial-of-service.
3. **Dual Authorization & Anti-Self-Approval**:
   - Playbooks marked with `requires_approval = True` enter `PENDING_APPROVAL` status upon invocation.
   - The user who requested the playbook execution cannot approve their own request (`AntiSelfApprovalError`).
   - A different authorized administrator must execute the approval.

---

## 5. Automated Test Coverage

The test suite covers:
- **`tests/test_threat_intel.py`** (11 tests): Normalization, validation, tenant isolation, cross-tenant 404, mock provider lookups (VT, AbuseIPDB), caching TTL, missing API keys, and false-positive flags.
- **`tests/test_webhooks.py`** (7 tests): SSRF validation (blocking loopback, RFC1918, cloud metadata), destination CRUD, synthetic ping, incident dispatch integration, and non-blocking failure semantics.
- **`tests/test_playbooks.py`** (8 tests): Playbook CRUD, RBAC, dry-run simulation, session revocation, anti-privilege escalation, loopback shield, dual-authorization approval, and rejection workflow.
- Total suite: **98 passing tests (100% pass rate)**.
