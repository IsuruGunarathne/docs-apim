# Preventing SSRF Attacks in Outbound Requests

## Overview

Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can manipulate a server to make unintended outbound requests to internal or external systems.

In WSO2 API Manager, outbound requests such as endpoint validation, WSDL imports, and other internal HTTP calls are protected using configurable validation mechanisms.

This feature allows administrators to control outbound traffic using platform-level and tenant-level configurations.

---

## How It Works

When an outbound request is initiated:

1. The request URL is validated against platform-level configuration
2. If allowed, tenant-level validation is applied (if enabled)
3. The request proceeds only if all validations pass

---

## Configuration

### Platform-Level Configuration

Global outbound request validation is configured in `deployment.toml`.

This controls system-wide behavior and is enforced for all tenants.

### Tenant-Level Configuration

Tenant-specific validation rules can be configured using `tenant-conf.json`.

These rules provide additional restrictions but cannot override platform-level configurations.

---

## Configuration Precedence

- Platform-level configuration has higher priority
- Tenant-level configuration cannot override platform restrictions
- Tenant rules apply only if the request is allowed at platform level
- If platform-level configuration is not defined, platform validation is skipped

---

## Host Pattern Matching

Outbound request validation supports simple wildcard-based host matching.

| Pattern | Matches |
|--------|--------|
| `*.example.com` | sub.example.com |
| `api.*.com` | api.test.com |
| `*` | all hosts |

### Notes

- Matching is performed only against the hostname (not full URL)
- `*` is treated as a wildcard
- Regular expressions are not required
- Matching is case-insensitive

---

## Blocking Private Network Access

!!! note
    `block_private_network_access` is only applicable when `enabled = true` is set under `[apim.outbound_request_security]`. Additionally, this check is applied **after** the host is validated against `mode` and `exceptions` — a request must first pass that validation before the private network check is performed.

When enabled, outbound requests to private or internal IP ranges are blocked after DNS resolution.

This protects against access to internal infrastructure such as:

- `127.0.0.1` (localhost)
- `10.x.x.x`
- `172.16.x.x – 172.31.x.x`
- `192.168.x.x`
- `169.254.x.x` (link-local)

### Behavior

1. Hostname is resolved to an IP address
2. The resolved IP is checked against private ranges
3. Request is blocked if it matches

---

## Platform-Level Configuration Reference

Configure in `deployment.toml`:

```toml
[apim.outbound_request_security]
enabled = false
mode = "allow_all"
exceptions = []
block_private_network_access = false
```

| Parameter | Type | Default | Description                                                                                                         |
|-----------|------|---------|---------------------------------------------------------------------------------------------------------------------|
| `enabled` | boolean | `false` | Enables or disables outbound request validation                                                                     |
| `mode` | string | `allow_all` | `allow_all` permits all hosts except those in `exceptions`; `deny_all` blocks all hosts except those in `exceptions` |
| `exceptions` | array | `[]` | List of host patterns acting as a denylist (`allow_all`) or allowlist (`deny_all`) (e.g., `*.example.com`)          |
| `block_private_network_access` | boolean | `false` | Blocks access to private/internal IP ranges after DNS resolution. Only applicable when `enabled = true`; evaluated after `mode` and `exceptions` validation passes |

!!! note
    If this configuration block is not defined, platform-level validation is skipped entirely.

---

## Tenant-Level Configuration Reference

Configure in `tenant-conf.json`:

```json
{
  "OutboundRequestSecurity": {
    "EnableHostAllowlist": false,
    "HostAllowlistPatterns": ["*"]
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `EnableHostAllowlist` | boolean | `false` | Enables tenant-level host validation |
| `HostAllowlistPatterns` | array | `["*"]` | List of allowed host patterns; supports wildcard matching (e.g., `*.example.com`) |

!!! note
    Tenant-level validation is applied only after the request passes platform-level validation. Tenant configuration cannot override platform restrictions.

---

## Example Scenarios

### 1. Allow all except specific hosts

Configuration:

- Mode: `allow_all`
- Exceptions act as a denylist

Behavior:

- All outbound requests are allowed
- Requests to hosts in `exceptions` are blocked

---

### 2. Deny all except trusted hosts

Configuration:

- Mode: `deny_all`
- Exceptions act as an allowlist

Behavior:

- All outbound requests are blocked
- Only hosts in `exceptions` are allowed

---

### 3. Tenant-specific restrictions

Configuration:

- Tenant allowlist enabled

Behavior:

- Tenant can only access hosts matching allowlist patterns
- Applied only if platform allows the request

---

### 4. Blocking internal network access

Configuration:

- `block_private_network_access = true`

Behavior:

- Requests to internal/private IPs are blocked even if host matches allowlist

