# Network Security Access Control

## Overview

Outbound host validation is a security mechanism that controls which external hosts WSO2 API Manager is permitted to connect to, preventing unintended or unauthorized outbound requests to internal or external systems.

In WSO2 API Manager, outbound requests such as endpoint validation, WSDL imports, remote OpenAPI/Swagger `$ref` resolution, and the gateway's XML schema-validation `xsdURL` fetch are protected using configurable validation mechanisms.

This feature allows administrators to control outbound traffic using platform-level and tenant-level configurations.

---

## How It Works

When an outbound request is initiated:

1. The request URL is validated against platform-level configuration
2. If allowed, tenant-level validation is applied (if enabled)
3. The request proceeds only if all validations pass

Platform-level validation is activated automatically when the `[apim.network_security.access_control]` configuration block is present in `deployment.toml`. If the block is absent, platform-level validation is skipped entirely.

---

## Validating Remote References in API Definitions

In addition to top-level user URLs (endpoint, WSDL, and Key Manager URLs), the same access control policy also governs **remote references inside OpenAPI and Swagger definitions**.

OpenAPI/Swagger documents can use `$ref` to point at other documents. When a definition is imported or validated, the server resolves these references — including references that are remote URLs, references nested transitively inside those remote documents, and references inside files bundled in an API archive (`.zip`). Without validation, an attacker could craft a definition whose `$ref` points at an internal or otherwise restricted host, causing the server to fetch it (an SSRF vector).

To close this gap, the server now validates **every** remote `$ref` URL — recursing through the full transitive closure of references — using the **same** `network_security.access_control` policy described on this page. The same `mode`, `hosts`, and `block_private_network_access` semantics, and the same platform (`deployment.toml`) and tenant (`tenant-conf.json`) configuration, apply to embedded references exactly as they do to top-level URLs.

!!! note
    No additional configuration is required. Remote reference validation is enabled automatically whenever the `[apim.network_security.access_control]` block (and/or the tenant-level `NetworkSecurityAccessControl` configuration) is present. The same policy that protects top-level URLs protects embedded references.

### Behavior

When a definition is imported or validated:

- Every remote `$ref` URL it contains is validated against the access control policy before any document is fetched.
- The server recurses through nested and transitive references, validating each remote URL it discovers.
- If **any** remote `$ref` points at a blocked destination — a private, loopback, link-local, or metadata address; a denied host; or a host that is not allow-listed in `allow` mode — the import or validation **fails** and the targeted document is never fetched.
- A blocked reference returns **HTTP 400** with the message: `The provided URL is not trusted. Please contact the system administrator.`
- A definition whose references are all clean (or that contains no remote references) validates and imports normally.

### Covered Flows

Remote reference validation applies to the following import-time and validation-time flows (the separate gateway request-time XML schema-validation path is covered in [Validating Gateway XML Schema URLs (xsdURL)](#validating-gateway-xml-schema-urls-xsdurl)):

| Flow | Endpoint / Operation |
|------|----------------------|
| Validate an OpenAPI definition | `POST /apis/validate-openapi` |
| Import an OpenAPI definition | `POST /apis/import-openapi` |
| Update an API's OpenAPI definition | `PUT /apis/{id}/swagger` |
| MCP server from OpenAPI | MCP `validate-openapi` / `generate-from-openapi` |
| API archive import | `.zip` / CTL (`apictl`) import |
| Service catalog import | Service definition import (content and URL) |

### Version Coverage

Validation of remote references is applied uniformly across **OpenAPI 3.1**, **OpenAPI 3.0**, and **Swagger 2.0** definitions, regardless of whether the definition is supplied inline, by URL, or inside an archive.

!!! note
    AsyncAPI definitions and the gateway's endpoint/backend request routing are outside the scope of this feature. The gateway XML schema-validation path (the `XMLSchemaValidator` mediator's `xsdURL` fetch) **is** covered by the same policy — see [Validating Gateway XML Schema URLs (xsdURL)](#validating-gateway-xml-schema-urls-xsdurl) below.

---

## Validating Gateway XML Schema URLs (xsdURL)

The Universal Gateway's XML schema-validation policy (the `XMLSchemaValidator` mediator, enabled through the XML Validator operation policy with `schemaValidation` set to `true` and an `xsdURL`) fetches the publisher-configured `xsdURL` at **request time**, in the data plane, for non-`GET` requests whose `Content-Type` is `application/xml` or `text/xml`. If `xsdURL` is empty, nothing is fetched and nothing is gated.

That schema fetch — together with any `xsd:import`, `xsd:include`, `xsd:redefine`, and external DTD references reached while compiling the fetched XSD — is governed by the **same** `network_security.access_control` policy described on this page. The same `mode`, `hosts`, and `block_private_network_access` semantics, and the same platform (`deployment.toml`) and tenant (`tenant-conf.json`) configuration apply: a host that is trusted for a `$ref` is trusted for an `xsdURL`. There is no separate XSD configuration.

!!! note
    No additional configuration is required. The gateway `xsdURL` fetch is governed automatically whenever the `[apim.network_security.access_control]` block (and/or the tenant-level `NetworkSecurityAccessControl` configuration) is present — the same policy that protects top-level URLs and embedded `$ref` references protects gateway schema URLs.

### Behavior

When the gateway validates a request against an XSD:

- The top-level `xsdURL` is validated against the access control policy **before** the gateway fetches it. Only `http` and `https` schemes are accepted — a `file:`, `jar:`, `ftp:`, or schemeless reference is rejected.
- Every nested `xsd:import`, `xsd:include`, `xsd:redefine`, and external DTD reached while compiling the schema is validated against the policy before it is fetched.
- If the `xsdURL` — or any reference inside it — points at a blocked destination (a private, loopback, link-local, or metadata address; a denied host; or a host that is not allow-listed in `allow` mode), the request is rejected with **HTTP 400** and the schema is never fetched.
- The request payload (the attacker-controlled body) is parsed with all external entity, DTD, and schema resolution disabled, so the payload itself can never trigger an outbound fetch.

A blocked top-level `xsdURL` returns **HTTP 400** with a message such as `The provided XSD URL is not trusted: <url>` (or `The provided XSD URL is not trusted (only HTTP/HTTPS is allowed): <url>` when a non-HTTP(S) scheme is used); a blocked reference inside the XSD returns `Blocked XSD reference not permitted by the network access-control policy: <url>`.

For details on configuring the XML schema-validation policy, see [XML Threat Protection for Universal Gateway]({{base_path}}/api-gateway/threat-protectors/xml-threat-protection-for-api-gateway/).

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
- If the platform-level configuration block is not present, platform validation is skipped

---

## Host Pattern Matching

Outbound request validation supports simple wildcard-based host matching.

| Pattern | Matches |
|--------|--------|
| `*.example.com` | sub.example.com |
| `api.*.com` | api.test.com |
| `*` | all hosts |

### Notes

- Matching is performed only against the hostname portion of the URL (not the full URL)
- `*` is treated as a wildcard
- Regular expressions are not required
- Matching is case-insensitive

### DNS Resolution During Validation

When the hostname in a request does not directly match any pattern in the `hosts` list, the hostname is resolved via DNS and the resulting IP addresses are also checked against the `hosts` list.

This means:

- `hosts = ["192.168.1.10"]` in `allow` mode — a request to `http://myserver.com/` that resolves to `192.168.1.10` **will be allowed**
- `hosts = ["mytestbackend.com"]` in `allow` mode — a request to `http://162.163.23.4/` **will be blocked** because the IP does not match the pattern

If DNS resolution fails at this stage, the request is **blocked**.

---

## Blocking Private Network Access

!!! note
    `block_private_network_access` is only applicable when the `[apim.network_security.access_control]` configuration block is present. In `allow` mode, this parameter has **no effect** — the hosts list is the sole authority for what is permitted and `block_private_network_access` is never evaluated. In `deny` mode, this check runs after host and resolved-IP list validation passes. When `mode` is absent, `block_private_network_access` is the only check applied.

When enabled, outbound requests to private or internal IP ranges are blocked after DNS resolution.

This protects against access to internal infrastructure such as:

- `127.0.0.1` / `::1` (loopback)
- `10.x.x.x`
- `172.16.x.x – 172.31.x.x`
- `192.168.x.x`
- `169.254.x.x` (link-local)
- `fc00::/7` (IPv6 unique local)
- Multicast addresses

### Behavior

1. Hostname is resolved to an IP address
2. The resolved IP is checked against private/reserved ranges
3. Request is blocked if it matches

If DNS resolution fails, the request is blocked.

---

## Platform-Level Configuration Reference

Configure in `deployment.toml`:

```toml
[apim.network_security.access_control]
mode = "allow"
hosts = ["api.github.com", "*.wso2.com"]
block_private_network_access = true
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | — | Determines the base filtering behavior. `allow`: only hosts whose hostname or resolved IP matches the `hosts` list are permitted; all others are blocked. `deny`: hosts whose hostname or resolved IP matches the `hosts` list are blocked; all others are allowed (subject to `block_private_network_access`). If absent or blank, the `hosts` list is ignored and only `block_private_network_access` is applied. |
| `hosts` | array | `[]` | List of host patterns matched against the hostname in the request URL. If the hostname does not match, DNS is resolved and the resulting IPs are also checked against this list. Supports wildcard matching (e.g., `*.example.com`). Behavior depends on `mode`. |
| `block_private_network_access` | boolean | `false` | When enabled, blocks requests whose resolved IP falls within a private or reserved network range. **Only evaluated in `deny` mode** (after host and resolved-IP list validation) and when `mode` is absent. Has no effect in `allow` mode. |

!!! note
    Validation is only active when the `[apim.network_security.access_control]` configuration block is explicitly added to `deployment.toml`. If the block is absent, platform-level validation is skipped entirely.

---

## Empty Hosts Behavior

### `allow` mode with empty `hosts`

```toml
[apim.network_security.access_control]
mode = "allow"
hosts = []
block_private_network_access = true
```

All outbound destinations are blocked. In `allow` mode, only explicitly listed hosts are permitted — an empty list means no host is allowed (fail-closed behavior).

### `deny` mode with empty `hosts`

```toml
[apim.network_security.access_control]
mode = "deny"
hosts = []
block_private_network_access = true
```

No explicit denylist is applied. Only the private network check is enforced.

---

## Tenant-Level Configuration Reference

Behaves the same as the Platform-Level Configuration. 

Configure in `tenant-conf.json`:

```json
{
  "NetworkSecurityAccessControl": {
    "Mode": "allow",
    "Hosts": ["api.github.com", "*.wso2.com"],
    "BlockPrivateNetworkAccess": true
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Mode` | string | — | Determines the base filtering behavior. `allow`: only hosts whose hostname or resolved IP matches the `hosts` list are permitted; all others are blocked. `deny`: hosts whose hostname or resolved IP matches the `hosts` list are blocked; all others are allowed (subject to `block_private_network_access`). If absent or blank, the `hosts` list is ignored and only `block_private_network_access` is applied. |
| `Hosts` | array | `[]` | List of host patterns matched against the hostname in the request URL. If the hostname does not match, DNS is resolved and the resulting IPs are also checked against this list. Supports wildcard matching (e.g., `*.example.com`). Behavior depends on `mode`. |
| `BlockPrivateNetworkAccess` | boolean | `false` | When enabled, blocks requests whose resolved IP falls within a private or reserved network range. **Only evaluated in `deny` mode** (after host and resolved-IP list validation) and when `mode` is absent. Has no effect in `allow` mode. |

!!! note
    Tenant-level validation is applied only after the request passes platform-level validation. Tenant configuration cannot override platform restrictions. The `NetworkSecurityAccessControl` key is **not present** in the default `tenant-conf.json` — tenant-level validation is disabled by default and activates only when the key is explicitly added by an admin.

---

## Example Scenarios

### 1. Allow only trusted external hosts

```toml
[apim.network_security.access_control]
mode = "allow"
hosts = ["api.github.com", "*.wso2.com", "localhost"]
block_private_network_access = true
```

Results:

| Request | Result |
|---------|--------|
| `https://api.github.com` | Allowed |
| `https://publisher.wso2.com` | Allowed |
| `http://localhost` | Allowed (`localhost` matches the hosts list directly; `block_private_network_access` is not evaluated in `allow` mode) |
| `http://127.0.0.1` | Blocked (not in hosts) |
| `http://192.168.1.10` | Blocked (not in hosts) |
| `https://example.com` | Blocked (not in hosts) |

---

### 2. Block specific hosts, allow everything else

```toml
[apim.network_security.access_control]
mode = "deny"
hosts = ["localhost", "*.internal"]
block_private_network_access = true
```

Results:

| Request | Result |
|---------|--------|
| `http://localhost` | Blocked (denylist match) |
| `http://service.internal` | Blocked (denylist match) |
| `http://127.0.0.1` | Blocked (private network) |
| `http://192.168.1.10` | Blocked (private network) |
| `https://api.github.com` | Allowed |

---

### 3. Tenant-specific restrictions

```json
{
  "NetworkSecurityAccessControl": {
    "Mode": "allow",
    "Hosts": ["*.example.com"],
    "BlockPrivateNetworkAccess": true
  }
}
```

Behavior:

- Tenant can only access hosts matching `*.example.com`
- Applied only after the platform-level check allows the request

---

### 4. Deny mode with no denylist (private network protection only)

```toml
[apim.network_security.access_control]
mode = "deny"
hosts = []
block_private_network_access = true
```

Results:

| Request | Result |
|---------|--------|
| `http://127.0.0.1` | Blocked (private network) |
| `http://192.168.1.10` | Blocked (private network) |
| `https://api.github.com` | Allowed |
