
# EntraFalcon Technical Documentation

## Overview

EntraFalcon is a PowerShell-based security assessment tool for Microsoft Entra ID (formerly Azure AD) environments, developed by Compass Security Switzerland AG. It evaluates the security posture of an Entra ID tenant by enumerating objects, analyzing configurations, scoring risk, and generating interactive HTML reports.

**Version analyzed**: V20260316
**License**: MIT
**Author**: Christian Feuchter, Compass Security Switzerland AG
**Repository**: [github.com/CompassSecurity/EntraFalcon](https://github.com/CompassSecurity/EntraFalcon)

## Purpose

EntraFalcon automates the enumeration and security analysis of Microsoft Entra ID tenants. It identifies:

- Privileged objects (users, groups, applications) with excessive permissions
- Conditional Access Policy misconfigurations and gaps
- PIM (Privileged Identity Management) configuration weaknesses
- Enterprise applications with dangerous API permissions
- Unprotected privileged accounts (no MFA, no role-assignable groups)
- Hybrid identity risks (on-premises synced accounts with cloud privileges)
- Inactive accounts and stale credentials

## Architecture Summary

EntraFalcon is a single-script entry point (`run_EntraFalcon.ps1`) that orchestrates 14 PowerShell modules:

| Module | Purpose |
|--------|---------|
| `EntraTokenAid.psm1` | OAuth authentication (vendored fork) |
| `Send-ApiRequest.psm1` | Generic HTTP API client with retry (vendored) |
| `Send-GraphRequest.psm1` | Microsoft Graph API client (vendored) |
| `Send-GraphBatchRequest.psm1` | Graph Batch API client (vendored) |
| `shared_Functions.psm1` | Shared scoring, HTML/JS/CSS, auth orchestration, helpers |
| `check_Groups.psm1` | Group enumeration and scoring |
| `check_Users.psm1` | User enumeration and scoring |
| `check_EnterpriseApps.psm1` | Enterprise Application enumeration and scoring |
| `check_AppRegistrations.psm1` | App Registration enumeration and scoring |
| `check_ManagedIdentities.psm1` | Managed Identity enumeration and scoring |
| `check_Roles.psm1` | Role assignment report generation |
| `check_CAPs.psm1` | Conditional Access Policy analysis |
| `check_PIM.psm1` | PIM settings analysis |
| `check_Tenant.psm1` | Security Findings engine (63 checks) |
| `export_Summary.psm1` | Summary report with charts |

## Execution Flow

1. **Authentication** — Obtains tokens for Microsoft Graph and optionally Azure ARM
2. **Pre-collection** — PIM for Groups assignments (requires separate auth)
3. **Data gathering** — Tenant info, licenses, admin units, CAPs, role assignments, Azure IAM, MFA status, devices, users
4. **Enumeration** — 10-step sequential enumeration: Groups → Enterprise Apps → Managed Identities → App Registrations → Users → Roles → CAPs → PIM Settings → Security Findings → Summary
5. **Reporting** — HTML, TXT, and optionally CSV reports per module

## Supported Platforms

| Platform | Supported | Notes |
|----------|-----------|-------|
| Windows + PowerShell 5.1 | Yes | Full support including BroCi and AuthCode flows |
| Windows + PowerShell 7 | Yes | Full support |
| Linux + PowerShell 7 | Partial | Only DeviceCode, ManualCode, BroCiManualCode, BroCiToken flows |
| macOS + PowerShell 7 | Partial | Same as Linux |

## Important Warnings

- **XSS Risk**: Generated HTML reports do not implement XSS protection. Tenant data (display names, descriptions) is rendered without sanitization. Reports should be treated as potentially containing malicious content from the assessed tenant.
- **Not Stealthy**: The tool generates significant Graph API traffic and sign-in events that are detectable.
- **Point-in-Time**: Results reflect tenant state at execution time. Cloud environments evolve rapidly.
- **Scoring is Approximate**: Risk scores are for prioritization only, not comparable across object types.
- **Global Reader Required**: A minimum of Global Reader role is mandatory.

## Documentation Pages

**Getting Started**

- [Installation & Requirements](getting-started/installation.md)
- [Usage Guide](getting-started/usage.md)

**Reference**

- [Authentication Flows](reference/authentication.md)
- [Architecture](reference/architecture.md)
- [Dependencies](reference/dependencies.md)
- [Network & Detection](reference/network-and-detection.md)
- [Limitations](reference/limitations.md)

**Assessment**

- [Checks and Findings](assessment/checks-and-findings.md)
- [Scoring System](assessment/scoring-system.md)
- [Scoring Glossary](assessment/scoring-glossary.md)
