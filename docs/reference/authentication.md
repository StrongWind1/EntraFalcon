# Authentication

EntraFalcon supports six authentication flows to obtain access tokens for the Microsoft Graph API, Azure Resource Manager API, and PIM APIs. This document describes the internal architecture, token lifecycle, and security characteristics of each flow.

## Architecture Overview

The central authentication orchestrator is `invoke-EntraFalconAuth` in `modules/shared_Functions.psm1`. Depending on the selected flow, it dispatches to one of the following functions from the vendored EntraTokenAid module:

- `Invoke-Auth` -- interactive authorization code and BroCi flows
- `Invoke-DeviceCodeFlow` -- device code flow
- `Invoke-Refresh` -- silent token refresh and broker-based token exchange

## Token Storage

All tokens are stored in PowerShell global variables. Each variable holds an object with `.access_token`, `.refresh_token`, and `.Expiration_time` properties. Token expiration is checked with a **30-minute buffer** -- if a token will expire within 30 minutes, it is proactively refreshed before the next API call.

| Global Variable | Purpose |
|----------------|---------|
| `$GLOBALMsGraphAccessToken` | Main Microsoft Graph token |
| `$GLOBALArmAccessToken` | Azure Resource Manager token |
| `$GLOBALPIMsGraphAccessToken` | PIM for Entra Roles token |
| `$GLOBALPimForGroupAccessToken` | PIM for Groups (Graph API) token |
| `$GLOBALPimForGroupAzrbacAccessToken` | PIM for Groups (azrbac API) token |
| `$GLOBALBrociAccessToken` | BroCi bootstrap token |
| `$GLOBALSecurityFindingsGraphAccessTokenSpecial` | Security Findings special token |

## Continuous Access Evaluation (CAE)

CAE is **requested by default** via the OAuth2 claims parameter. CAE-enabled tokens have an extended lifetime of approximately **24 hours**, compared to roughly 1 hour for standard tokens.

To disable CAE (for example, if it causes issues with specific Conditional Access configurations):

```powershell
.\run_EntraFalcon.ps1 -DisableCAE
```

---

## Non-BroCi Flows

The non-BroCi flows (`AuthCode`, `DeviceCode`, `ManualCode`) obtain tokens directly from the Microsoft identity platform using well-known first-party client application IDs. Each purpose requires a separate interactive login (3-4 prompts total).

### Token Acquisition Matrix

| Purpose | Client ID | Client Name | Resource | Interactive? | Notes |
|---------|-----------|-------------|----------|-------------|-------|
| Main Graph | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure CLI | `graph.microsoft.com` | Yes | Primary token for all Graph API calls |
| PIM for Groups | `1b730954-1685-4b74-9bfd-dac224a7b894` | Azure PowerShell | `graph.microsoft.com` | Yes | Redirect: `https://login.microsoftonline.com/common/oauth2/nativeclient` |
| PIM for Entra Roles | `51f81489-12ee-4a9e-aaae-a2591f45987d` | Managed Meeting Rooms | `graph.microsoft.com` | Yes | Redirect: `http://localhost:13824/` |
| Azure ARM | _(refresh from Main Graph RT)_ | _(same as Main Graph)_ | `management.azure.com` | **No** | Uses refresh token exchange from the Main Graph refresh token |
| Security Findings | `80ccca67-54bd-44ab-8625-4b79c4dc7775` | Security Portal | `graph.microsoft.com` | Yes | Redirect: `https://transition.security.microsoft.com/Blank`, Origin: `https://doesnotmatter` |

### DeviceCode Flow Limitation

The DeviceCode flow **cannot authenticate for Security Findings**. When using DeviceCode, the Security Findings checks CAP-004 and CAP-005 run with reduced depth, producing less detailed results.

---

## BroCi Flows

The BroCi flows (`BroCi`, `BroCiManualCode`, `BroCiToken`) use a **broker-based token exchange pattern** that requires only a single interactive login to obtain all necessary tokens.

### How BroCi Works

1. **Initial authentication** against the Azure Portal client:
   - Client ID: `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` (Azure Portal)
   - Redirect URI: `https://startups.portal.azure.com/auth/login/`

2. **Token exchange** via `Invoke-Refresh` with the `BrkClientId` parameter. The bootstrap refresh token is exchanged for purpose-specific tokens using different client IDs:

### BroCi Token Exchange Matrix

| Purpose | Exchange Client ID | BrkClientId | Redirect URI | Origin |
|---------|-------------------|-------------|-------------|--------|
| Main Graph | `74658136-14ec-4630-ad9b-26e160ff0fc6` | `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | `brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com` | `https://portal.azure.com` |
| PIM for Groups | `50aaa389-5a33-4f1a-91d7-2c45ecd8dac8` | `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | `brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com` | `https://portal.azure.com` |
| Azure ARM | `74658136-14ec-4630-ad9b-26e160ff0fc6` | `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | `brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com` | `https://portal.azure.com` |
| PIM for Entra Roles | `74658136-14ec-4630-ad9b-26e160ff0fc6` | `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | `brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com` | `https://portal.azure.com` |

### PIM for Groups via azrbac API

In BroCi flows, PIM for Groups additionally queries the `api.azrbac.mspim.azure.com` endpoint using resource ID `01fc33a7-78ba-4d2f-a4b7-768e336e890e`. This is stored in the `$GLOBALPimForGroupAzrbacAccessToken` variable.

### BroCi Advantage

BroCi requires **only 1 interactive login** compared to 3-4 interactive prompts for the non-BroCi flows. This makes it the preferred flow for most assessments on Windows.

---

## Flow Comparison and Security Implications

### AuthCode

- **Platform:** Windows only
- **Mechanism:** Opens a localhost HTTP listener to receive the authorization code callback
- **Security:** PKCE (Proof Key for Code Exchange) is enabled by default, mitigating authorization code interception attacks
- **Interactive prompts:** 3-4 (one per purpose-specific client)

### DeviceCode

- **Platform:** Windows, Linux, macOS
- **Mechanism:** Displays a device code the user enters at `https://microsoft.com/devicelogin`
- **Security:** Inherently phishable -- an attacker could present the device code to a victim. Often blocked by Conditional Access policies for this reason
- **Limitation:** Cannot obtain Security Findings tokens; CAP-004 and CAP-005 run with reduced depth
- **Interactive prompts:** 3 (Security Findings skipped)

### ManualCode

- **Platform:** Windows, Linux, macOS
- **Mechanism:** Generates authorization URLs the user must open manually in a browser, then paste the resulting authorization code back into the terminal
- **Security:** Requires clipboard access; user manually handles URLs and codes
- **Interactive prompts:** 3-4

### BroCi

- **Platform:** Windows only
- **Mechanism:** Uses an embedded browser or localhost listener with the Azure Portal client to authenticate, then exchanges the bootstrap token for all purpose-specific tokens
- **Security:** Leverages first-party Microsoft application IDs, which bypass admin consent requirements. Single sign-on reduces exposure surface
- **Interactive prompts:** 1

### BroCiManualCode

- **Platform:** Windows, Linux, macOS
- **Mechanism:** Same broker-based exchange as BroCi, but the initial authentication is performed manually by extracting token data from browser developer tools
- **Security:** Requires access to browser developer tools to capture the authentication response
- **Interactive prompts:** 1 (manual extraction)

### BroCiToken

- **Platform:** Windows, Linux, macOS
- **Mechanism:** Accepts a pre-obtained refresh token for the Azure Portal client (`c44b4083-3bb0-49c1-b47d-974e53cbdf3c`) and performs the broker-based token exchange non-interactively
- **Security:** The refresh token must be treated as sensitive secret material. No interactive login is required
- **Interactive prompts:** 0

---

## Flow Selection Guide

| Scenario | Recommended Flow |
|----------|-----------------|
| Windows workstation, standard assessment | `BroCi` (default) |
| Linux or macOS host | `DeviceCode` |
| Automated / CI pipeline | `BroCiToken` (supply `-BroCiToken` with a valid refresh token) |
| DeviceCode blocked by CA policies | `ManualCode` or `BroCiManualCode` |
| Full Security Findings coverage required | Any flow except `DeviceCode` |
| Minimize interactive prompts | `BroCi`, `BroCiManualCode`, or `BroCiToken` |
