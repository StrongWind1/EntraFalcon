
# Known Limitations

This document catalogs confirmed limitations from the README and code, additional limitations discovered through code analysis, and blind spots in the assessment coverage.

---

## Documented Limitations (from README)

### 1. M365 RBAC, Defender for Endpoint RBAC, Intune RBAC Are Not Assessed

EntraFalcon focuses on Entra ID (directory roles, Conditional Access, PIM) and Azure IAM (subscription-level RBAC). It does not assess:

- Microsoft 365 RBAC (Exchange Online, SharePoint, Teams roles)
- Microsoft Defender for Endpoint RBAC
- Intune RBAC

These role systems have their own privilege hierarchies and permission models that are not evaluated.

### 2. HTML Reports Lack XSS Protection

HTML reports render tenant-controlled data (display names, descriptions, UPNs, membership rules) without HTML entity encoding. An attacker who controls any display name in the tenant could inject JavaScript that executes when the report is opened in a browser. This is acknowledged in the README.

### 3. Cloud Platform Evolution May Cause Assessments to Become Outdated

Microsoft continuously updates Entra ID, Azure, and the Graph API. New features, permission changes, or API deprecations may cause EntraFalcon's checks to become outdated or incomplete. The assessment represents a point-in-time snapshot and should be re-evaluated periodically.

### 4. Tenant Complexity May Lead to Inaccurate Results

Complex tenant configurations with many overlapping Conditional Access policies, custom roles, and nested group hierarchies may produce results that require careful interpretation. The tool uses heuristics in some checks and may not fully model all interactions.

---

## Authentication Limitations

### BroCi and AuthCode Flows: Windows Only

The BroCi and AuthCode flows rely on spawning a browser window and capturing the OAuth redirect. This uses either:

- A local HTTP listener on `localhost:13824` (works on all platforms for AuthCode).
- An embedded Internet Explorer browser control (`System.Windows.Forms.WebBrowser`) for external redirect URLs (Windows-only, IE-based).
- The BroCi flow always uses external redirect URLs (`startups.portal.azure.com`, `brk-*` scheme), making it Windows-only when the `MiscUrl` auth mode is needed.

The tool checks for non-Windows compatibility at startup via `Test-NonWindowsAuthFlowCompatibility` and will refuse to run incompatible flows.

### DeviceCode Flow: Reduced Depth for CAP-004 and CAP-005

When using the DeviceCode authentication flow:

- **CAP-004** (device registration policy check) and **CAP-005** (authentication strength policies check) run with reduced depth because the device registration policy endpoint (`/policies/deviceRegistrationPolicy`) and authentication strength policy endpoints (`/identity/conditionalAccess/authenticationStrength/policies`) cannot be retrieved with the DeviceCode flow's token context.
- The Security Findings module sets the special data unavailability reason to "DeviceCode flow does not support these endpoints."
- There is no first-party client that supports the required scopes via DeviceCode for these specific endpoints.

### DeviceCode Flow: Often Blocked by Conditional Access

Organizations that implement CAP-001 (block device code flow) will prevent EntraFalcon from authenticating via DeviceCode. This creates a catch-22 where the tool cannot assess the tenant if the recommended security measure is in place.

### ManualCode: Requires Clipboard Access

The ManualCode authentication flow requires the user to manually copy an authorization code from the browser URL bar. This requires clipboard access and browser interaction.

### BroCiManualCode: Requires Browser Developer Tools

The BroCiManualCode flow requires the user to extract a token from the browser's developer tools, which is a manual and error-prone process.

### PIM for Groups Requires Separate Authentication

PIM for Groups enumeration requires a secondary authentication flow using a different client ID (`1b730954-1685-4b74-9bfd-dac224a7b894` for non-BroCi flows, `50aaa389-5a33-4f1a-91d7-2c45ecd8dac8` for BroCi). The user must authenticate a second time (unless using BroCi, where token refresh handles it). The `-SkipPimForGroups` flag can be used to skip this phase entirely.

---

## Scoring Limitations

### Risk Scores Not Comparable Across Object Types

Risk scores for users, groups, enterprise apps, managed identities, and app registrations use different impact/likelihood formulas and different weighting factors. A risk score of 500 for a user does not have the same meaning as 500 for an enterprise app. Cross-type risk comparisons should not be made.

### Azure Role Tier Categorization Does Not Account for Scope

Azure role tier categorization is based on role definition capabilities, without accounting for scope limitations. A "Reader" role assigned to a single virtual machine receives the same tier weight (Tier-2, +50 Impact) as "Reader" assigned to the entire subscription.

### Custom Entra/Azure Roles Default to Tier ? (Uncategorized)

Custom Entra ID roles and custom Azure roles whose IDs are not in the tier lookup tables (`$GLOBALEntraRoleRating`, `$GLOBALAzureRoleRating`) receive default tier weights (Entra: 80, Azure: 50). A custom role with powerful permissions may be under-categorized.

### Delegated API Permissions Scored Per-Category, Not Per-Permission

Delegated permissions are scored once per severity category (Dangerous: +200, High: +100, Medium: +60, Low: +20, Misc: +20). An enterprise app with 100 "High" delegated permissions receives the same Impact score as one with a single "High" delegated permission. This is asymmetric with Application permissions, which are scored per-permission.

### Managed Identity Likelihood Is Always 1

Managed Identity Likelihood is hardcoded at 1 (the base value). Since Likelihood never varies, the Likelihood column provides no useful differentiation. Risk always equals Impact for managed identities.

### Inactive Threshold Is Hardcoded at 180 Days

The inactivity threshold is hardcoded at 180 days throughout the codebase (`check_Users.psm1`, `check_EnterpriseApps.psm1`, `check_Tenant.psm1`). There is no configuration option to adjust this threshold. Organizations with different inactivity policies cannot customize this value without modifying the source code.

### Group Risk Uses Ceiling, Users Use Round

Groups compute Risk as `Ceiling(Impact * Likelihood)` while Users compute Risk as `Round(Impact * Likelihood)`. This minor inconsistency means the same mathematical product may produce slightly different Risk values depending on the object type.

---

## Data Completeness Limitations

### SignInActivity May Not Be Available

The tool attempts to retrieve user sign-in activity via the `signInActivity` property in the Beta `/users` endpoint. If this fails (e.g., due to missing Entra ID Premium license or insufficient permissions), it falls back to retrieving the user list without sign-in activity data. In this fallback path:

- `LastSignInDays` shows `?`
- `Inactive` shows `?`
- USR-005 (Inactive Users) cannot be evaluated

Enterprise App sign-in activity (`/reports/servicePrincipalSignInActivities`) has a similar fallback.

### Azure IAM: Management Group Assignments Require Resource Graph

Azure IAM enumeration retrieves subscription-level and below assignments via the Azure Resource Manager API. Management group-level assignments require Azure Resource Graph queries (`POST /providers/Microsoft.ResourceGraph/resources`), which are conditional on the user having Resource Graph access.

### LimitResults Only Limits Users and Groups

The `-LimitResults` parameter only limits the number of users and groups included in reports. It does not limit:

- Enterprise Apps
- Managed Identities
- App Registrations
- Conditional Access Policies
- PIM Role Settings

In large tenants with thousands of enterprise apps, the report may still be very large even with `-LimitResults` set.

### Named Location Quality Not Assessed

Conditional Access policies that reference Named Locations are checked for their presence and usage, but the quality of the Named Locations themselves is not assessed:

- IP ranges that are overly broad (e.g., /8 CIDR blocks) are not flagged.
- Named Locations based on country/region codes are not evaluated for accuracy.
- Stale Named Locations (IPs no longer in use) are not identified.

### Conditional Access: Only Checks for Specific Patterns

The CAP analysis checks for specific known patterns (e.g., "all users" coverage, MFA enforcement, device compliance, sign-in frequency). Novel or complex Conditional Access configurations may not be evaluated:

- Custom authentication contexts are not fully analyzed.
- Workload identity policies are checked at a high level but not deeply.
- Interactions between multiple overlapping policies are not modeled.
- Session controls beyond sign-in frequency and persistent browser are not assessed.

---

## API and Platform Limitations

### api.azrbac.mspim.azure.com Is Undocumented

When using the BroCi flow, PIM for Groups data is retrieved via the undocumented API: `https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources`. This API is not part of the official Microsoft Graph documentation and may change or be removed without notice. The non-BroCi flow uses the official Graph Beta endpoint `/privilegedAccess/aadGroups/resources` as a fallback.

### Graph Beta API Endpoints May Change

Several features rely on Microsoft Graph Beta API endpoints, which are not guaranteed to be stable:

- `/users` with `signInActivity` (Beta)
- `/reports/servicePrincipalSignInActivities` (Beta)
- `/policies/roleManagementPolicies` (Beta)
- `/policies/roleManagementPolicyAssignments` (Beta)
- `/privilegedAccess/aadGroups/resources` (Beta)
- `/identity/conditionalAccess/authenticationStrength/policies` (Beta)

### PIM for Groups via Graph Is in Beta

PIM for Groups APIs (`/privilegedAccess/aadGroups/*`) are in the Graph Beta namespace. Microsoft may change the API surface, response format, or deprecate these endpoints.

### First-Party App IDs Could Change

EntraFalcon uses pre-consented first-party application IDs for authentication:

- `1b730954-1685-4b74-9bfd-dac224a7b894` (Azure Active Directory PowerShell)
- `50aaa389-5a33-4f1a-91d7-2c45ecd8dac8` (Azure Portal)
- `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office)

Microsoft could modify the pre-consented scopes for these applications or retire them, which would break authentication flows.

### Large Tenants May Experience Slow Processing

In tenants with many app registrations or enterprise apps, the tool may take longer to process due to sequential API calls for resolving admin and ownership details. Caching mitigates repeated lookups, but the initial resolution can be slow.

---

## Nested Group Processing

Nested group processing uses an iterative depth-first search approach. While there is no hardcoded depth limit, deeply nested group hierarchies may:

- Result in a large number of batch API calls.
- Take significant processing time.
- Potentially hit API throttling limits in extreme cases.

The tool tracks visited groups to prevent infinite loops from circular group memberships.

---

## Scope-Limited Azure Roles Receive Same Tier Weight

An Azure role assignment scoped to a single resource (e.g., Reader on one virtual machine) receives the same tier weight as the same role assigned at the subscription level. This can cause:

- Over-estimation of risk for narrowly scoped assignments.
- Under-estimation when a seemingly low-tier role at subscription scope has broad impact.
