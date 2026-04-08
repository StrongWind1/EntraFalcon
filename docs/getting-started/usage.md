# Usage Guide

## Running EntraFalcon

```powershell
.\run_EntraFalcon.ps1 [parameters]
```

EntraFalcon is invoked directly as a PowerShell script. No prior installation step is required.

!!! note "Execution Policy"
    You may need to set the execution policy for the current process:
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
    ```

---

## Parameters

EntraFalcon accepts 13 parameters. All are optional; the script runs with sensible defaults when no parameters are specified.

### Authentication Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-AuthFlow` | String | `BroCi` | Authentication flow selector. See [Authentication Flows](../reference/authentication.md) for details. |
| `-BroCiToken` | String | _(none)_ | Pre-obtained Azure Portal refresh token. Required with `-AuthFlow BroCiToken`. |
| `-Tenant` | String | `organizations` | Target tenant ID or domain. Useful when assessing a tenant other than the account's home tenant. |
| `-DisableCAE` | Switch | `$false` | Disables Continuous Access Evaluation. CAE tokens last ~24 hours; standard tokens last ~1 hour. |

**`-AuthFlow` valid values** (from `ValidateSet` at `run_EntraFalcon.ps1:80`):

| Value | Platform | Interactive Logins | Notes |
|-------|----------|-------------------|-------|
| `BroCi` | Windows only | 1 | Default. Uses Azure Portal broker for single sign-on. |
| `AuthCode` | Windows only | 4 | Standard OAuth auth code flow via localhost listener. |
| `DeviceCode` | Windows, Linux, macOS | 3 | Authentication on another device. CAP-004 and CAP-005 run with reduced depth. |
| `ManualCode` | Windows, Linux, macOS | 4 | Auth URL copied to clipboard; user pastes redirect URL back. |
| `BroCiManualCode` | Windows, Linux, macOS | 1 | BroCi auth via browser dev tools (user extracts code from network log). |
| `BroCiToken` | Windows, Linux, macOS | 0 | Non-interactive. Requires a valid refresh token for client `c44b4083-3bb0-49c1-b47d-974e53cbdf3c`. |

!!! warning "Platform restrictions"
    On non-Windows platforms, `BroCi` and `AuthCode` are not available. The script checks OS compatibility at startup (`run_EntraFalcon.ps1:152`) and exits with a message listing alternatives if an incompatible flow is selected.

**`-BroCiToken` validation** (from `run_EntraFalcon.ps1:143-171`):

- Cannot be used without `-AuthFlow BroCiToken` (error if both conditions mismatch)
- Must be a refresh token, not an access token — tokens starting with `ey` (JWT header) are rejected
- Must start with `1.` (Azure refresh token format)
- This value is visible in the process list and shell history — treat as a secret

**`-Tenant` behavior** (from `run_EntraFalcon.ps1:183-185`):

- If omitted or empty, the underlying EntraTokenAid module defaults to `organizations`, which resolves to the user's home tenant
- Accepts a tenant ID (GUID) or a verified domain name (e.g., `contoso.onmicrosoft.com`)
- Passed to all authentication flows via `$GLOBALAuthParameters`

**`-DisableCAE` behavior** (from `run_EntraFalcon.ps1:180-182`):

- When set, the `claims` parameter requesting CAE (`xms_cc: CP1`) is omitted from token requests
- This results in shorter-lived access tokens (~1 hour vs ~24 hours)
- Useful when Conditional Access policies interfere with CAE tokens

### Enumeration Control Parameters

| Parameter | Type | Default | Validation | Description |
|-----------|------|---------|------------|-------------|
| `-SkipPimForGroups` | Switch | `$false` | — | Skips PIM for Groups enumeration entirely. |
| `-IncludeMsApps` | Switch | `$false` | — | Includes Microsoft-owned enterprise applications. |
| `-LimitResults` | Int | _(unlimited)_ | — | Limits users and groups in the report after risk sorting. |
| `-ApiTop` | Int | `999` | `ValidateRange(5, 999)` | Graph API page size (objects per response). |

**`-SkipPimForGroups` behavior** (from `run_EntraFalcon.ps1:219-225`):

- When set, the PIM for Groups pre-collection phase is skipped entirely
- This avoids the secondary authentication required to retrieve PIM for Groups data (using client `1b730954` in non-BroCi flows or `50aaa389` in BroCi flows)
- PIM for Groups checks (eligible member/owner of privileged group, unprotected group nesting) will not appear in reports
- `$GLOBALPimForGroupsChecked` is set to `$false`

**`-IncludeMsApps` behavior** (from `run_EntraFalcon.ps1:189-191` and `run_EntraFalcon.ps1:334`):

- Passed to `Invoke-CheckEnterpriseApps` and `Get-TenantReportAvailability`
- When not set, service principals from these Microsoft tenant IDs are excluded from the Enterprise Apps report:
    - `f8cdef31-a31e-4b4a-93e4-5f571e91255a` (Microsoft Services)
    - `72f988bf-86f1-41af-91ab-2d7cd011db47` (Microsoft Corp)
    - `33e01921-4d64-4f8c-a055-5bdaffd5e33d` (Microsoft infrastructure)
    - `cdc5aeea-15c5-4db6-b079-fcadd2505dc2` (Microsoft infrastructure)
- Does **not** affect Managed Identities, App Registrations, Users, Groups, or Role Assignment reports

**`-LimitResults` behavior** (from `run_EntraFalcon.ps1:193-196`):

- Passed to both `Invoke-CheckGroups` and `Invoke-CheckUsers` via `@optionalParamsUserandGroup`
- The limit is applied **after** data collection and risk scoring — all objects are still fetched from the API and scored, but only the top N (by Risk descending) are included in the final report
- Does **not** limit Enterprise Apps, App Registrations, Managed Identities, Conditional Access Policies, Role Assignments, PIM Settings, or Security Findings
- Useful for large tenants where generating full HTML reports for tens of thousands of users/groups is impractical

**`-ApiTop` behavior** (from `run_EntraFalcon.ps1:108-110`):

- Controls the `$top` OData query parameter sent to Microsoft Graph API
- Lower values mean more HTTP requests but smaller payloads per request, reducing HTTP 504 timeout risk
- The Microsoft Graph API default is 100; EntraFalcon sets 999 for fewer round-trips
- Passed to: `Get-Devices` (line 313), `Get-UsersBasic` (line 316), `Invoke-CheckGroups` (line 362), `Invoke-CheckEnterpriseApps` (line 365), `Invoke-CheckManagedIdentities` (line 368), `Invoke-CheckUsers` (line 374)

### Output Parameters

| Parameter | Type | Default | Validation | Description |
|-----------|------|---------|------------|-------------|
| `-OutputFolder` | String | `Results_<TenantName>_<YYYYMMDD_HHMM>` | — | Custom output folder path. |
| `-Csv` | Switch | `$false` | — | Enables CSV report generation alongside HTML and TXT. |
| `-LogLevel` | String | `Off` | `ValidateSet("Off", "Verbose", "Debug", "Trace")` | Runtime logging verbosity. |
| `-UserAgent` | String | `EntraFalcon` | — | User-Agent HTTP header for all API requests. |
| `-QAMode` | Switch | `$false` | — | Dumps `AllGroups` and `AllUsers` objects as JSON for QA testing. |

**`-OutputFolder` behavior** (from `run_EntraFalcon.ps1:241-254`):

- If not specified, generated as `Results_<TenantDisplayName>_<YYYYMMDD_HHMM>` using the tenant's display name and the start timestamp
- The folder is created if it does not exist
- If folder creation fails (e.g., invalid path, permissions), the script aborts with an error
- All report files (HTML, TXT, CSV) are written into this folder

!!! warning "Tenant display name in path"
    The default output folder includes the tenant's display name, which could contain special characters. If the display name contains characters invalid for file paths on your OS, use `-OutputFolder` to specify a safe path.

**`-Csv` behavior** (from `run_EntraFalcon.ps1:201-204`):

- Passed to Groups, Enterprise Apps, Managed Identities, App Registrations, Users, Roles, CAPs, and PIM modules via `@optionalParamsOutput`
- CSV files contain the same columns as the HTML main table for each report
- Not applied to the Security Findings report or the Summary report (these have different output formats)

**`-LogLevel` behavior** (from `run_EntraFalcon.ps1:84-85` and `run_EntraFalcon.ps1:177`):

- Stored in `$GLOBALEntraFalconLogLevel` and checked by the `Write-Log` function throughout all modules
- Levels are cumulative: `Trace` includes `Debug` includes `Verbose`
- `Off` (default): No additional output beyond the standard progress banners
- `Verbose`: High-level status messages (e.g., auth flow selection, token acquisition)
- `Debug`: Includes Verbose plus API call details, object counts, and processing decisions
- `Trace`: Includes Debug plus very detailed output (individual object processing, batch request details) — can be very noisy

**`-UserAgent` behavior** (from `run_EntraFalcon.ps1:179`):

- Set as `$GLOBALAuthParameters['UserAgent']` and passed to all API request functions
- Applied to: all `Send-GraphRequest` calls, all `Send-GraphBatchRequest` calls, all `Send-ApiRequest` calls, and all `Invoke-Refresh` / `Invoke-Auth` token endpoint calls
- Interactive sign-ins (browser-based) use the browser's own User-Agent, not this value
- Default `EntraFalcon` is easily detectable in sign-in logs and API audit logs
- Set to a generic browser string (e.g., `"Mozilla/5.0"`) to blend in, though application IDs in sign-in logs cannot be spoofed

**`-QAMode` behavior** (from `run_EntraFalcon.ps1:197-199`):

- Passed to `Invoke-CheckGroups` and `Invoke-CheckUsers` via `@optionalParamsUserandGroup`
- When enabled, writes the full `AllGroups` and `AllUsers` internal PowerShell objects as JSON files in the output folder
- Intended for development and regression testing — not useful for normal assessments
- JSON output contains the complete internal data model including all computed scores, warnings, and details

---

## Execution Flow

EntraFalcon runs a fixed 10-step enumeration pipeline. Understanding this helps interpret progress output and troubleshoot issues.

| Step | Phase | What Happens |
|------|-------|-------------|
| Pre | Main Authentication | Authenticates to Microsoft Graph. Requires interactive login (except BroCiToken). |
| Pre | PIM for Groups | Collects PIM for Groups eligible assignments. Requires a separate authentication unless using BroCi or `-SkipPimForGroups`. |
| Pre | Basic Data | Retrieves tenant info, licenses, admin units, CAPs, PIM role assignments, Azure IAM (if subscriptions accessible), MFA status, devices, basic user list. |
| 1/10 | Groups | Enumerates all groups, members, owners, roles, CAPs, nested groups. Scores and produces report. |
| 2/10 | Enterprise Apps | Enumerates all service principals (Application type), permissions, roles, owners. Scores and produces report. |
| 3/10 | Managed Identities | Enumerates all managed identity service principals, permissions, roles. Scores and produces report. |
| 4/10 | App Registrations | Enumerates all application registrations, credentials, owners, admins. Scores using Enterprise App Impact. Produces report. |
| 5/10 | Users | Enumerates all users, memberships, ownerships, roles, MFA status. Scores using inherited group/app data. Produces report. |
| 6/10 | Role Assignments | Generates Entra ID and Azure IAM role assignment reports from collected data. |
| 7/10 | CAPs | Analyzes Conditional Access Policies for misconfigurations and coverage gaps. Produces report. |
| 8/10 | PIM Settings | Analyzes PIM role configuration (activation, assignment, notification settings). Skipped if tenant lacks P2 license. Produces report. |
| 9/10 | Security Findings | Runs 63 security checks across all collected data. Produces the Security Findings report with severity ratings and remediation guidance. |
| 10/10 | Summary | Aggregates statistics and generates the Enumeration Summary report with charts. |

!!! info "Conditional steps"
    - **PIM for Groups** is skipped if `-SkipPimForGroups` is set
    - **Azure IAM** is skipped if ARM authentication fails or no subscriptions are accessible
    - **PIM Settings** (step 8) is skipped if the tenant lacks an Entra ID P2 or Governance license
    - **Security Findings** steps CAP-004 and CAP-005 run with reduced depth when `-AuthFlow DeviceCode` is used (device registration policy and authentication strength policies cannot be retrieved)

---

## Output Structure

EntraFalcon creates an output folder containing the assessment results. The default folder name follows the pattern:

```
Results_<TenantDisplayName>_<YYYYMMDD_HHMM>/
```

### Report Files

Each module produces report files with a consistent naming convention:

```
<ReportName>_<TenantDisplayName>_<YYYYMMDD_HHMM>.html
<ReportName>_<TenantDisplayName>_<YYYYMMDD_HHMM>.txt
<ReportName>_<TenantDisplayName>_<YYYYMMDD_HHMM>.csv   (only with -Csv)
```

| Report Name | Source Module | Always Generated? |
|-------------|-------------|-------------------|
| Groups | `check_Groups.psm1` | Only if groups exist in tenant |
| Enterprise Apps | `check_EnterpriseApps.psm1` | Yes |
| Managed Identities | `check_ManagedIdentities.psm1` | Only if managed identities exist |
| App Registrations | `check_AppRegistrations.psm1` | Only if app registrations exist |
| Users | `check_Users.psm1` | Yes |
| Entra Role Assignments | `check_Roles.psm1` | Yes |
| Azure Role Assignments | `check_Roles.psm1` | Only if Azure IAM is accessible |
| Conditional Access Policies | `check_CAPs.psm1` | Only if CAPs exist |
| PIM Settings | `check_PIM.psm1` | Only if tenant has P2 license and PIM assignments exist |
| Security Findings | `check_Tenant.psm1` | Yes |
| Enumeration Summary | `export_Summary.psm1` | Yes (prefixed with `_`) |

### Output Formats

- **HTML** — Interactive reports with filtering, sorting, column toggling, export, and cross-navigation. Always generated.
- **TXT** — Plain-text summaries with tabular data. Always generated.
- **CSV** — Tabular data matching the HTML main table columns. Generated only when `-Csv` is specified. Not produced for Security Findings or Summary reports.

---

## Common Workflows

### Basic Assessment (Windows)

Uses the default BroCi flow with a single interactive login:

```powershell
.\run_EntraFalcon.ps1
```

### Assessment from Linux or macOS

DeviceCode is the most convenient cross-platform flow:

```powershell
.\run_EntraFalcon.ps1 -AuthFlow DeviceCode
```

!!! note
    DeviceCode is often blocked by Conditional Access in hardened environments. If blocked, use `-AuthFlow ManualCode` or `-AuthFlow BroCiManualCode` instead.

### Assessment of a Guest Tenant

When your account is a guest in another tenant:

```powershell
.\run_EntraFalcon.ps1 -Tenant "target-tenant-id-or-domain"
```

### Large Tenant

Limit the number of users and groups in the report and reduce the API page size to avoid timeouts:

```powershell
.\run_EntraFalcon.ps1 -LimitResults 5000 -ApiTop 500
```

### Include Microsoft-Owned Applications

By default, Microsoft-owned enterprise apps are excluded. To include them:

```powershell
.\run_EntraFalcon.ps1 -IncludeMsApps
```

### Skip PIM for Groups

Avoid the extra authentication step for PIM for Groups:

```powershell
.\run_EntraFalcon.ps1 -SkipPimForGroups
```

### Reduced Detection Footprint

Use a generic User-Agent string and disable CAE to reduce the token lifetime and avoid the `EntraFalcon` string in API logs:

```powershell
.\run_EntraFalcon.ps1 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -DisableCAE
```

!!! warning
    The application IDs used in sign-in logs **cannot** be changed and remain detectable regardless of User-Agent.

### Non-Interactive with Pre-Obtained Token

Supply a BroCi refresh token for zero-interaction execution:

```powershell
.\run_EntraFalcon.ps1 -AuthFlow BroCiToken -BroCiToken "1.XXXXXXXXXXX"
```

### Full Output with CSV and Verbose Logging

```powershell
.\run_EntraFalcon.ps1 -Csv -LogLevel Verbose
```

### Debug Troubleshooting

```powershell
.\run_EntraFalcon.ps1 -LogLevel Debug
```

---

## HTML Report Features

The interactive HTML reports provide several features for navigating and analyzing assessment results.

### Filtering

Each column in the report tables supports filtering. Type a filter value in the input below any column header.

| Operator | Syntax | Example | Description |
|----------|--------|---------|-------------|
| Contains | `value` | `admin` | Default. Matches rows containing "admin" anywhere in the column. |
| Exact match | `=value` | `=True` | Matches rows where the column value is exactly "True". |
| Starts with | `^value` | `^Service` | Matches rows where the column value starts with "Service". |
| Ends with | `$value` | `$@contoso.com` | Matches rows where the column value ends with "@contoso.com". |
| Greater than | `>value` | `>5` | Numeric comparison (also `>=`). |
| Less than | `<value` | `<10` | Numeric comparison (also `<=`). |
| Negation | `!value` | `!disabled` | Excludes rows containing "disabled". Works with other operators: `!=`, `!^`, `!$`. |
| OR (same column) | `val1\|\|val2` | `Admin\|\|Guest` | Matches rows containing either value in the same column. |
| OR (cross-column) | `or_value` | `or_>1` | Matches if **any** column with an `or_` prefix matches. Also supports `group1_`, `group2_`, etc. |
| Empty | `=empty` | `=empty` | Matches empty cells. `!=empty` matches non-empty cells. |

!!! tip "Filter by Object ID"
    The **DisplayName** column also includes the object's ID (invisible), so filtering by ID is possible.

### URL-Based Controls (GET Parameters)

Reports can be controlled via URL query parameters, enabling shareable filtered views:

| Parameter | Example | Description |
|-----------|---------|-------------|
| Field filters | `?EntraRoles=>1&Enabled=true` | Apply filters using column names as keys |
| Cross-column OR | `?or_EntraRoles=>0&or_GrpMem=>0` | OR logic across columns |
| Column selection | `?columns=DisplayName,Owner` | Show only specified columns |
| Sorting | `?sort=Impact&sortDir=desc` | Sort by column with direction |
| Object anchor | `#<ObjectID>` | Jump to a specific object's details section |

### Sorting

Click any column header to sort. Click again to reverse. The current sort state is preserved in Share View links.

### Column Toggling

Click the **Columns** button to show or hide specific columns. Some columns are hidden by default (e.g., `DeviceReg`, `DeviceOwn`, `LicenseStatus`, `OwnersSynced`, `CreatedDays`, `LastSignInDays`, delegated API permission columns).

### CSV Export

Click **Export CSV** to download the currently visible (filtered and sorted) data as a CSV file.

### Share View

Click **Share View** to copy a URL that encodes the current filter, sort, and column selection state. Share these links with colleagues to point them to a specific view.

### Preset Views

Click **Preset Views** to apply predefined filter/column/sort combinations. Available presets vary by report:

- **Users**: Tier-0 Users, Users with Roles, Inactive Users, Users Without MFA, Privileged Unprotected Users, New Users, Agent Users, Guest Users, Users Owning Applications, Users Disabled Per-User MFA, Entra Connect Accounts
- **Groups**: Tier-0 Groups, Public M365 Groups, Dynamic Groups, Privileged Unprotected Groups, Groups Used in CAPs, Groups Owned by Guests, PIM Groups, PIM for Groups PrivEsc, Interesting Groups by Keywords
- **Enterprise Apps**: Foreign/Internal Privileged Apps, Apps with Extensive API Privs (Application/Delegated), Apps with Roles, Apps with Credentials, Apps with Owners, Inactive Apps, Entra Connect Application
- **Managed Identities**: Privileged, Extensive API Privs, With Roles
- **App Registrations**: Apps with Owners, Apps Controlled by App Admins, Apps with Secrets, Not Protected by AppLock, Multitenant, Entra Connect
- **CAPs**: Enabled, Blocking, MFA, Auth Strength, Device Registration, Security Info, Legacy Auth, Device Code Flow, Network Location, Session Control
- **Entra Roles**: Eligible, Active, Tier-0, Service Principal, Scoped, Custom Roles
- **Azure Roles**: Eligible, Active, Additional Conditions, Service Principal, Custom Roles
- **PIM**: Various tier-based views

### Reset View

Click **Reset View** to clear all filters, sorting, and column selections back to defaults.

### Details Sections

Click an object name to expand its **Details** section, which shows additional information such as group memberships, permission grants, credentials, role assignments, and ownership chains. Browser search (Ctrl+F) can locate content within collapsed details sections.

### Cross-Report Navigation

Object names are hyperlinked across reports. For example, a user's group membership links to that group's entry in the Groups report. Use the browser's back button to return after following a cross-report link.

### Theme Toggle

Reports support dark mode (default) and light mode. The toggle is in the report header and the preference is saved in `localStorage`.

### Table Header Tooltips

Some column headers display helper text on mouse hover explaining what the column represents (e.g., Impact, Likelihood, Risk definitions).
