# EntraFalcon Architecture

## Entry Point

**File:** `run_EntraFalcon.ps1` (399 lines)

The entry point script performs parameter validation and then imports 14 modules via `Import-Module` with hardcoded relative paths using backslash separators.

**Cross-platform note:** The `Import-Module` paths (lines 127-141) use literal Windows-style backslash separators, e.g. `'modules\filename.psm1'`. While PowerShell's `Join-Path` handles cross-platform path construction, these hardcoded strings may fail on Linux unless the PowerShell runtime resolves backslashes transparently.

---

## Module Architecture

### Vendored Modules (Forked External Tools)

These modules are forked from external repositories and included directly in the repo:

- **EntraTokenAid** -- OAuth authentication flows
- **Send-ApiRequest** -- Generic HTTP client with retry logic
- **Send-GraphRequest** -- Microsoft Graph API client
- **Send-GraphBatchRequest** -- Microsoft Graph Batch API client

### Shared Module

- **shared_Functions.psm1** (6055 lines, ~448KB) -- The largest module in the project. Contains:
  - HTML/JS/CSS templates for report generation
  - Scoring tables for security findings
  - Authentication orchestration
  - Data collection helpers
  - General-purpose utility functions

### Check Modules

Each check module is responsible for analyzing a specific area of the Entra ID tenant:

| Module | Area |
|--------|------|
| check_Groups | Group configuration and membership |
| check_Users | User accounts and properties |
| check_EnterpriseApps | Enterprise application (service principal) analysis |
| check_AppRegistrations | Application registration analysis |
| check_ManagedIdentities | Managed identity analysis |
| check_CAPs | Conditional Access Policies |
| check_PIM | Privileged Identity Management settings |
| check_Tenant | Tenant-wide configuration |
| check_Roles | Role assignment analysis |

### Export Module

- **export_Summary** -- Produces the final summary report with statistics and charts.

---

## Data Flow

The tool executes in a fixed sequence. Each phase depends on data produced by earlier phases.

1. **Authentication** -- Tokens are acquired and stored in global variables.
2. **Pre-collection: PIM for Groups** -- Requires a separate auth token; collected early because group analysis depends on it.
3. **Basic data collection** -- Org info, licenses, admin units, Conditional Access Policies, PIM role assignments, Azure IAM role assignments, MFA status, devices, basic user data.
4. **Groups enumeration** -- Produces the `$AllGroupsDetails` hashtable, keyed by group ID.
5. **Enterprise Apps** -- Produces the `$EnterpriseApps` hashtable and populates `$GLOBALUserAppRoles`.
6. **Managed Identities** -- Produces the `$ManagedIdentities` collection.
7. **App Registrations** -- Produces `$AppRegistrations` and cross-references entries in `$EnterpriseApps`.
8. **Users** -- Produces `$Users`, inheriting membership and role data from the groups and apps phases.
9. **Roles report** -- Enriches and displays role assignment data.
10. **CAPs report** -- Analyzes Conditional Access Policies; produces `$AllCaps`.
11. **PIM settings** -- Analyzes PIM configuration; produces `$PimforEntraRoles`.
12. **Security Findings** -- Aggregates all collected data and runs 63 security checks.
13. **Summary** -- Final statistics and charts are generated.

---

## State Management

EntraFalcon relies heavily on PowerShell global variables for cross-module communication. There is no dependency injection or formal state object; modules read and write shared globals directly.

### Token Globals

| Variable | Purpose |
|----------|---------|
| `$GLOBALMsGraphAccessToken` | Microsoft Graph access token |
| `$GLOBALArmAccessToken` | Azure Resource Manager access token |

### Auth State

| Variable | Purpose |
|----------|---------|
| `$GLOBALAuthMethods` | Available authentication methods |
| `$GLOBALAuthParameters` | Parameters used during authentication |

### Feature Flags

| Variable | Purpose |
|----------|---------|
| `$GLOBALAzurePsChecks` | Whether Azure PS-based checks are enabled |
| `$GLOBALPIMForEntraRolesChecked` | Whether PIM for Entra roles has been checked |
| `$GLOBALPimForGroupsChecked` | Whether PIM for Groups has been checked |
| `$GLOBALGraphExtendedChecks` | Whether extended Graph queries are enabled |

### Report State

| Variable | Purpose |
|----------|---------|
| `$GlobalAuditSummary` | Accumulated audit/security findings |
| `$ReportContext` | Metadata for the current report |
| `$TenantReportTabs` | Navigation tabs across reports |

### Data Caches

| Variable | Scope | Purpose |
|----------|-------|---------|
| `$GLOBALPimForGroupsHT` | Global | PIM for Groups data, keyed by group |
| `$GLOBALUserAppRoles` | Global | User-to-application role mappings |
| `ObjectInfoCache` | Script | Cached object lookups to reduce API calls |

### HTML/JS/CSS Globals

| Variable | Purpose |
|----------|---------|
| `$GLOBALJavaScript` | Shared table JavaScript |
| `$GLOBALCss` | Shared CSS styles |
| `$GLOBALReportManifestScript` | Cross-report navigation manifest |

---

## Report Pipeline

Each check module generates up to three output types:

| Format | Description |
|--------|-------------|
| **HTML** | Standalone HTML file with embedded JS/CSS, interactive table, detail sections, and appendices |
| **TXT** | Plain text summary consisting of a header, formatted table, and detail sections |
| **CSV** | Optional export with the same columns as the HTML main table |

### Shared HTML Resources

All HTML reports share a common set of embedded resources:

- **Common CSS** (`$GLOBALCss`) -- Consistent styling across all reports.
- **Table JavaScript** (`$GLOBALJavaScript_Table`) -- Sorting, filtering, and interactive table behavior.
- **Navigation JavaScript** (`$GLOBALJavaScript_Nav`) -- Cross-report navigation.
- **Chart.js** (`$GLOBALJavaScript_Chart`) -- Client-side charting (doughnut, bar, stacked bar).
- **Report Manifest** -- A manifest enabling navigation between individual report files.

Reports are fully self-contained: all CSS, JavaScript, and data are embedded directly in each HTML file. No external CDN or network access is required to view them.
