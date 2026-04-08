# EntraFalcon Code Review

**Review Date:** 2026-03-20
**Codebase Version:** V20260316
**Scope:** All modules under `modules/`, `run_EntraFalcon.ps1`, and supporting files

---

## Finding 1: XSS in HTML Reports

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **Confidence** | Confirmed |
| **Category** | Security |
| **Affected Files** | `modules/shared_Functions.psm1` (HTML report generation), all `check_*.psm1` (data passed to reports) |

**Evidence:**
All tenant-derived data (display names, UPNs, descriptions, group names, etc.) is rendered into HTML reports without sanitization. The JavaScript in `shared_Functions.psm1` renders table data from JSON objects, some via `innerHTML`. Links are constructed throughout the codebase using raw string interpolation, e.g.:

```powershell
DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
```

These patterns appear in every module (`check_Users.psm1`, `check_Groups.psm1`, `check_EnterpriseApps.psm1`, `check_ManagedIdentities.psm1`, `check_AppRegistrations.psm1`).

**Why It Matters:**
An attacker who controls a display name, group name, or description in the tenant could inject arbitrary JavaScript into the report. When an administrator opens the report in a browser, the script executes in the context of the local file, potentially exfiltrating the report data or performing actions on behalf of the user.

**Recommended Fix:**
HTML-encode all tenant-derived strings before embedding them in HTML output. Apply encoding at the point where the HTML string is constructed, e.g., using `[System.Web.HttpUtility]::HtmlEncode()` or `[System.Net.WebUtility]::HtmlEncode()`. This is acknowledged as a known limitation in the README.

---

## Finding 2: Managed Identities AppRoles Always Zero

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_ManagedIdentities.psm1`, line 697 |

**Evidence:**
Line 697 references `$MatchingAppRoles` in the output object:

```powershell
AppRoles = ($MatchingAppRoles | Measure-Object).count
AppRolesDetails = $MatchingAppRoles
```

However, `$MatchingAppRoles` is never defined within the Managed Identities processing loop. No variable by that name is assigned anywhere in `check_ManagedIdentities.psm1`. The result is that `AppRoles` is always 0 and `AppRolesDetails` is always `$null`.

**Why It Matters:**
Managed Identities with custom AppRole assignments will not have those roles reflected in the report or in the scoring. This creates a blind spot in the risk assessment for Managed Identities that have been granted AppRoles.

**Recommended Fix:**
Add AppRole enumeration logic to the Managed Identity processing loop, similar to the pattern used in `check_EnterpriseApps.psm1` lines 467-495 where `$MatchingAppRoles` is populated by iterating `$Approles`.

---

## Finding 3: Risk Formula Inconsistency Across Modules

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Confirmed |
| **Category** | Maintainability |
| **Affected Files** | `check_Users.psm1` line 970, `check_Groups.psm1` line 1292, `check_EnterpriseApps.psm1` line 1210, `check_ManagedIdentities.psm1` line 706, `check_AppRegistrations.psm1` line 650 |

**Evidence:**
Each module computes Risk differently:

| Module | Formula | Code |
|--------|---------|------|
| Users | `[math]::Round($Impact * $Likelihood)` | line 970 |
| Groups | `[math]::Ceiling($ImpactScore * $LikelihoodScore)` | line 1292 |
| Enterprise Apps | `$ImpactScore * $LikelihoodScore` (raw, then `[math]::Round()` in post-processing) | line 1210, post-processing lines 1236/1248/1268/1280 |
| Managed Identities | `$ImpactScore * $LikelihoodScore` (raw, no rounding) | line 706 |
| App Registrations | `[math]::Round($ImpactScore * $LikelihoodScore)` | line 650 |

**Why It Matters:**
The inconsistent rounding means that cross-module risk comparisons (e.g., in the summary dashboard) are not strictly comparable. A risk score of 100 in one module may have been rounded differently than a risk score of 100 in another module. The practical impact is small since the differences are typically less than 1 unit, but it complicates auditing and testing.

**Recommended Fix:**
Standardize on a single rounding function for risk computation across all modules. `[math]::Round()` (banker's rounding) is the most commonly used and would be a reasonable default.

---

## Finding 4: Wrong Variable in User SP Report

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_Users.psm1`, line 1288 |

**Evidence:**
Line 1288 constructs the SP owner details report for the user detail view:

```powershell
"AzureRoles" = $app.GroupOwnership
```

This should be `$app.AzureRoles`. The `$app` object (sourced from `$SPOwnerDetails`) has both `.GroupOwnership` and `.AzureRoles` properties. The current code displays GroupOwnership data in the AzureRoles column of the user's detail HTML view.

**Why It Matters:**
The user detail report incorrectly shows group ownership counts in the Azure Roles column for owned Service Principals. Administrators reviewing the report will see misleading data in this specific sub-table.

**Recommended Fix:**
Change line 1288 from `$app.GroupOwnership` to `$app.AzureRoles`.

---

## Finding 5: Expired Variable Not Reset Between Credential Iterations

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_AppRegistrations.psm1`, lines 296-315 (secrets), lines 327-343 (certificates) |

**Evidence:**
The `$Expired` variable is set inside an `if ($null -ne $creds.EndDateTime)` block (lines 298-305) but is never reset at the top of the `foreach` loop. If a credential has `EndDateTime = $null` (i.e., a non-expiring credential), the `if` block is skipped, and `$Expired` retains its value from the previous iteration.

```powershell
$AppCredentialsSecrets = foreach ($creds in $item.PasswordCredentials) {
    if ($null -ne $creds.EndDateTime) {
        try {
            $endDate = [datetime]$creds.EndDateTime
            $Expired = ($endDate - (Get-Date)).TotalDays -le 0
        } catch {
            $Expired = "?"
        }
    }
    # $Expired is NOT reset if EndDateTime is null
    [pscustomobject]@{
        ...
        Expired = $Expired
        ...
    }
}
```

The same pattern repeats for certificates at lines 328-335.

**Why It Matters:**
A non-expiring credential could be incorrectly marked as expired (or vice versa) based on the status of a prior credential in the same application. This could cause incorrect reporting on credential hygiene.

**Recommended Fix:**
Add `$Expired = $null` (or a meaningful default like `"N/A"`) at the beginning of each `foreach` iteration, before the `if` check.

---

## Finding 6: O(N*M) SP Matching in App Registrations

| Field | Value |
|-------|-------|
| **Severity** | Medium (Performance) |
| **Confidence** | Confirmed |
| **Category** | Maintainability |
| **Affected Files** | `modules/check_AppRegistrations.psm1`, line 606 |

**Evidence:**
Line 606 iterates the entire `$EnterpriseApps` hashtable for every App Registration to find the matching SP:

```powershell
$EnterpriseApps.GetEnumerator() | Where-Object { $_.Value.AppId -eq $item.AppId } | Select-Object -First 1 | ForEach-Object {
    $ImpactScore += $_.Value.Impact
    $SPObjectID = $_.Name
    $ApiDelegatedCount = $_.Value.ApiDelegated
}
```

`$EnterpriseApps` is a hashtable keyed by SP ObjectId, not by AppId. This forces a linear scan of all SPs for every App Registration, resulting in O(N*M) complexity where N = number of App Registrations and M = number of Enterprise Apps.

**Why It Matters:**
In large tenants with thousands of App Registrations and Enterprise Apps, this becomes a significant performance bottleneck. For example, with 5,000 App Registrations and 10,000 Enterprise Apps, this produces 50 million comparisons.

**Recommended Fix:**
Build a reverse lookup hashtable `$EnterpriseAppsByAppId` keyed by `AppId` before the processing loop, then perform O(1) lookups: `$match = $EnterpriseAppsByAppId[$item.AppId]`.

---

## Finding 7: O(N*R) Role Assignment Scanning in App Registrations

| Field | Value |
|-------|-------|
| **Severity** | Medium (Performance) |
| **Confidence** | Confirmed |
| **Category** | Maintainability |
| **Affected Files** | `modules/check_AppRegistrations.psm1`, lines 187-208 |

**Evidence:**
Lines 187 and 199 scan ALL role assignments across ALL principals to find Cloud Application Administrators and Application Administrators scoped to the entire tenant:

```powershell
$CloudAppAdminTenant = $TenantRoleAssignments.Values | ForEach-Object {$_ | Where-Object { $_.RoleDefinitionId -eq "158c047a-..." -and $_.DirectoryScopeId -eq "/" }}
```

This iterates every value in the `$TenantRoleAssignments` hashtable (which maps PrincipalId -> array of role assignments). The same operation is repeated for Application Administrators.

Similarly, inside the per-app processing loop (lines 493 and 506), the same pattern scans all role assignments to find scoped admins for each individual app registration. This is O(N * R) where N = app registration count and R = total role assignment count.

**Why It Matters:**
For tenants with many role assignments and many app registrations, this compounds into substantial processing time. The tenant-scoped admin lookup (lines 187-208) is done once and is less concerning, but the per-app scoped admin lookup (lines 493/506) is inside the main loop.

**Recommended Fix:**
Pre-build index hashtables: one mapping `RoleDefinitionId + DirectoryScopeId` to lists of principal IDs, enabling O(1) lookups in the processing loop.

---

## Finding 8: AppRegistration Type Never Matches in check_Roles.psm1

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_Roles.psm1`, line 91 |

**Evidence:**
Line 91 contains:

```powershell
if ($normalizedType -eq "unknown" -or $normalizedType -eq "AppRegistration" ) {
```

However, `$normalizedType` is produced by `.ToLower()` (or equivalent normalization) earlier in the function, so it will always be `"appregistration"` (lowercase), never `"AppRegistration"` (PascalCase). PowerShell's `-eq` operator is case-insensitive by default, so this actually does match.

**Update on re-analysis:** PowerShell's `-eq` is case-insensitive by default. `"appregistration" -eq "AppRegistration"` evaluates to `$true`. This finding may be a false positive depending on whether the normalization explicitly uses `-ceq` (case-sensitive) anywhere. Based on the code at line 91, the standard `-eq` operator is used, which is case-insensitive. However, if `$normalizedType` is normalized via `.ToLower()`, the intent suggests case-sensitive comparison was expected. The code works correctly due to PowerShell's default behavior, but the inconsistency between lowercasing and then comparing to a mixed-case string indicates a code quality issue.

**Why It Matters:**
If the comparison were ever changed to `-ceq` or if the normalization logic changes, this would silently break. The code works today by accident of PowerShell's default case-insensitivity.

**Recommended Fix:**
Use consistent casing: either compare to `"appregistration"` (lowercase) or do not lowercase `$normalizedType`.

---

## Finding 9: Undefined $groupDynamic in check_Groups.psm1

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_Groups.psm1`, line 1094 |

**Evidence:**
Line 1094 references `$groupDynamic`:

```powershell
} elseif ($group.Visibility -eq "Public" -and $groupDynamic -eq $false -and $grouptype -contains "M365 Group") {
```

The variable `$groupDynamic` is never defined in the scope. The group's dynamic status is stored in `$group.Dynamic` (set at lines 860-863). An undefined variable in PowerShell evaluates to `$null`, and `$null -eq $false` is `$true` in PowerShell, so this condition passes when `$group.Dynamic` is `$true` (dynamic groups), which is the opposite of the intended behavior.

**Why It Matters:**
The warning "Public M365 group in CAP" could be incorrectly generated for dynamic public M365 groups used in CAPs, when the intent was to generate it only for non-dynamic groups. The practical impact is limited because earlier `elseif` branches catch dynamic groups (line 1090), so this branch is only reached when `$group.Dynamic` is `$false` and `$group.OnPremisesSyncEnabled` is also `$false` and `$group.IsAssignableToRole` is `$false`.

**Recommended Fix:**
Replace `$groupDynamic` with `$group.Dynamic`.

---

## Finding 10: Incorrect Null Check Pattern in check_CAPs.psm1

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_CAPs.psm1`, lines 1324, 1338, 1351 |

**Evidence:**
Three locations use the pattern:

```powershell
if (-not $null -eq $ConditionsHTML) {
```

This is logically incorrect. PowerShell evaluates this as `(-not $null) -eq $ConditionsHTML`, which first evaluates `-not $null` to `$true`, then compares `$true -eq $ConditionsHTML`. For a non-null string, PowerShell coerces the string to a boolean, which is `$true` for non-empty strings and `$false` for empty strings.

The intended pattern is `if ($null -ne $ConditionsHTML)` or `if (-not ($null -eq $ConditionsHTML))`.

**Why It Matters:**
The bug is masked because the typical value of `$ConditionsHTML` is a non-empty string (which coerces to `$true`). If `$ConditionsHTML` were an empty string `""`, the current code would skip it (since `$true -eq ""` coerces `""` to `$false`), while the correct check would pass it through. The behavior difference only manifests for empty strings, which are unlikely but possible edge cases.

**Recommended Fix:**
Change all three instances to `if ($null -ne $variable)`.

---

## Finding 11: Import-Module Paths Use Backslash Literals

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Likely |
| **Category** | Bug |
| **Affected Files** | `run_EntraFalcon.ps1`, lines 127-141 |

**Evidence:**
Lines 127-141 use `Join-Path` with backslash-containing string literals:

```powershell
Import-Module (Join-Path $ScriptRoot 'modules\EntraTokenAid.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\Send-ApiRequest.psm1') -Force
...
```

`Join-Path` in PowerShell joins two path segments using the platform-appropriate separator. However, the second argument `'modules\EntraTokenAid.psm1'` already contains a backslash. On Linux, `Join-Path "/root/falcon" "modules\EntraTokenAid.psm1"` produces `/root/falcon/modules\EntraTokenAid.psm1` -- the backslash inside the second argument is treated as a literal character, not a path separator.

**Why It Matters:**
On Linux, this produces paths with embedded backslashes that will fail to resolve. PowerShell on Linux treats `\` as a literal character in paths, not a separator. This would prevent the tool from loading its modules on Linux if the backslash is not handled by PowerShell's `Join-Path` normalization.

**Note:** In practice, PowerShell 7's `Join-Path` on Linux does normalize backslashes in the child path on some builds, so this may work on many Linux installations. The behavior is implementation-dependent.

**Recommended Fix:**
Use forward slashes or `[System.IO.Path]::Combine()`: `Join-Path $ScriptRoot 'modules/EntraTokenAid.psm1'`.

---

## Finding 12: Delegated vs Application Permission Scoring Asymmetry

| Field | Value |
|-------|-------|
| **Severity** | Info |
| **Confidence** | Confirmed |
| **Category** | Risky Assumption |
| **Affected Files** | `modules/check_EnterpriseApps.psm1`, lines 1019-1097 |

**Evidence:**
Application permissions are scored per-permission (additive). Each individual permission adds its category weight to Impact:

```
Dangerous: +800 per permission
High:      +400 per permission
Medium:    +100 per permission
Low:       +50 per permission
Misc:      +20 per permission
```

Delegated permissions are scored per-category (once), regardless of how many permissions exist in that category:

```
Dangerous: +200 (once, if any)
High:      +100 (once, if any)
Medium:    +60 (once, if any)
Low:       +20 (once, if any)
Misc:      +20 (once, if any)
```

Example: An SP with 10 High application permissions gets Impact += 4,000. An SP with 10 High delegated permissions gets Impact += 100.

**Why It Matters:**
This is a deliberate design choice reflecting the higher risk of application permissions (which do not require user context). However, users of the tool should understand that delegated permission risk is capped per category, which may understate the risk of SPs with many consented delegated permissions across many users.

**Recommended Fix:**
Document this design decision in the scoring methodology. No code change required unless the scoring model is deliberately revised.

---

## Finding 13: AzureRoleTier?Privileged Key Missing from Impact Score Table

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/shared_Functions.psm1` (line 4048-4059), `modules/check_Groups.psm1` (via `Invoke-AzureRoleProcessing`) |

**Evidence:**
The `$GLOBALImpactScore` hashtable at line 4048 defines:

```powershell
"AzureRoleTier0"            = 200
"AzureRoleTier1"            = 70
"AzureRoleTier2"            = 50
"AzureRoleTier3"            = 10
"AzureRoleTier?"            = 50
```

There is no `"AzureRoleTier?Privileged"` key. However, `Invoke-AzureRoleProcessing` at line 4331 references it:

```powershell
if ($Role.IsPrivileged) {
    $RoleImpact = $GLOBALImpactScore["AzureRoleTier?Privileged"]
} else {
    $RoleImpact = $GLOBALImpactScore["AzureRoleTier?"]
}
```

When `$GLOBALImpactScore["AzureRoleTier?Privileged"]` is looked up and the key does not exist, PowerShell returns `$null`, which is treated as `0` in arithmetic.

**Why It Matters:**
Any Azure role not in the rating table that has `IsPrivileged = $true` will receive an Impact score of 0 instead of a meaningful value. This silently understates the risk of unrecognized privileged Azure roles. The Entra side has the corresponding `"EntraRoleTier?Privileged" = 100` key defined.

**Recommended Fix:**
Add `"AzureRoleTier?Privileged" = 100` (or an appropriate value) to the `$GLOBALImpactScore` hashtable.

---

## Finding 14: Wrong Variable in Debug Log in check_EnterpriseApps.psm1

| Field | Value |
|-------|-------|
| **Severity** | Info |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_EnterpriseApps.psm1`, line 1256 |

**Evidence:**
Line 1256:

```powershell
Write-Log -Level Debug -Message "Number of ownerships SP->SP: $($SPOwningApps.count)"
```

At this point in the code, the context is processing SP->SP ownership (`$SPOwningSPs`), but the debug message references `$SPOwningApps` (which was from the previous SP->AppReg->SP section at line 1222). The variable name should be `$SPOwningSPs`.

**Why It Matters:**
Debug log output will show the count of SPs owning App Registrations instead of the count of SPs owning other SPs. This is cosmetic but can confuse debugging.

**Recommended Fix:**
Change `$SPOwningApps.count` to `$SPOwningSPs.count`.

---

## Finding 15: Credential DateTime Null Risk in Managed Identities

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_ManagedIdentities.psm1`, lines 895-896 |

**Evidence:**
Lines 895-896 call `.ToString()` on credential DateTime properties without null guards:

```powershell
"StartDateTime" = $($object.StartDateTime.ToString())
"EndDateTime" = $($object.EndDateTime.ToString())
```

If `StartDateTime` or `EndDateTime` is `$null`, calling `.ToString()` on `$null` in PowerShell produces an empty string in PowerShell 5.1 but throws an error in strict mode or may behave differently in PowerShell 7.

**Why It Matters:**
Managed Identities typically have system-managed credentials that may not have explicit EndDateTime values. A null DateTime could cause a runtime error or produce misleading output.

**Recommended Fix:**
Add null guards: `if ($object.StartDateTime) { $object.StartDateTime.ToString() } else { "-" }`.

---

## Finding 16: Azure Role Sort Logic Uses Hashtable Indexer on PSCustomObject

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | `modules/check_Roles.psm1`, lines 460-466 |

**Evidence:**
Lines 460-465 use hashtable indexer syntax on what are PSCustomObjects:

```powershell
$SortedAzureRoles = $SortedAzureRoles | Sort-Object -Property @{
    Expression = {
        if ($_['Scope'] -eq '/') {
            0
        } elseif ($_['Scope'] -like '/providers/Microsoft.Management/managementGroups/*') {
            1
        } else {
            2 + ($_['Scope'] -split '/').Count
        }
    }
}
```

The `$_['Scope']` syntax works on hashtables but is unreliable on PSCustomObjects. In PowerShell 5.1, PSCustomObjects do not support indexer access; in PowerShell 7, they do via the `Item` method. The adjacent sort expression at line 470 correctly uses `$_.Scope`.

**Why It Matters:**
On PowerShell 5.1, `$_['Scope']` on a PSCustomObject returns `$null`, causing all items to fall into the `else` branch. The sort order would then depend only on the secondary and tertiary sort keys, which may still produce acceptable results, but the primary sort by scope depth would be ineffective.

**Recommended Fix:**
Change `$_['Scope']` to `$_.Scope` in all three occurrences within the sort expression.

---

## Finding 17: Null Value JavaScript Interpolation in export_Summary.psm1

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Confidence** | Likely |
| **Category** | Bug |
| **Affected Files** | `modules/export_Summary.psm1`, lines 339-488 |

**Evidence:**
Lines 339-488 construct a JavaScript `dataSources` object by interpolating PowerShell variables directly into a here-string:

```powershell
users_general: {
    internal: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.Guests)),
    guests: $($GlobalAuditSummary.Users.Guests),
    total: $($GlobalAuditSummary.Users.Count)
},
```

If any `$GlobalAuditSummary` property is `$null`, the interpolation produces an empty string, resulting in invalid JavaScript such as:

```javascript
internal: ,
guests: 0,
```

This would cause a JavaScript parse error, breaking all charts on the summary page.

**Why It Matters:**
If any module fails to populate its section of `$GlobalAuditSummary` (e.g., due to insufficient permissions, API errors, or empty tenant), the summary page charts will break silently. The rest of the HTML page may still render, but the chart section will not.

**Recommended Fix:**
Default all null values to `0` before interpolation, e.g., using `$(if ($null -eq $val) { 0 } else { $val })` or pre-validating the `$GlobalAuditSummary` object.

---

## Finding 18: README Claims >60 Checks, Code Has 49 Finding IDs

| Field | Value |
|-------|-------|
| **Severity** | Info |
| **Confidence** | Confirmed |
| **Category** | Inaccurate Documentation |
| **Affected Files** | `README.md`, `modules/check_Tenant.psm1` |

**Evidence:**
The README states "performs >60 automated checks." A count of unique `FindingId` entries in `check_Tenant.psm1` yields **63** formal security finding IDs: COL (3) + PAS (5) + USR (12) + GRP (5) + CAP (11) + ENT (12) + APP (3) + MAI (3) + PIM (9) = 63. The README claim of ">60" is therefore **accurate**.

**Why It Matters:**
The initial analysis incorrectly counted 49 finding IDs due to an incomplete grep. The actual count of 63 confirms the README's claim. This finding is **retracted** — the README is accurate.

**Recommended Fix:**
No fix needed. The README's ">60 automated checks" claim is correct (63 findings exist).

---

## Finding 19: BroCi Token Visible in Command Line

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Confidence** | Confirmed |
| **Category** | Security |
| **Affected Files** | `run_EntraFalcon.ps1` (parameter definition) |

**Evidence:**
The `-BroCiToken` parameter is defined as a plain `[string]`:

```powershell
[Parameter(Mandatory=$false)][string]$BroCiToken
```

When a user provides this token on the command line, it is visible in:
- The process list (`ps aux` / `Get-Process`)
- Shell history (`.bash_history`, `PSReadLine` history)
- PowerShell transcript logs if enabled

The BroCi token is an OAuth refresh token that grants access to Microsoft Graph and Azure management APIs.

**Why It Matters:**
An OAuth refresh token exposed in process lists or command history can be extracted by other users on the same system or by malware that reads shell history. This token grants broad access to the tenant.

**Recommended Fix:**
Use `[securestring]` for the parameter type and convert internally, or prompt for the token interactively when the `BroCiToken` auth flow is selected, or read the token from a file or environment variable.

---

## Finding 20: No Token Refresh Error Handling

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Confidence** | Confirmed |
| **Category** | Bug |
| **Affected Files** | All `check_*.psm1` modules |

**Evidence:**
Multiple modules call token refresh with no error handling:

```powershell
if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
```

This pattern appears at the top of each module and periodically within processing loops. If `RefreshAuthenticationMsGraph` fails (e.g., network error, token revocation, conditional access enforcement), the return value is piped to `Out-Null` and execution continues with an expired token. Subsequent API calls will fail with 401 errors, but the errors are not caught in a way that would abort the module gracefully.

**Why It Matters:**
A token refresh failure mid-execution could lead to a cascade of API errors. The module may continue processing with stale data, partially complete results, or may produce an incomplete report without clearly indicating that data is missing.

**Recommended Fix:**
Check the return value of `RefreshAuthenticationMsGraph` and abort or warn if the refresh fails. Consider a pattern like:

```powershell
if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) {
    $refreshResult = RefreshAuthenticationMsGraph
    if (-not $refreshResult) {
        Write-Error "Token refresh failed. Aborting module." -ErrorAction Stop
    }
}
```
