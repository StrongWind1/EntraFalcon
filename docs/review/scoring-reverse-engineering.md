# EntraFalcon Scoring System -- Complete Reverse Engineering

**Date:** 2026-03-20
**Codebase Version:** V20260316
**Source:** `modules/shared_Functions.psm1`, `check_Users.psm1`, `check_Groups.psm1`, `check_EnterpriseApps.psm1`, `check_ManagedIdentities.psm1`, `check_AppRegistrations.psm1`, `export_Summary.psm1`

---

## 1. Global Scoring Framework

### 1.1 Impact Score Weights

Defined in `shared_Functions.psm1` lines 4048-4059:

```
$GLOBALImpactScore = @{
    "EntraRoleTier0"            = 2000
    "EntraRoleTier1"            = 400
    "EntraRoleTier2"            = 80
    "EntraRoleTier?Privileged"  = 100
    "EntraRoleTier?"            = 80
    "AzureRoleTier0"            = 200
    "AzureRoleTier1"            = 70
    "AzureRoleTier2"            = 50
    "AzureRoleTier3"            = 10
    "AzureRoleTier?"            = 50
}
```

**Note:** `"AzureRoleTier?Privileged"` is referenced in `Invoke-AzureRoleProcessing` (line 4331) but is NOT defined in this hashtable. This means unknown privileged Azure roles score 0 instead of a non-zero value. See code review Finding 13.

### 1.2 Entra Role Tier Mapping

Defined in `shared_Functions.psm1` lines 3977-4017. Total: 39 roles mapped.

| Tier | Count | Notable Roles |
|------|-------|---------------|
| 0 | 10 | Global Admin, Priv Auth Admin, Priv Role Admin, App Admin, Cloud App Admin, Security Admin, Hybrid Identity Admin, Domain Name Admin, External IdP Admin, Partner Tier2 |
| 1 | 22 | Conditional Access Admin, Auth Admin, Directory Writers, Exchange Admin, Groups Admin, Helpdesk Admin, Intune Admin, User Admin, Password Admin, SharePoint Admin, Teams Admin, etc. |
| 2 | 7 | Auth Policy Admin, Cloud Device Admin, Global Reader, Guest Inviter, Security Reader, Directory Readers, Azure AD Joined Device Local Admin |

Roles not in this table receive tier "?" (unknown). If `IsPrivileged` is true, they get the `EntraRoleTier?Privileged` weight (100); otherwise `EntraRoleTier?` (80).

### 1.3 Azure Role Tier Mapping

Defined in `shared_Functions.psm1` lines 4020-4046. Total: 25 roles mapped.

| Tier | Count | Notable Roles |
|------|-------|---------------|
| 0 | 5 | Owner, User Access Admin, Contributor, RBAC Admin, Reservations Admin |
| 1 | 16 | Security Admin, VM Contributor, VM Data Access Admin, VM Admin Login, Key Vault Admin, Key Vault Secrets Officer, AKS RBAC Admin, Storage Account Contributor, etc. |
| 2 | 2 | Reader, SecurityReader |
| 3 | 2 | VM User Login, Desktop Virtualization User |

### 1.4 API Permission Categorization

#### Application Permissions (`$GLOBALApiPermissionCategorizationList`)
Defined in `shared_Functions.psm1` lines 4061-4122. Keyed by permission GUID.

| Category | Count | Examples |
|----------|-------|----------|
| Dangerous | 10 | RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, Application.ReadWrite.All, Domain.ReadWrite.All |
| High | 37 | Directory.ReadWrite.All, Group.ReadWrite.All, User.DeleteRestore.All, Sites.FullControl.All, Files.ReadWrite.All, Policy.ReadWrite.ConditionalAccess |
| Medium | 7 | User.ReadWrite.All, Chat.Read.All, Mail.Read, Mail.Send, Calendars.ReadWrite |
| Low | 1 | AgentIdentity.CreateAsManager |

#### Delegated Permissions (`$GLOBALDelegatedApiPermissionCategorizationList`)
Defined in `shared_Functions.psm1` lines 4124-4207. Keyed by permission name (string).

| Category | Count | Examples |
|----------|-------|----------|
| Dangerous | 10 | Same logical permissions as application, different GUIDs |
| High | 26 | Directory.ReadWrite.All, Sites.FullControl.All, UserAuthMethod-Password.ReadWrite.All |
| Medium | 30+ | Mail.Read, Calendars.ReadWrite, Chat.ReadWrite, Directory.AccessAsUser.All, EWS.AccessAsUser.All |
| Low | 5 | offline_access, openid, email, profile, User.Read |

### 1.5 Shared Scoring Functions

#### Invoke-EntraRoleProcessing (lines 4213-4285)
- Input: Array of role detail objects
- Process: For each role, looks up `RoleTier` in switch statement, maps to `$GLOBALImpactScore` key
- Accumulates `$ImpactScore` and `$EligibleImpactScore` (for eligible-only roles)
- Generates summary warning string (e.g., "2 (Tier0), 1 (Tier1) Entra roles assigned")
- Returns: `[PSCustomObject]@{ ImpactScore; EligibleImpactScore; Warning }`

#### Invoke-AzureRoleProcessing (lines 4288-4367)
- Identical structure to Entra, but includes Tier 3
- Uses `AzureRoleTier*` keys from `$GLOBALImpactScore`
- Bug: references `AzureRoleTier?Privileged` which does not exist (returns $null/0)

#### Tier Helper Functions
- `Get-HighestTierLabel`: Examines an array of role assignments and returns the highest (most privileged) tier label string (e.g., "T0", "T1", "T2", "T3", "-")
- `Resolve-TierLabel`: Converts a numeric tier to its label
- `Get-TierPriority`: Returns sort priority for tier labels
- `Merge-HigherTierLabel`: Compares two tier labels and returns the more privileged one

---

## 2. Per-Module Scoring Breakdown

### 2.1 Users Module (`check_Users.psm1`)

#### Impact Constants (lines 61-66)

```
$UserImpact = @{
    "Base"                      = 1
    "DirectAppRoleNormal"       = 10
    "DirectAppRoleSensitive"    = 50
    "SpOwnAppLock"              = 20
}
```

#### Likelihood Constants (lines 68-73)

```
$UserLikelihood = @{
    "Base"                      = 5
    "SyncedFromOnPrem"          = 3      # Note: defined but NOT used in scoring
    "Protected"                 = -4
    "NoMFA"                     = 10
}
```

**Note:** `SyncedFromOnPrem` is defined but never referenced in the scoring logic. It appears to be a vestigial constant.

#### Impact Accumulation (step by step)

1. **Base Impact** (line 339): `$Impact = $UserImpact["Base"]` = 1
2. **Owned SP Impact** (lines 648-676): For each owned SP:
   - If SP has `AppLock = $false`: add full SP Impact
   - If SP has `AppLock = $true`: add `min(SP.Impact, SpOwnAppLock=20)`
   - If SP has `AppLock` unknown: add full SP Impact
3. **Owned App Registration Impact** (lines 680-690): For each owned AppReg, add `AppReg.Impact`
4. **Owned Group Impact** (lines 694-745): For each owned group, add `group.Impact`
5. **Member Group Impact** (lines 748-798): For each group membership:
   - Add `group.Impact`
   - Subtract `50 * ObjectsWithCaps` (lines 776-777, removes CAP impact for mere members)
6. **Entra Role Impact** (lines 843-858): Via `Invoke-EntraRoleProcessing`, adds per-role tier weights
7. **Direct App Role Impact** (lines 861-888):
   - Sensitive AppRoles (matching "admin"/"critical" keywords): add 50 each
   - Normal AppRoles: add 10 each
8. **Azure Role Impact** (lines 932-937): Via `Invoke-AzureRoleProcessing`

#### Likelihood Accumulation

1. **Base Likelihood** (line 340): `$Likelihood = $UserLikelihood["Base"]` = 5
2. **No MFA** (lines 643-645): If user is not MFA-capable and not sync account and not agent: +10
3. **Protected** (line 929): If user is protected (role-assignable group member, restricted AU, etc.): -4
4. Likelihood is accumulated but NOT further increased for on-prem sync, ownership counts, etc. (unlike other modules)

#### Risk Formula (line 970)
```
$Risk = [math]::Round($Impact * $Likelihood)
```

#### Protected Status Determination
- Member of role-assignable group (line 782-784)
- Owner of role-assignable group (line 723-725)
- Member of restricted Administrative Unit (line 800-803)
- Has any Entra role not in `$UnprotectedRoles` list (line 838-840)

---

### 2.2 Groups Module (`check_Groups.psm1`)

#### Impact Constants (lines 212-220)

```
$GroupImpactScore = @{
    "M365Group"                 = 1
    "HiddenGAL"                 = 1
    "Distribution"              = 0.5
    "SecurityEnabled"           = 2
    "AzureRole"                 = 100      # Note: defined but NOT used directly
    "AppRole"                   = 10
    "CAP"                       = 50
}
```

**Note:** `AzureRole` (100) is defined but Azure role impact is handled by `Invoke-AzureRoleProcessing` using global weights, not this constant. Similarly `HiddenGAL` is defined but not visibly consumed.

#### Likelihood Constants (lines 221-234)

```
$GroupLikelihoodScore = @{
    "PublicM365Group"           = 100
    "Member"                    = 0.1
    "DirectOwnerCloud"          = 1
    "DirectOwnerOnprem"         = 2
    "PIMforGroupsOwnersGroup"   = 3
    "NestedGroup"               = 2       # Defined but not visibly used in main loop
    "DynamicGroup"              = 5
    "DynamicGroupDangerous"     = 20
    "ExternalSPMemberOwner"     = 50
    "InternalSPMemberOwner"     = 5
    "BaseNotProtected"          = 5
    "GuestMemberOwner"          = 5
}
```

#### Impact Accumulation

1. **Group Type** (lines 848-856):
   - M365 Group: +1
   - Distribution: +0.5
   - Security Group: +0 (no explicit addition)
2. **Azure Role Processing** (lines 987-993): Via `Invoke-AzureRoleProcessing` using global weights
3. **Entra Role Processing** (lines 1038-1049): Via `Invoke-EntraRoleProcessing` using global weights
4. **CAP Assignment** (line 1087): +50 per CAP association
5. **App Roles** (line 1167): +10 if any AppRole assignments exist
6. **Security Enabled** (line 1203): +2

#### Likelihood Accumulation

1. **Not Protected** (line 1081): +5 if not protected
2. **Direct Owner Cloud** (line 1029): +1 if cloud owner exists
3. **Direct Owner On-Prem** (line 1027): +2 if on-prem synced owner exists
4. **PIM for Groups Owners** (line 1035): +3 if group-based eligible owners exist
5. **Public M365 Group** (line 1133): +100 if public, non-dynamic M365 group
6. **Guest Owner** (line 1143): +5 if guest user is an owner
7. **Dynamic Group** (lines 1147-1161):
   - Normal dynamic: +5
   - Dangerous query patterns: +20
8. **External SP Member/Owner** (lines 1171-1191): +50 per external non-MS SP
9. **Internal SP Member/Owner** (lines 1175-1190): +5 per internal SP
10. **Member Count** (line 1198): `+sqrt(MemberCount) * 0.1` (square root scaling)

#### Risk Formula (line 1292)
```
Risk = [math]::Ceiling($ImpactScore * $LikelihoodScore)
```

**Note:** Uses `Ceiling` instead of `Round`. This is the only module using `Ceiling`.

#### Special: ImpactOrgActiveOnly (line 1236)
```
$ImpactOrgActiveOnly = [math]::Round([math]::Max(0, $ImpactScore - $EligibleRoleImpactContribution))
```
This value strips out eligible (PIM) role contributions from the impact score. It is used by downstream modules (Enterprise Apps, Managed Identities) when inheriting group impact through membership (as opposed to ownership, which inherits full impact).

#### Protected Status
- On-prem synced group (line 1077)
- Role-assignable group (line 1077)
- In restricted Administrative Unit (line 1077)

---

### 2.3 Enterprise Apps Module (`check_EnterpriseApps.psm1`)

#### Impact Constants (lines 44-58)

```
$SPImpactScore = @{
    "Base"                      = 1
    "APIDangerous"              = 800
    "APIHigh"                   = 400
    "APIMedium"                 = 100
    "APILow"                    = 50
    "ApiMisc"                   = 20
    "APIDelegatedDangerous"     = 200
    "APIDelegatedHigh"          = 100
    "APIDelegatedMedium"        = 60
    "APIDelegatedLow"           = 20
    "ApiDelegatedMisc"          = 20
    "AppRoleRequired"           = 10
    "AppRole"                   = 2
}
```

#### Likelihood Constants (lines 60-67)

```
$SPLikelihoodScore = @{
    "SpWithCredentials"         = 5
    "ForeignApp"                = 30
    "InternApp"                 = 5
    "Owners"                    = 5
    "UnknownAppLock"            = 1
    "NoAppLock"                 = 2
}
```

**Note:** `$LikelihoodScore` starts at 0 (implicit; no base initialization in the per-SP loop).

#### Impact Accumulation

1. **Base** (line 376): `$ImpactScore = $SPImpactScore["Base"]` = **1**
2. **Azure Role Processing** (lines 779-784): Via `Invoke-AzureRoleProcessing`
3. **App Role Count** (lines 854-857): `+2 * AppRolesCount`
4. **AppRoleAssignmentRequired** (lines 860-862): +10 if SP requires AppRole assignment
5. **Group Membership Impact** (lines 883-938):
   - Inherits `ImpactOrgActiveOnly` from each member group (active-only, excludes eligible roles)
6. **Entra Role Processing** (lines 942-947): Via `Invoke-EntraRoleProcessing`
7. **Group Ownership Impact** (lines 950-1017):
   - Inherits full `Impact` (or `ImpactOrg`) from each owned group (includes eligible roles)
8. **Application API Permissions** (lines 1019-1030): Per-permission additive scoring:
   - Dangerous: +800 per permission
   - High: +400 per permission
   - Medium: +100 per permission
   - Low: +50 per permission
   - Uncategorized: +20 per permission
9. **Delegated API Permissions** (lines 1065-1097): Per-category-once scoring:
   - Dangerous: +200 (once if any)
   - High: +100 (once if any)
   - Medium: +60 (once if any)
   - Low: +20 (once if any)
   - Uncategorized: +20 (once if any)

#### Likelihood Accumulation

1. **SP with Credentials** (line 765): +5 if SP has any credentials
2. **Owner with Unknown AppLock** (line 835): +1 if foreign app with owners
3. **Owner with No AppLock** (line 842): +2 if internal app with owners and no AppLock
4. **Per User Owner** (line 851): `+5 * OwnerUserCount`
5. **Foreign Non-MS App** (line 1125): +30
6. **Internal Non-MS App** (line 1127): +5

#### Risk Formula (line 1210)
```
Risk = $ImpactScore * $LikelihoodScore    # raw, no rounding
```

#### Post-Processing (lines 1217-1285)

After initial scoring, two post-processing passes adjust scores based on ownership chains:

**Pass 1: SP -> AppReg -> SP** (lines 1221-1252)
- For each SP that owns App Registrations:
  - Find the corresponding SP for each owned AppReg
  - Owned SP: `Likelihood += Round(OwnerSP.Likelihood)`
  - Owned SP: `Risk = Round(Impact * Likelihood)`
  - Owner SP: `Impact += Round(OwnedSP.Impact)`
  - Owner SP: `Risk = Round(Impact * Likelihood)`

**Pass 2: SP -> SP** (lines 1254-1285)
- Same pattern for direct SP ownership

After post-processing, Risk is recalculated with `[math]::Round()`.

---

### 2.4 Managed Identities Module (`check_ManagedIdentities.psm1`)

#### Impact Constants (lines 32-44)

```
$SPImpactScore = @{
    "Base"                      = 1
    "CAPGroupOwner"             = 100
    "InheritedHighValue"        = 200
    "APIDangerous"              = 800
    "APIHigh"                   = 400
    "APIMedium"                 = 100
    "APILow"                    = 50
    "ApiMisc"                   = 20
    "GroupMember"               = 5
    "GroupOwner"                = 5      # Defined but not explicitly used
    "AppRole"                   = 2
}
```

#### Likelihood Constants (lines 46-48)

```
$SPLikelihoodScore = @{
    "Base"                      = 1
}
```

**Key observation:** Managed Identity likelihood is effectively fixed at 1. There is only one likelihood constant and no other additions. This is because Managed Identities cannot be owned by external parties, do not have user-creatable credentials, and are inherently bound to Azure resources.

#### Impact Accumulation

1. **Base** (line 175): `$ImpactScore = $SPImpactScore["Base"]` = **1**
2. **Azure Role Processing** (lines 453-458): Via `Invoke-AzureRoleProcessing`
3. **Group Membership** (lines 471-528):
   - Basic score: +5 if member of any group
   - Inherits `ImpactOrgActiveOnly` from each member group
4. **Entra Role Processing** (lines 532-538): Via `Invoke-EntraRoleProcessing`
5. **Group Ownership** (lines 541-608):
   - Inherits full `Impact`/`ImpactOrg` from each owned group
6. **Application API Permissions** (lines 611-621): Per-permission additive (same as Enterprise Apps):
   - Dangerous: +800, High: +400, Medium: +100, Low: +50, Uncategorized: +20

#### Likelihood Accumulation

Explicitly initialized to 1 at line 176: `$LikelihoodScore = $SPLikelihoodScore["Base"]`. No additional likelihood modifiers exist. This is intentional — Managed Identities authenticate via platform tokens, not credentials.

**Note:** Likelihood is not explicitly initialized in the per-MI loop visible in the code excerpt. It inherits whatever the loop-local variable state is.

#### Risk Formula (line 706)
```
Risk = $ImpactScore * $LikelihoodScore    # raw, no rounding
```

---

### 2.5 App Registrations Module (`check_AppRegistrations.psm1`)

#### Likelihood Constants (lines 148-158)

```
$AppLikelihoodScore = @{
    "AppBase"                   = 1
    "AppSecret"                 = 5
    "EntraConnectIoC"           = 200
    "AppCertificate"            = 2
    "AppOwner"                  = 20
    "AppAdmins"                 = 10
    "InternalSPOwner"           = 5
    "ExternalSPOwner"           = 50
    "GuestAsOwner"              = 50
}
```

**Note:** There are no AppRegistration-specific Impact constants. Impact is inherited entirely from the matched Enterprise App (SP) via line 606-610.

#### Impact Accumulation

1. **Impact starts at 0** (line 262): `$ImpactScore = 0`
2. **Inherited from Enterprise App** (lines 606-610): The entire SP Impact score is added to the AppReg Impact

That is the entirety of Impact for App Registrations -- it is a pass-through of the Enterprise App's Impact score.

#### Likelihood Accumulation

1. **Base** (line 263): `$LikelihoodScore = $AppLikelihoodScore["AppBase"]` = 1
2. **Per Secret** (line 521): `+5 * SecretsCount`
3. **Per Certificate** (line 524): `+2 * CertificateCount`
4. **Entra Connect IoC** (lines 528, 534): +200 if Entra Connect app has secrets or multiple certs
5. **Per Admin** (line 543): `+10 * AppAdminsCount` (Cloud App Admins + App Admins, scoped + tenant)
6. **Per Owner** (line 549): `+20 * AppOwnersCount`
7. **External SP Owner** (line 576): +50 if foreign SP is owner
8. **Internal SP Owner** (line 579): +5 if internal SP is owner
9. **Guest as Owner** (lines 586, 590, 594): +50 per guest owner/admin occurrence
10. **Foreign SP as Scoped Admin** (lines 598, 602): +50

#### Risk Formula (line 650)
```
Risk = [math]::Round($ImpactScore * $LikelihoodScore)
```

---

## 3. Worked Examples

### Example 1: Tier-0 User, Synced, No MFA, Owns SP with Dangerous API Permissions

**Scenario:** A user synced from on-premises, no MFA, owns one Enterprise App that has 1 Dangerous + 2 High application API permissions and no AppLock, and holds the Global Administrator role directly.

**Impact Calculation:**

| Step | Source | Value | Running Total |
|------|--------|-------|---------------|
| Base | `$UserImpact["Base"]` | 1 | 1 |
| Global Admin Entra role | `Invoke-EntraRoleProcessing` -> `EntraRoleTier0` | 2000 | 2001 |
| Owned SP Impact (no AppLock) | SP Impact inherited. SP has: Dangerous(800) + High(400)*2 = 1600 | 1600 | 3601 |

SP Impact breakdown: 800 (Dangerous) + 400 (High) + 400 (High) = 1600. With no AppLock, full Impact is inherited.

**Likelihood Calculation:**

| Step | Source | Value | Running Total |
|------|--------|-------|---------------|
| Base | `$UserLikelihood["Base"]` | 5 | 5 |
| No MFA | `$UserLikelihood["NoMFA"]` | 10 | 15 |
| Protected (Global Admin is protected) | `$UserLikelihood["Protected"]` | -4 | 11 |

**Risk Calculation:**
```
Risk = Round(3601 * 11) = Round(39611) = 39611
```

**Warnings Generated:**
- "1 (Tier0) Entra role assigned"
- "User is owner of 1 SP (AppLock:0/1, Unknown:0)"

---

### Example 2: Public M365 Group with Tier-0 Entra Role and Guest Owners

**Scenario:** A public M365 group (not dynamic, not role-assignable, not on-prem) with 50 user members, a guest as owner, and assigned the Global Administrator Entra role via a role-assignable group nested inside it. The group itself is not role-assignable, but it has a nested role-assignable group with the GA role.

Actually, for simplicity: The group IS role-assignable, has the Global Administrator role assigned, is a public M365 group, has a guest owner, and has 50 members.

**Impact Calculation:**

| Step | Source | Value | Running Total |
|------|--------|-------|---------------|
| M365 Group type | `$GroupImpactScore["M365Group"]` | 1 | 1 |
| Security Enabled (if true) | `$GroupImpactScore["SecurityEnabled"]` | 2 | 3 |
| Entra Role: Global Admin | `Invoke-EntraRoleProcessing` -> `EntraRoleTier0` | 2000 | 2003 |
| CAP (assume used in 1 CAP) | `$GroupImpactScore["CAP"]` | 50 | 2053 |

**Likelihood Calculation:**

| Step | Source | Value | Running Total |
|------|--------|-------|---------------|
| Not Protected? | Role-assignable groups ARE protected | 0 | 0 |
| Public M365 Group | `$GroupLikelihoodScore["PublicM365Group"]` | 100 | 100 |
| Guest Owner | `$GroupLikelihoodScore["GuestMemberOwner"]` | 5 | 105 |
| Direct Owner (cloud) | `$GroupLikelihoodScore["DirectOwnerCloud"]` | 1 | 106 |
| Member Count (50 users) | `sqrt(50) * 0.1` = 0.707 | 0.707 | 106.707 |

**Risk Calculation:**
```
Risk = Ceiling(2053 * 106.707) = Ceiling(219073.771) = 219074
```

**Warnings Generated:**
- "1 (Tier0) Entra role assigned"
- "Group is used in CAP"
- "Public M365 group"
- "Guest as owner"

---

### Example 3: Foreign Enterprise App with High API Permissions and Credentials

**Scenario:** A foreign (non-Microsoft) Enterprise App with 3 High application API permissions, 1 Dangerous delegated permission, 2 secrets, 2 user owners, not in any groups, no Entra/Azure roles.

**Impact Calculation:**

| Step | Source | Value | Running Total |
|------|--------|-------|---------------|
| Application API: 3x High | `$SPImpactScore["APIHigh"]` * 3 | 1200 | 1200 |
| Delegated API: Dangerous (once) | `$SPImpactScore["APIDelegatedDangerous"]` | 200 | 1400 |

**Likelihood Calculation:**

| Step | Source | Value | Running Total |
|------|--------|-------|---------------|
| SP with credentials | `$SPLikelihoodScore["SpWithCredentials"]` | 5 | 5 |
| Foreign non-MS App | `$SPLikelihoodScore["ForeignApp"]` | 30 | 35 |
| Owner with no AppLock (foreign) | `$SPLikelihoodScore["UnknownAppLock"]` | 1 | 36 |
| 2 User Owners | `$SPLikelihoodScore["Owners"]` * 2 | 10 | 46 |

**Risk Calculation (initial):**
```
Risk = 1400 * 46 = 64400    # raw, no rounding at this stage
```

Post-processing would further adjust if this SP owns or is owned by other SPs.

**Warnings Generated:**
- "SP with credentials!"
- "SP with owner (unknown AppLock)!"
- "Known high API permission!"
- "Known dangerous delegated API permission!"

---

## 4. Cross-Module Inconsistencies

### 4.1 Risk Formula Rounding

| Module | Formula | Rounding |
|--------|---------|----------|
| Users | `Round(I * L)` | Banker's rounding |
| Groups | `Ceiling(I * L)` | Always rounds up |
| Enterprise Apps | `I * L` (raw), then `Round()` in post-processing | Initially none, then banker's rounding |
| Managed Identities | `I * L` (raw) | None |
| App Registrations | `Round(I * L)` | Banker's rounding |

This makes cross-module comparison of risk scores slightly unreliable at the boundaries.

### 4.2 Application vs Delegated Permission Scoring Asymmetry

Application permissions are scored **additively per permission**. Each individual Dangerous permission adds 800 to Impact.

Delegated permissions are scored **once per category**. No matter how many Dangerous delegated permissions exist, Impact increases by only 200.

**Example impact of 10 Dangerous permissions:**
- Application: 10 * 800 = 8,000
- Delegated: 1 * 200 = 200

This is a design decision reflecting that application permissions operate without user context, but the 40x difference can mask delegated permission risk.

### 4.3 Missing AzureRoleTier?Privileged Key

`$GLOBALImpactScore["AzureRoleTier?Privileged"]` is referenced in `Invoke-AzureRoleProcessing` (line 4331) but not defined in the hashtable. PowerShell returns `$null` (treated as 0). The Entra equivalent `"EntraRoleTier?Privileged" = 100` IS defined.

**Effect:** Unknown privileged Azure roles contribute 0 to impact instead of a meaningful value.

### 4.4 Group ImpactOrgActiveOnly vs Full Impact Inheritance

When a principal is a **member** of a group, it inherits `ImpactOrgActiveOnly` -- which strips out eligible (PIM) role contributions. This makes sense because mere membership does not grant the ability to activate eligible roles.

When a principal **owns** a group, it inherits the full `Impact` (or `ImpactOrg`) including eligible role contributions. This reflects that an owner can potentially manipulate the group to gain access to eligible role paths.

This asymmetry is intentional and documented in code comments (e.g., line 553: "ownership inherits the group's full impact (active + eligible role paths)").

### 4.5 Managed Identity Fixed Likelihood

Managed Identities have a fixed likelihood of 1 (only `"Base" = 1` defined). This means MI risk scores are essentially equal to their impact scores. The rationale is that MIs are bound to Azure resources and cannot be directly compromised through typical attack vectors (no passwords, no owners, no external credentials).

### 4.6 Unused Constants

Several constants are defined but never used in the scoring logic:

| Module | Constant | Value | Status |
|--------|----------|-------|--------|
| Users | `SyncedFromOnPrem` | 3 | Defined but never referenced |
| Groups | `AzureRole` | 100 | Defined but Azure roles are scored via `Invoke-AzureRoleProcessing` |
| Groups | `HiddenGAL` | 1 | Defined but not visibly consumed |
| Groups | `NestedGroup` | 2 | Defined but not visibly consumed in main loop |
| Managed Identities | `GroupOwner` | 5 | Defined but not explicitly referenced (GroupMember is used) |

---

## 5. Code-to-Report Mapping

This section maps each visible column in the HTML reports to the code that computes it.

### 5.1 Users Report

| Report Column | Code Location | Computation |
|---------------|---------------|-------------|
| DisplayName | `check_Users.psm1` line 975 | Direct from Graph API |
| UPN | `check_Users.psm1` line 977-978 | Direct from Graph API, HTML link wrapping |
| Enabled | `check_Users.psm1` line 979 | `$item.AccountEnabled` |
| UserType | `check_Users.psm1` line 980 | `$item.UserType` (Member/Guest) |
| OnPrem | `check_Users.psm1` line 983 | `$item.OnPremisesSyncEnabled` |
| EntraRoles | `check_Users.psm1` line 960 | Sum of direct + group ownership + group membership role counts |
| EntraMaxTier | `check_Users.psm1` lines 940-942 | `Merge-HigherTierLabel` across direct, group ownership, group membership |
| AzureRoles | `check_Users.psm1` lines 962-966 | Sum of direct + group ownership + group membership Azure role counts |
| AzureMaxTier | `check_Users.psm1` lines 944-950 | `Merge-HigherTierLabel` across direct, group ownership, group membership |
| Impact | `check_Users.psm1` line 339 + accumulation | Accumulated `$Impact` variable |
| Likelihood | `check_Users.psm1` line 340 + accumulation | Accumulated `$Likelihood` variable |
| Risk | `check_Users.psm1` line 970 | `[math]::Round($Impact * $Likelihood)` |
| Warnings | `check_Users.psm1` lines 952-957 | Joined HashSet of warning strings |

### 5.2 Groups Report

| Report Column | Code Location | Computation |
|---------------|---------------|-------------|
| DisplayName | `check_Groups.psm1` line 1241 | Direct from Graph API |
| Type | `check_Groups.psm1` lines 848-856 | M365/Distribution/Security based on properties |
| Visibility | `check_Groups.psm1` line 1244 | `$group.Visibility` (Private/Public) |
| RoleAssignable | `check_Groups.psm1` line 1245 | `$group.IsAssignableToRole` |
| EntraRoles | `check_Groups.psm1` line 1251 | Count of direct role assignments |
| EntraMaxTier | `check_Groups.psm1` line 1252 | `Get-HighestTierLabel` on role details |
| AzureRoles | `check_Groups.psm1` line 1257 | Direct Azure role count |
| AzureMaxTier | `check_Groups.psm1` line 1258 | `Get-HighestTierLabel` on Azure role details |
| CAPs | `check_Groups.psm1` line 1256 | Count of CAPs referencing this group |
| Users | `check_Groups.psm1` line 1262 | `$memberuser.count` |
| Protected | `check_Groups.psm1` line 1288 | Boolean from protection logic |
| Impact | `check_Groups.psm1` line 1293 | `[math]::Round($ImpactScore, 1)` |
| ImpactOrg | `check_Groups.psm1` line 1294 | `[math]::Round($ImpactScore)` (integer version for downstream use) |
| ImpactOrgActiveOnly | `check_Groups.psm1` line 1236 | `Round(Max(0, Impact - EligibleRoleImpact))` |
| Likelihood | `check_Groups.psm1` line 1296 | `[math]::Round($LikelihoodScore, 1)` |
| Risk | `check_Groups.psm1` line 1292 | `[math]::Ceiling($ImpactScore * $LikelihoodScore)` |

### 5.3 Enterprise Apps Report

| Report Column | Code Location | Computation |
|---------------|---------------|-------------|
| DisplayName | `check_EnterpriseApps.psm1` line 1150 | Direct from Graph API |
| Foreign | `check_EnterpriseApps.psm1` line 1173 | `$ForeignTenant` boolean |
| DefaultMS | `check_EnterpriseApps.psm1` line 1174 | Boolean from MS tenant ID check |
| Enabled | `check_EnterpriseApps.psm1` line 1151 | `$item.accountEnabled` |
| EntraRoles | `check_EnterpriseApps.psm1` line 1160 | Direct + group membership + group ownership |
| EntraMaxTier | `check_EnterpriseApps.psm1` line 1161 | Merged tier across all paths |
| AzureRoles | `check_EnterpriseApps.psm1` line 1177 | Direct + group membership + group ownership |
| ApiDangerous..ApiMisc | `check_EnterpriseApps.psm1` lines 1203-1207 | Counts from `$AppApiPermission` grouping |
| ApiDelegated | `check_EnterpriseApps.psm1` line 1196 | Unique delegated permission count |
| Impact | `check_EnterpriseApps.psm1` line 1208 | Raw `$ImpactScore` |
| Likelihood | `check_EnterpriseApps.psm1` line 1209 | Raw `$LikelihoodScore` |
| Risk | `check_EnterpriseApps.psm1` line 1210 | `$ImpactScore * $LikelihoodScore` (raw) |
| *Post-processed Risk* | `check_EnterpriseApps.psm1` lines 1236/1248/1268/1280 | `Round(Impact * Likelihood)` after ownership chain adjustments |

### 5.4 Managed Identities Report

| Report Column | Code Location | Computation |
|---------------|---------------|-------------|
| DisplayName | `check_ManagedIdentities.psm1` line 666 | Direct from Graph API |
| IsExplicit | `check_ManagedIdentities.psm1` line 684 | User-assigned vs system-assigned |
| EntraRoles | `check_ManagedIdentities.psm1` line 673 | Direct + group membership + group ownership |
| EntraMaxTier | `check_ManagedIdentities.psm1` line 674 | Merged tier |
| AzureRoles | `check_ManagedIdentities.psm1` line 690 | Direct + group membership + group ownership |
| AppRoles | `check_ManagedIdentities.psm1` line 697 | **Always 0** (bug: `$MatchingAppRoles` undefined) |
| Impact | `check_ManagedIdentities.psm1` line 704 | Raw `$ImpactScore` |
| Likelihood | `check_ManagedIdentities.psm1` line 705 | Raw `$LikelihoodScore` (effectively always 1) |
| Risk | `check_ManagedIdentities.psm1` line 706 | `$ImpactScore * $LikelihoodScore` (raw, no rounding) |

### 5.5 App Registrations Report

| Report Column | Code Location | Computation |
|---------------|---------------|-------------|
| DisplayName | `check_AppRegistrations.psm1` line 627 | Direct from Graph API |
| AppLock | `check_AppRegistrations.psm1` lines 556-560 | Boolean from `ServicePrincipalLockConfiguration` |
| Owners | `check_AppRegistrations.psm1` line 632 | User owners + SP owners |
| SecretsCount | `check_AppRegistrations.psm1` line 634 | `($AppCredentialsSecrets).Count` |
| CertsCount | `check_AppRegistrations.psm1` line 635 | `($AppCredentialsCertificates).Count` |
| CloudAppAdmins | `check_AppRegistrations.psm1` line 645 | Scoped + tenant Cloud App Admins |
| AppAdmins | `check_AppRegistrations.psm1` line 646 | Scoped + tenant App Admins |
| Impact | `check_AppRegistrations.psm1` line 651 | `[math]::Round($ImpactScore)` (inherited from SP) |
| Likelihood | `check_AppRegistrations.psm1` line 652 | `[math]::Round($LikelihoodScore, 1)` |
| Risk | `check_AppRegistrations.psm1` line 650 | `[math]::Round($ImpactScore * $LikelihoodScore)` |

---

## 6. Summary Dashboard Mapping

The summary page (`export_Summary.psm1` lines 339-488) renders Chart.js charts from `$GlobalAuditSummary` values. Each chart's data source is interpolated directly into JavaScript.

Key risk: if any `$GlobalAuditSummary` sub-property is `$null`, the interpolation produces invalid JavaScript (empty value in object literal). See code review Finding 17.

### Chart Data Sources

| Chart | Data Source | Module That Populates It |
|-------|------------|-------------------------|
| Users General | `$GlobalAuditSummary.Users.Count`, `.Guests` | `check_Users.psm1` |
| Users Enabled | `$GlobalAuditSummary.Users.Enabled` | `check_Users.psm1` |
| Users OnPrem | `$GlobalAuditSummary.Users.OnPrem` | `check_Users.psm1` |
| Users MFA | `$GlobalAuditSummary.Users.MfaCapable` | `check_Users.psm1` |
| Groups General | `$GlobalAuditSummary.Groups.Count`, `.M365` | `check_Groups.psm1` |
| Enterprise Apps | `$GlobalAuditSummary.EnterpriseApps.Count`, `.Foreign` | `check_EnterpriseApps.psm1` |
| App Registrations | `$GlobalAuditSummary.AppRegistrations.Count` | `check_AppRegistrations.psm1` |
| Managed Identities | `$GlobalAuditSummary.ManagedIdentities.Count` | `check_ManagedIdentities.psm1` |
| Entra Roles | `$GlobalAuditSummary.EntraRoleAssignments.*` | `check_Roles.psm1` |
| Azure Roles | `$GlobalAuditSummary.AzureRoleAssignments.*` | `check_Roles.psm1` |
