# EntraFalcon Scoring System

## Core Philosophy

EntraFalcon uses a **Risk = Impact x Likelihood** model to prioritize objects within each report.

- **Impact** measures how much privilege or permission an object possesses. A Global Admin user has high Impact; a user with no roles has low Impact.
- **Likelihood** measures how easily the object can be compromised or influenced. A user synced from on-premises with no MFA has high Likelihood; a cloud-only user protected by a role-assignable group has low Likelihood.
- **Risk** is the product of Impact and Likelihood. It is used exclusively for sorting rows within a single report. Risk scores are **not comparable across different object types** (e.g., a User Risk of 500 is not equivalent to a Group Risk of 500).

Each module defines its own local impact/likelihood weight tables. A shared global weight table (`$GLOBALImpactScore` in `shared_Functions.psm1`) governs role-tier scoring that is reused across all modules via `Invoke-EntraRoleProcessing` and `Invoke-AzureRoleProcessing`.

---

## Global Impact Weights

Defined in `/modules/shared_Functions.psm1` as `$GLOBALImpactScore`:

| Key                      | Weight | Description                                |
|--------------------------|--------|--------------------------------------------|
| `EntraRoleTier0`         | 2000   | Entra ID Tier-0 role (e.g., Global Admin)  |
| `EntraRoleTier1`         | 400    | Entra ID Tier-1 role                       |
| `EntraRoleTier2`         | 80     | Entra ID Tier-2 role                       |
| `EntraRoleTier?Privileged` | 100  | Uncategorized Entra role marked privileged |
| `EntraRoleTier?`         | 80     | Uncategorized Entra role (not privileged)  |
| `AzureRoleTier0`         | 200    | Azure IAM Tier-0 role (e.g., Owner)        |
| `AzureRoleTier1`         | 70     | Azure IAM Tier-1 role                      |
| `AzureRoleTier2`         | 50     | Azure IAM Tier-2 role                      |
| `AzureRoleTier3`         | 10     | Azure IAM Tier-3 role                      |
| `AzureRoleTier?`         | 50     | Uncategorized Azure role                   |

These weights are additive: if an object holds two Tier-0 Entra roles, its Impact increases by 4000 from those roles alone. Both `Invoke-EntraRoleProcessing` and `Invoke-AzureRoleProcessing` iterate over each assigned role, look up the tier, apply the corresponding weight, and return a cumulative `ImpactScore`. They also track an `EligibleImpactScore` (the portion attributable to PIM-eligible-only assignments) for downstream inheritance calculations.

---

## Per-Module Scoring

### Users (`check_Users.psm1`)

**Impact Weights (local `$UserImpact`):**

| Key                    | Value | When Applied                                      |
|------------------------|-------|---------------------------------------------------|
| `Base`                 | 1     | Every user starts with Impact = 1                 |
| `DirectAppRoleNormal`  | 10    | Per non-sensitive AppRole directly assigned        |
| `DirectAppRoleSensitive` | 50  | Per AppRole matching "admin" or "critical"         |
| `SpOwnAppLock`         | 20    | Cap on inherited SP Impact when AppLock is enabled |

**Impact Inheritance:**

- **Entra roles:** Via `Invoke-EntraRoleProcessing`. Each role adds its tier weight.
- **Azure roles:** Via `Invoke-AzureRoleProcessing`. Each role adds its tier weight.
- **Owned Service Principals:** If AppLock is `false` or unknown, the full SP Impact is added. If AppLock is `true`, `min(SP.Impact, 20)` is added.
- **Owned App Registrations:** The full AppReg Impact is added per owned registration.
- **Owned Groups:** The full group Impact is added per owned group.
- **Group Memberships:** The group Impact is added, then a CAP correction is applied: `Impact -= (ObjectsWithCaps * 50)`. This prevents CAP assignments from inflating a member's score, since CAP influence is only relevant to group owners, not members.
- **Direct AppRoles:** +50 per sensitive role (matching "admin" or "critical" in name/description), +10 per normal role.

**Likelihood Weights (local `$UserLikelihood`):**

| Key                | Value | When Applied                                        |
|--------------------|-------|-----------------------------------------------------|
| `Base`             | 5     | Every user starts with Likelihood = 5               |
| `SyncedFromOnPrem` | 3     | User has `OnPremisesSyncEnabled = true`              |
| `Protected`        | -4    | User is in a role-assignable group, restricted AU, or holds a non-unprotected Entra role |
| `NoMFA`            | 10    | User has no MFA capability (excluding sync accounts and AgentUsers) |

**Risk Formula:** `Round(Impact * Likelihood)`

---

### Groups (`check_Groups.psm1`)

**Impact Weights (local `$GroupImpactScore`):**

| Key               | Value | When Applied                     |
|-------------------|-------|----------------------------------|
| `M365Group`       | 1     | Group type is M365 (Unified)     |
| `Distribution`    | 0.5   | Group type is Distribution       |
| `SecurityEnabled` | 2     | Group has `SecurityEnabled=true` |
| `CAP`             | 50    | Per CAP assignment               |
| `AppRole`         | 10    | Group has at least one AppRole   |
| `AzureRole`       | 100   | (defined but applied via `Invoke-AzureRoleProcessing` instead) |

Note: there is no explicit base Impact; it starts at 0.

**Impact Inheritance:**

- Entra/Azure roles are processed through `Invoke-EntraRoleProcessing` / `Invoke-AzureRoleProcessing` using the same global weights.
- CAP assignments add a flat +50 if the group is used in any CAP (one-time bonus, not per-CAP).
- AppRole assignments add +10 if the group has any.
- `EligibleRoleImpactContribution` is tracked separately: it captures the portion of Impact attributable to PIM-eligible (not active) role assignments. This is subtracted to produce `ImpactOrgActiveOnly = max(0, Impact - EligibleRoleImpactContribution)`, which downstream objects (Enterprise Apps, Managed Identities) inherit for memberships.

**Likelihood Weights (local `$GroupLikelihoodScore`):**

| Key                       | Value | When Applied                                             |
|---------------------------|-------|----------------------------------------------------------|
| `DirectOwnerCloud`        | 1     | Any cloud-only user owner exists                         |
| `DirectOwnerOnprem`       | 2     | Any on-prem-synced user owner exists                     |
| `PIMforGroupsOwnersGroup` | 3    | PIM for Groups eligible owner group exists               |
| `BaseNotProtected`        | 5     | Group is not Protected (not on-prem, not role-assignable, not in restricted AU) |
| `PublicM365Group`         | 100   | Public M365 group (non-dynamic)                          |
| `GuestMemberOwner`        | 5     | Guest user is an owner                                   |
| `DynamicGroup`            | 5     | Dynamic group (non-dangerous rule)                       |
| `DynamicGroupDangerous`   | 20    | Dynamic group with potentially dangerous membership rule |
| `ExternalSPMemberOwner`   | 50    | External (non-MS) SP is a member or owner                |
| `InternalSPMemberOwner`   | 5     | Internal (non-MS) SP is a member or owner                |
| `Member`                  | 0.1   | Scaled by `sqrt(MemberUserCount) * 0.1`                 |

Note: Likelihood starts at 0 (no explicit base).

**Risk Formula:** `Ceiling(Impact * Likelihood)`

**Post-Processing:**

Nested groups inherit Impact from parent groups. When a parent group has Entra/Azure roles or CAP assignments and contains nested groups, the parent's role score is added to the nested group's Impact, and the nested group's Risk is recalculated as `Ceiling(Impact * Likelihood)`. The `EntraMaxTier` and `AzureMaxTier` labels are also propagated downward.

---

### Enterprise Apps (`check_EnterpriseApps.psm1`)

**Impact Weights (local `$SPImpactScore`):**

| Key                      | Value | When Applied                                          |
|--------------------------|-------|-------------------------------------------------------|
| `Base`                   | 1     | Every Enterprise App starts with Impact = 1           |
| `APIDangerous`           | 800   | Per Application permission categorized as Dangerous   |
| `APIHigh`                | 400   | Per Application permission categorized as High        |
| `APIMedium`              | 100   | Per Application permission categorized as Medium      |
| `APILow`                 | 50    | Per Application permission categorized as Low         |
| `ApiMisc`                | 20    | Per Application permission categorized as Uncategorized |
| `APIDelegatedDangerous`  | 200   | Once if any Delegated permission is Dangerous         |
| `APIDelegatedHigh`       | 100   | Once if any Delegated permission is High              |
| `APIDelegatedMedium`     | 60    | Once if any Delegated permission is Medium            |
| `APIDelegatedLow`        | 20    | Once if any Delegated permission is Low               |
| `ApiDelegatedMisc`       | 20    | Once if any Delegated permission is Uncategorized     |
| `AppRoleRequired`        | 10    | `AppRoleAssignmentRequired` is true                   |
| `AppRole`                | 2     | Per AppRole assignment count                          |

**Important distinction:** Application (app-only) permissions are scored **per permission** (additive). Delegated permissions are scored **per category** (once per severity level, regardless of how many individual permissions exist at that level).

**Impact Inheritance:**

- Entra/Azure roles via standard processing functions.
- Group membership inherits `ImpactOrgActiveOnly` from each group (active-only, excluding PIM-eligible contributions).
- Group ownership inherits the full `Impact` or `ImpactOrg` from each owned group.

**Likelihood Weights (local `$SPLikelihoodScore`):**

| Key                 | Value | When Applied                                |
|---------------------|-------|---------------------------------------------|
| (no explicit base)  | 0     | Likelihood starts at 0                      |
| `SpWithCredentials` | 5     | SP has configured credentials               |
| `UnknownAppLock`    | 1     | Foreign app (AppLock status unknown)         |
| `NoAppLock`         | 2     | Internal app without AppLock                 |
| `Owners`            | 5     | Per user owner                              |
| `ForeignApp`        | 30    | Foreign non-MS app                          |
| `InternApp`         | 5     | Internal non-MS app                         |

**Risk Formula:** `Impact * Likelihood` (no rounding in initial calculation)

**Post-Processing:**

1. **SP -> AppReg -> SP chains:** If an SP owns an App Registration that corresponds to another SP, the owning SP's Likelihood is added to the owned SP's Likelihood, and the owned SP's Impact is added to the owning SP's Impact. Both have Risk recalculated with `Round()`.
2. **SP -> SP chains:** Direct SP ownership follows the same pattern: likelihood propagates downward, impact propagates upward.

---

### Managed Identities (`check_ManagedIdentities.psm1`)

**Impact Weights (local `$SPImpactScore`):**

| Key              | Value | When Applied                                          |
|------------------|-------|-------------------------------------------------------|
| `Base`           | 1     | Every Managed Identity starts with Impact = 1         |
| `APIDangerous`   | 800   | Per Application permission categorized as Dangerous   |
| `APIHigh`        | 400   | Per Application permission categorized as High        |
| `APIMedium`      | 100   | Per Application permission categorized as Medium      |
| `APILow`         | 50    | Per Application permission categorized as Low         |
| `ApiMisc`        | 20    | Per Application permission categorized as Uncategorized |
| `GroupMember`    | 5     | Base addition if MI is a member of any group          |
| `GroupOwner`     | 5     | (defined; applied contextually)                       |

**Impact Inheritance:**

- Entra/Azure roles via standard processing functions.
- Group membership inherits `ImpactOrgActiveOnly` from each group.
- Group ownership inherits full `Impact` or `ImpactOrg` from each owned group.

**Likelihood:** Fixed at `1` (defined as `$SPLikelihoodScore["Base"] = 1`). No modifiers are applied. This is intentional: Managed Identities authenticate via platform-managed credentials that cannot be phished, leaked, or guessed.

**Risk Formula:** `Impact * 1 = Impact`

---

### App Registrations (`check_AppRegistrations.psm1`)

**Impact:** Starts at 0. The entire Impact score is inherited from the corresponding Enterprise App's Impact score. The lookup matches via `AppId`.

**Likelihood Weights (local `$AppLikelihoodScore`):**

| Key                | Value | When Applied                                          |
|--------------------|-------|-------------------------------------------------------|
| `AppBase`          | 1     | Every App Registration starts with Likelihood = 1     |
| `AppSecret`        | 5     | Per client secret                                     |
| `AppCertificate`   | 2     | Per certificate                                       |
| `EntraConnectIoC`  | 200   | Entra Connect app with secrets or multiple certificates |
| `AppOwner`         | 20    | Per owner (user or SP)                                |
| `AppAdmins`        | 10    | Per Cloud App Admin or Application Admin (tenant-wide + scoped) |
| `InternalSPOwner`  | 5     | Internal SP is an owner                               |
| `ExternalSPOwner`  | 50    | Foreign SP is an owner                                |
| `GuestAsOwner`     | 50    | Guest user is an owner or scoped admin                |

**Risk Formula:** `Round(Impact * Likelihood)`

---

## Scoring Behavior Notes

These are observations about how the scoring system behaves across modules.

1. **Risk rounding varies by module:**
   - Users: `Round(Impact * Likelihood)`
   - Groups: `Ceiling(Impact * Likelihood)`
   - Enterprise Apps: `Impact * Likelihood` (raw multiplication, no rounding during initial processing)
   - Managed Identities: `Impact * Likelihood` (raw; effectively equals Impact since Likelihood = 1)
   - App Registrations: `Round(Impact * Likelihood)`

2. **Application vs. Delegated permission scoring asymmetry (Enterprise Apps):** Application permissions are scored per-permission (each Dangerous permission adds 800). Delegated permissions are scored per-category (only one +200 regardless of whether there are 1 or 50 Dangerous delegated permissions). This means 10 "High" Application permissions add 4000 Impact, but 10 "High" Delegated permissions add only 100.

3. **Managed Identities have fixed Likelihood = 1:** Risk always equals Impact. The Likelihood column provides no differentiating information in the Managed Identities report.

4. **Enterprise Apps post-processing re-rounding:** During post-processing (SP->AppReg->SP and SP->SP chains), Risk is recalculated with `Round()`, creating a potential inconsistency between the initial raw multiplication and the post-processed rounded value.

5. **Group CAP correction for Users:** When a user is a member of a group used in a CAP, the group's CAP Impact (+50) is subtracted from the user's inherited Impact. This prevents CAP assignments from inflating member scores. However, this correction is not applied to Enterprise Apps or Managed Identities that are members of the same groups.

---

## Security Findings Weighted Coverage

The Security Findings report (generated by `check_Tenant.psm1`) uses a separate scoring system for overall tenant posture. Each finding has a severity level with associated point weights:

| Severity | Label    | Points |
|----------|----------|--------|
| 0        | Info     | 0      |
| 1        | Low      | 1      |
| 2        | Medium   | 3      |
| 3        | High     | 7      |
| 4        | Critical | 10     |

**Coverage Calculation:**

```
possiblePoints = sum of severity points for all applicable findings
riskPoints     = sum of severity points for findings marked Vulnerable
Coverage %     = ((possiblePoints - riskPoints) / possiblePoints) * 100
```

Coverage is also calculated per category (e.g., "Conditional Access Policies", "Enterprise Applications") using the same formula scoped to that category's findings.
