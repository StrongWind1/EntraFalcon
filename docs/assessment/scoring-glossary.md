
# Scoring Glossary

This glossary defines every scoring-related term and report column used across all EntraFalcon modules.

---

## Global Terms

| Term | Definition |
|------|-----------|
| Impact | Numeric score representing privilege/permission severity. Computed by summing base values, role weights, API permission weights, and inherited values from owned/member objects. Higher = more powerful. |
| Likelihood | Numeric score representing ease of compromise. Factors include credential exposure, on-premises sync, lack of MFA, public visibility, and ownership by external entities. Higher = easier to exploit. |
| Risk | Impact x Likelihood. Used for sorting within a single report. Risk scores are not comparable across different object types (different bases, formulas, rounding). |
| Protected | Object is in a role-assignable group, restricted Admin Unit (`IsMemberManagementRestricted = true`), or has a direct Entra role that is not in the "unprotected roles" list (for users). Protected status reduces Likelihood for users (-4) and prevents the base "not protected" Likelihood addition for groups (+5 is skipped). |
| Tier-0 | Most powerful roles (e.g., Global Administrator, Privileged Role Administrator, Owner). Score weight: Entra = 2000, Azure = 200. |
| Tier-1 | Significant admin roles (e.g., User Administrator, Exchange Administrator, Contributor). Score weight: Entra = 400, Azure = 70. |
| Tier-2 | Limited admin roles (e.g., Global Reader, Reader). Score weight: Entra = 80, Azure = 50. |
| Tier-3 | Minimal-impact roles (Azure only, e.g., VM User Login). Score weight: Azure = 10. |
| Dangerous | API permission that can directly escalate to Global Administrator (e.g., `RoleManagement.ReadWrite.Directory`). Application weight: 800 per permission. |
| High | API permission with significant tenant-wide impact (e.g., `Directory.ReadWrite.All`). Application weight: 400 per permission. |
| Medium | API permission with user-data or configuration access. Application weight: 100 per permission. |
| Low | Minimal API permission. Application weight: 50 per permission. |
| Uncategorized | API permission not in the categorization lookup. Application weight: 20 per permission. |
| EligibleRoleImpactContribution | The portion of a group's Impact score attributable to PIM-eligible (not permanently active) role assignments. Used to compute `ImpactOrgActiveOnly` so downstream objects do not double-count eligible roles. |
| ImpactOrgActiveOnly | `max(0, Impact - EligibleRoleImpactContribution)`. Group Impact excluding PIM-eligible roles. Enterprise Apps and Managed Identities inherit this value through membership (not ownership). |
| ImpactOrg | The group's raw Impact score (rounded integer). Used by downstream objects inheriting impact through group ownership. |

### Special Symbols

| Symbol | Meaning |
|--------|---------|
| `?` | Data was not assessed. The corresponding check was skipped (e.g., Azure IAM not checked, MFA capabilities not retrieved, PIM for Groups not assessed). |
| `-` | Not applicable or no data. For example, a user who has never signed in shows `-` for LastSignInDays. A group with no roles shows `-` for MaxTier. |
| `0` | Explicitly zero. The check was performed and found no matching items. |

---

## Users Report Fields

Source: `check_Users.psm1`

**Impact base**: 1
**Likelihood base**: 5

| Field | Type | Affects Score? | Definition |
|-------|------|---------------|-----------|
| UPN | String | No | User Principal Name. |
| Enabled | Boolean | No | Account enabled status (`AccountEnabled`). |
| UserType | String | No | `Member` or `Guest`. |
| Agent | Boolean | No | Whether user is an Agent Identity type (`agentUser`). Excluded from NoMFA penalty. |
| OnPrem | Boolean | Likelihood (+3) | Synced from on-premises Active Directory (`OnPremisesSyncEnabled`). |
| LicenseStatus | String | No | `Licensed` or `Unlicensed` based on `AssignedLicenses` count. |
| Protected | Boolean | Likelihood (-4) | In role-assignable group, restricted AU, or has qualifying Entra role (excluding Guest Inviter, Helpdesk Admin, Password Admin, etc.). |
| GrpMem | Integer | Impact | Count of transitive group memberships. Group Impact inherited. |
| GrpOwn | Integer | Impact | Count of group ownerships. Group Impact inherited. |
| AuUnits | Integer | Indirectly | Count of Administrative Units the user belongs to. Restricted AUs set Protected. |
| EntraRoles | Integer | Impact | Count of Entra ID role assignments (direct + through group membership + through group ownership). Each role adds its tier weight to Impact. |
| EntraMaxTier | String | No | Highest (lowest number) Entra role tier across all paths: Tier-0 > Tier-1 > Tier-2 > ? > -. |
| AzureRoles | Integer | Impact | Count of Azure IAM role assignments (direct + through groups). `?` if Azure checks not performed. |
| AzureMaxTier | String | No | Highest Azure role tier. `?` if not assessed. |
| AppRoles | Integer | Impact | Count of AppRoles directly assigned to the user. +50 per sensitive role, +10 per normal role. |
| AppRegOwn | Integer | Impact | Count of owned App Registrations. AppReg Impact inherited. |
| SPOwn | Integer | Impact | Count of owned Enterprise Applications (Service Principals). SP Impact inherited, modulated by AppLock (capped at +20 if AppLock is true). |
| DeviceOwn | Integer | No | Count of devices the user owns. |
| DeviceReg | Integer | No | Count of devices the user has registered. |
| Inactive | Boolean | No | No sign-in for 180+ days (or never signed in and account older than 180 days). `?` if sign-in data unavailable. |
| LastSignInDays | Integer | No | Days since last successful sign-in. `-` if never signed in. `?` if permission unavailable. |
| CreatedDays | Integer | No | Days since account creation. |
| MfaCap | Boolean | Likelihood (+10 if false) | Whether user has any MFA method registered. Penalty does not apply to sync accounts or agent users. `?` if not checked. |
| PerUserMfa | String | No | Per-user MFA state from the `/users` endpoint: `enforced`, `enabled`, `disabled`, or `-`. |
| Impact | Numeric | -- | Computed impact score, rounded to integer. |
| Likelihood | Numeric | -- | Computed likelihood score, rounded to 1 decimal. |
| Risk | Numeric | -- | `Round(Impact * Likelihood)`. |
| Warnings | String | No | Concatenated warning strings separated by ` / `. Describes ownership of SPs, AppRegs, groups, role assignments, sync account status, etc. |

---

## Groups Report Fields

Source: `check_Groups.psm1`

**Impact base**: 0 (computed from group type and assignments)
**Likelihood base**: 0 (computed from properties)

| Field | Type | Affects Score? | Definition |
|-------|------|---------------|-----------|
| DisplayName | String | No | Group display name. |
| Type | String | Impact | `M365 Group` (+1), `Security Group` (0), or `Distribution` (+0.5). Security-enabled groups additionally receive +2 Impact. |
| SecurityEnabled | Boolean | Impact (+2) | Whether the group is security-enabled. |
| RoleAssignable | Boolean | Indirectly | Whether the group can be assigned Entra roles (`IsAssignableToRole`). Sets Protected. |
| OnPrem | Boolean | Indirectly | Synced from on-premises. Sets Protected. |
| Dynamic | Boolean | Likelihood | Whether the group uses dynamic membership rules. +5 Likelihood (basic), +20 Likelihood if rule uses dangerous attributes (e.g., `businessPhones`, `mobilePhone`, `preferredLanguage`). |
| Visibility | String | Likelihood | `Public`, `Private`, or `HiddenMembership`. +100 Likelihood if Public M365 Group (non-dynamic). +1 if `HiddenMembership` (HiddenGAL). |
| Protected | Boolean | Likelihood | True if on-prem synced, role-assignable, or in a restricted AU. +5 Likelihood if NOT Protected. |
| PIM | Boolean | No | Whether the group is onboarded in PIM for Groups. `?` if not assessed. |
| AuUnits | Integer | Indirectly | Count of Administrative Units. Restricted AUs set Protected. |
| DirectOwners | Integer | Likelihood | Count of direct owners (users + SPs + PIM-eligible owner groups). +2 Likelihood per synced owner, +1 per cloud owner, +3 per PIM-for-Groups owner group. |
| NestedOwners | Integer | No | Count of inherited owners through group nesting (computed in post-processing). |
| OwnersSynced | Integer | Likelihood | Count of user owners synced from on-premises. |
| Users | Integer | Likelihood | Count of transitive user members. `sqrt(count) * 0.1` added to Likelihood. |
| Guests | Integer | Likelihood | Count of guest user members. +5 Likelihood if any guest is an owner. |
| SPCount | Integer | Likelihood | Count of SP members/owners. +50 Likelihood for external non-MS SP member/owner (`ExternalSPMemberOwner`), +5 for internal SP (`InternalSPMemberOwner`). |
| Devices | Integer | No | Count of device members. |
| NestedGroups | Integer | Likelihood | Count of child groups nested inside this group. +2 Likelihood per nested group. |
| NestedInGroups | Integer | No | Count of parent groups this group is nested in. |
| AppRoles | Integer | Impact (+10) | Count of AppRole assignments. +10 Impact per assignment. |
| CAPs | Integer | Impact (+50) | Count of Conditional Access Policy references. +50 Impact per CAP. `?` if not assessed. |
| EntraRoles | Integer | Impact | Count of Entra role assignments (direct + inherited from nesting in post-processing). Tier weights added to Impact. |
| EntraMaxTier | String | No | Highest Entra role tier (including post-processing inheritance). |
| AzureRoles | Integer | Impact | Count of Azure IAM roles. `?` if not assessed. +100 Impact per role assignment. |
| AzureMaxTier | String | No | Highest Azure role tier. `?` if not assessed. |
| Impact | Numeric | -- | Calculated Impact score, rounded to 1 decimal. |
| Likelihood | Numeric | -- | Calculated Likelihood score, rounded to 1 decimal. |
| Risk | Numeric | -- | `Ceiling(Impact * Likelihood)`. |
| Warnings | String | No | Concatenated warning messages. Describes public groups, dynamic rules, CAP usage, SP members/owners, role assignments, PIM for Groups nesting, etc. |

---

## Enterprise Apps Report Fields

Source: `check_EnterpriseApps.psm1`

**Impact base**: 1
**Likelihood base**: 0

| Field | Type | Affects Score? | Definition |
|-------|------|---------------|-----------|
| DisplayName | String | No | Enterprise App display name. |
| AppRoleRequired | Boolean | Impact (+10) | Whether `AppRoleAssignmentRequired` is set. |
| PublisherName | String | No | Publisher name from SP metadata. |
| DefaultMS | Boolean | Likelihood | Whether the app is a default Microsoft application. If false, Likelihood increases. |
| Foreign | Boolean | Likelihood (+30) | Whether the app is from a different tenant. +30 if foreign non-MS, +5 if internal non-MS. |
| Enabled | Boolean | No | Whether the SP is enabled (`accountEnabled`). |
| Inactive | Boolean | No | `true` if last sign-in >= 180 days ago or no sign-in data. |
| SAML | Boolean | No | Whether `preferredSingleSignOnMode` is `saml`. |
| LastSignInDays | Integer | No | Days since last sign-in. `-` if no data. |
| CreationInDays | Integer | No | Days since creation. |
| Owners | Integer | Likelihood (+5) | Total owner count (users + SPs). +5 Likelihood per user owner. |
| Credentials | Integer | Likelihood (+5) | Count of configured credentials (secrets + certificates). +5 Likelihood if any (SpWithCredentials). |
| AppLock | Boolean | Likelihood | App Instance Property Lock status. +2 Likelihood if no lock (NoAppLock), +1 if unknown (UnknownAppLock). |
| AppRoles | Integer | Impact (+2) | Count of AppRole assignments to this SP. +2 Impact per AppRole. |
| GrpMem | Integer | Impact | Count of group memberships (transitive). Inherits `ImpactOrgActiveOnly` from each group. |
| GrpOwn | Integer | Impact | Count of owned groups. Inherits full Impact or ImpactOrg from each group. |
| AppOwn | Integer | Indirectly | Count of owned App Registrations. |
| SpOwn | Integer | Indirectly | Count of owned Service Principals. |
| EntraRoles | Integer | Impact | Total effective Entra role count (direct + through group membership + through group ownership). Tier weights added to Impact. |
| EntraMaxTier | String | No | Highest Entra role tier across all paths. |
| AzureRoles | Integer | Impact | Total effective Azure role count. `?` if not assessed. Tier weights added to Impact. |
| AzureMaxTier | String | No | Highest Azure role tier. `?` if not assessed. |
| ApiDangerous | Integer | Impact (+800/ea) | Count of Application permissions categorized as Dangerous. +800 Impact per permission. |
| ApiHigh | Integer | Impact (+400/ea) | Count of Application permissions categorized as High. +400 Impact per permission. |
| ApiMedium | Integer | Impact (+100/ea) | Count of Application permissions categorized as Medium. +100 Impact per permission. |
| ApiLow | Integer | Impact (+50/ea) | Count of Application permissions categorized as Low. +50 Impact per permission. |
| ApiMisc | Integer | Impact (+20/ea) | Count of Application permissions categorized as Uncategorized. +20 Impact per permission. |
| ApiDelegated | Integer | No | Count of unique Delegated permission scopes (informational). |
| ApiDelegatedDangerous | Integer | Impact (+200 once) | Count of Delegated permissions at Dangerous level. +200 Impact if category present (per-category, not per-permission). |
| ApiDelegatedHigh | Integer | Impact (+100 once) | Count of Delegated permissions at High level. +100 Impact if category present. |
| ApiDelegatedMedium | Integer | Impact (+60 once) | Count of Delegated permissions at Medium level. +60 Impact if category present. |
| ApiDelegatedLow | Integer | Impact (+20 once) | Count of Delegated permissions at Low level. +20 Impact if category present. |
| ApiDelegatedMisc | Integer | Impact (+20 once) | Count of Delegated permissions at Uncategorized level. +20 Impact if category present. |
| Impact | Numeric | -- | Calculated Impact score. |
| Likelihood | Numeric | -- | Calculated Likelihood score. |
| Risk | Numeric | -- | `Round(Impact * Likelihood)` after post-processing. |
| Warnings | String | No | Concatenated warning messages. Describes API permissions, ownership, credentials, foreign status, etc. |

---

## Managed Identities Report Fields

Source: `check_ManagedIdentities.psm1`

**Impact base**: 1
**Likelihood base**: 1 (fixed -- never changes)

| Field | Type | Affects Score? | Definition |
|-------|------|---------------|-----------|
| DisplayName | String | No | Managed Identity display name. |
| IsExplicit | Boolean | No | Whether the MI is user-assigned (explicit) vs. system-assigned. Parsed from `AlternativeNames`. |
| MiPath | String | No | Azure resource path the MI is associated with (from `AlternativeNames`). |
| CreationInDays | Integer | No | Days since creation. |
| GroupMembership | Integer | Impact (+5 base) | Count of group memberships (transitive). +5 base Impact for any membership, plus inherits `ImpactOrgActiveOnly`. |
| GroupOwnership | Integer | Impact | Count of owned groups. Inherits full Impact or ImpactOrg. |
| AppOwnership | Integer | No | Count of owned App Registrations (informational warning). |
| SpOwn | Integer | No | Count of owned Service Principals (informational warning). |
| EntraRoles | Integer | Impact | Total effective Entra role count. Tier weights added to Impact. |
| EntraMaxTier | String | No | Highest Entra role tier. |
| AzureRoles | Integer | Impact | Total effective Azure role count. `?` if not assessed. Tier weights added to Impact. |
| AzureMaxTier | String | No | Highest Azure role tier. `?` if not assessed. |
| AppRoles | Integer | No | Count of app role assignments. |
| ApiDangerous | Integer | Impact (+800/ea) | Count of Application permissions at Dangerous level. |
| ApiHigh | Integer | Impact (+400/ea) | Count of Application permissions at High level. |
| ApiMedium | Integer | Impact (+100/ea) | Count of Application permissions at Medium level. |
| ApiLow | Integer | Impact (+50/ea) | Count of Application permissions at Low level. |
| ApiMisc | Integer | Impact (+20/ea) | Count of Application permissions at Uncategorized level. |
| Impact | Numeric | -- | Calculated Impact score. Equals Risk since Likelihood is always 1. |
| Likelihood | Numeric | -- | Always `1`. Fixed value. |
| Risk | Numeric | -- | `Impact * 1 = Impact`. |
| Warnings | String | No | Concatenated warning messages. Describes API permissions, roles, group memberships, ownership, etc. |

---

## App Registrations Report Fields

Source: `check_AppRegistrations.psm1`

**Impact base**: 0 (inherited entirely from corresponding Enterprise App)
**Likelihood base**: 1

| Field | Type | Affects Score? | Definition |
|-------|------|---------------|-----------|
| DisplayName | String | No | App Registration display name. |
| SignInAudience | String | No | Sign-in audience setting (e.g., `AzureADMyOrg`, `AzureADMultipleOrgs`, `AzureADandPersonalMicrosoftAccount`). |
| Enabled | Boolean | No | Inverse of `isDisabled`. |
| AppLock | Boolean | No | Whether App Instance Property Lock is enabled with full protection. Affects Likelihood of the corresponding Enterprise App's owners, not the AppReg itself. |
| CreationInDays | Integer | No | Days since creation. |
| AppRoles | Integer | No | Count of defined App Roles (not assigned roles). |
| Owners | Integer | Likelihood (+20/ea) | Count of owners (users + SPs). +20 Likelihood per owner. |
| FederatedCreds | Integer | No | Count of Federated Identity Credentials. |
| CloudAppAdmins | Integer | Likelihood (+10/ea) | Count of Cloud Application Administrators (tenant-wide + scoped to this app). +10 Likelihood per admin. |
| AppAdmins | Integer | Likelihood (+10/ea) | Count of Application Administrators (tenant-wide + scoped to this app). +10 Likelihood per admin. |
| SecretsCount | Integer | Likelihood (+5/ea) | Count of client secrets. +5 Likelihood per secret. +200 for Entra Connect IoC pattern. |
| CertsCount | Integer | Likelihood (+2/ea) | Count of certificates. +2 Likelihood per certificate. |
| Impact | Numeric | -- | Inherited from the corresponding Enterprise App's Impact score. AppReg starts at 0. |
| Likelihood | Numeric | -- | Calculated Likelihood score, rounded to 1 decimal. |
| Risk | Numeric | -- | `Round(Impact * Likelihood)`. |
| Warnings | String | No | Concatenated warning messages. Describes Entra Connect status, IoC indicators, owner types, federated credentials, redirect URIs, etc. |

---

## Entra Roles Report Fields

Source: `check_Roles.psm1`

| Field | Type | Definition |
|-------|------|-----------|
| RoleName | String | Entra ID role display name. |
| PrincipalName | String | Name of the principal (user, group, SP, MI) assigned to the role. Links to the corresponding report. |
| PrincipalType | String | Type of the assigned principal: User, Group, Enterprise Application, Managed Identity, etc. |
| AssignmentType | String | `Active` or `Eligible`. |
| RoleTier | String | Tier classification: Tier-0, Tier-1, Tier-2, or ? (unknown/custom). |
| RoleType | String | `BuiltInRole` or `CustomRole`. |
| Privileged | Boolean | Whether the role is classified as privileged. |
| Scope | String | Directory scope: `/ (Tenant)` for tenant-wide, or the scoped object path. |

---

## Azure Roles Report Fields

Source: `check_Roles.psm1`

| Field | Type | Definition |
|-------|------|-----------|
| RoleName | String | Azure IAM role display name. |
| PrincipalName | String | Name of the assigned principal. |
| PrincipalType | String | Principal type (User, Group, ServicePrincipal, etc.). |
| AssignmentType | String | `Active` or `Eligible`. |
| RoleTier | String | Tier classification: Tier-0, Tier-1, Tier-2, Tier-3, or ? (unknown/custom). |
| RoleType | String | `BuiltInRole` or `CustomRole`. |
| Conditions | Boolean | Whether additional conditions (e.g., ABAC) are applied to the assignment. |
| Scope | String | Azure resource scope (subscription, resource group, resource). |

---

## PIM Settings Report Fields

Source: `check_PIM.psm1`

| Field | Type | Definition |
|-------|------|-----------|
| RoleName | String | Entra ID role display name. |
| RoleTier | String | Tier classification of the role. |
| ActiveAssignments | Integer | Count of permanent active assignments. |
| EligibleAssignments | Integer | Count of eligible (PIM-managed) assignments. |
| LinkedCAPs | Integer | Count of Conditional Access policies linked to the role via authentication context. |
| CapIssues | Boolean | Whether linked CAPs have detected issues. |
| ActivationDuration | String | Maximum activation duration (e.g., `4 Hours`, `8 Hours`). |
| ActivationRequireMFA | Boolean | Whether MFA is required on activation. |
| ActivationRequireJustification | Boolean | Whether justification is required on activation. |
| ActivationRequireApproval | Boolean | Whether approval is required on activation. |
| ActivationRequireAuthContext | Boolean | Whether authentication context is required on activation. |
| ActiveAssignmentRequireJustification | Boolean | Whether justification is required for permanent active assignments. |
| ActiveAssignmentRequireMFA | Boolean | Whether MFA is required for permanent active assignments. |
| PermanentActiveAssignment | Boolean | Whether permanent active assignments are allowed. |
| PermanentEligibleAssignment | Boolean | Whether permanent eligible assignments are allowed. |
| NotifyOnActivation | String | Notification settings for role activation. |
| NotifyOnActiveAssignment | String | Notification settings for active assignment creation. |
| NotifyOnEligibleAssignment | String | Notification settings for eligible assignment creation. |
| Warnings | String | Concatenated warning strings. |

---

## Scoring Weight Reference

### Entra Role Tier Weights (used in `Invoke-EntraRoleProcessing`)

| Tier | Weight |
|------|--------|
| Tier-0 | 2000 |
| Tier-1 | 400 |
| Tier-2 | 80 |
| ? (Custom/Unknown) | 80 |

### Azure Role Tier Weights (used in `Invoke-AzureRoleProcessing`)

| Tier | Weight |
|------|--------|
| Tier-0 | 200 |
| Tier-1 | 70 |
| Tier-2 | 50 |
| Tier-3 | 10 |
| ? (Custom/Unknown) | 50 |

### Application API Permission Weights (Enterprise Apps and Managed Identities)

| Category | Application Weight (per-permission) | Delegated Weight (per-category, once) |
|----------|-------------------------------------|---------------------------------------|
| Dangerous | 800 | 200 |
| High | 400 | 100 |
| Medium | 100 | 60 |
| Low | 50 | 20 |
| Uncategorized | 20 | 20 |

### User-Specific Weights

| Factor | Weight |
|--------|--------|
| Base Impact | 1 |
| Base Likelihood | 5 |
| OnPrem synced | +3 Likelihood |
| Protected | -4 Likelihood |
| No MFA capability | +10 Likelihood |
| Direct AppRole (normal) | +10 Impact |
| Direct AppRole (sensitive) | +50 Impact |
| SP ownership with AppLock | +20 Impact (capped) |

### Group-Specific Weights

| Factor | Weight |
|--------|--------|
| M365 Group type | +1 Impact |
| Distribution type | +0.5 Impact |
| HiddenGAL | +1 Impact |
| Security-enabled | +2 Impact |
| Azure role on group | +100 Impact |
| AppRole on group | +10 Impact |
| CAP reference | +50 Impact |
| Public M365 Group | +100 Likelihood |
| Per member | +0.1 Likelihood |
| Direct owner (cloud) | +1 Likelihood |
| Direct owner (on-prem) | +2 Likelihood |
| PIM for Groups owner group | +3 Likelihood |
| Nested group | +2 Likelihood |
| Dynamic group (basic) | +5 Likelihood |
| Dynamic group (dangerous) | +20 Likelihood |
| External SP member/owner | +50 Likelihood |
| Internal SP member/owner | +5 Likelihood |
| Not Protected | +5 Likelihood |
| Guest as member/owner | +5 Likelihood |
