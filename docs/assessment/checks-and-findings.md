
# Security Findings Reference

## Overview

EntraFalcon performs 62 automated security checks across 9 categories. Results are presented in an interactive Security Findings report with severity ratings, descriptions, threats, and remediation guidance.

Source: `check_Tenant.psm1`

### Severity Levels

| Level | Weight | Meaning |
|-------|--------|---------|
| 3 (Critical/High) | 10 | Significant security risk requiring immediate attention. |
| 2 (Medium) | 3 | Moderate security concern that should be addressed. |
| 1 (Low) | 1 | Minor security improvement opportunity. |
| 0 (Info) | 0 | Informational finding with no risk weight. |

### Weighted Coverage Formula

```
Coverage = ((possiblePoints - riskPoints) / possiblePoints) * 100%
```

Where `possiblePoints` sums the severity weight of all non-skipped findings, and `riskPoints` sums the severity weight of all Vulnerable findings. Coverage is also calculated per category.

### Default Status

- **CAP-001 through CAP-010**: Default to **Vulnerable** (must be disproven by finding a matching Conditional Access policy).
- **CAP-011**: Defaults to **NotVulnerable**.
- **All other findings**: Default to **NotVulnerable** (must be proven vulnerable by detection logic).

### Confidence Levels

| Level | Meaning |
|-------|---------|
| Sure | Deterministic check with reliable API data. |
| Requires Verification | Heuristic check; manual review recommended. |

### CAP Two-Stage Evaluation

Each CAP finding uses a two-stage evaluation:
1. **Hard check**: Does the policy meet the mandatory structural requirements (correct resources, correct grant controls, enabled state)?
2. **Soft check**: Does the policy avoid common weaknesses (too many exclusions, missing roles, scoped roles, additional conditions)?

A policy must pass both checks to count as a passing policy. Policies that pass the hard check but fail the soft check are shown as "SoftFail" in the affected objects table.

---

## External Collaboration (COL)

### COL-001: Guest Access Level Not Set to Restricted
- **Severity**: 2 (Medium); reduced to 1 if Limited access (default setting)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `guestUserRoleId` from the authorization policy. Vulnerable if guests have member-level access (`a0b1b346-4d3e-4e8b-98f8-753987be4970`) or limited access (default GUID). Not vulnerable if restricted (`2af84b1e-32c8-42b7-82bc-daa82404023b`).
- **API**: `GET /policies/authorizationPolicy` (`guestUserRoleId`)
- **Variants**: Member (severity 2), Limited (severity 1), Restricted (not vulnerable)

### COL-002: Weak Guest Invite Settings
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `allowInvitesFrom` setting. Vulnerable if `everyone` (all users including guests can invite) or `adminsGuestInvitersAndAllMembers` (all internal users can invite). Not vulnerable if `adminsAndGuestInviters` or `none`.
- **API**: `GET /policies/authorizationPolicy` (`allowInvitesFrom`)
- **Variants**: Everyone, AdminsGuestInvitersAndAllMembers, AdminsAndGuestInviters, None

### COL-003: Guests Allowed to Own M365 Groups
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `AllowGuestsToBeGroupOwner` in the Unified Group Settings directory template (`templateId: 62375ab9-6b52-47ed-826b-58e47e0e304b`). Vulnerable if `true`.
- **API**: `GET /settings` (template values)

---

## Passwords (PAS)

### PAS-001: Custom Banned Password List Not Used
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks the Password Protection Settings directory template (`templateId: 5cf42378-d67d-4f36-ba46-e8b86229381d`). Vulnerable if `EnableBannedPasswordCheck` is not `true`.
- **API**: `GET /settings` (template values)

### PAS-002: Custom Banned Password List Provides Limited Protection
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `BannedPasswordList` entry count in the Password Protection Settings template. Vulnerable if the list has fewer than 10 entries. Skipped if PAS-001 is vulnerable (list not enabled).
- **API**: `GET /settings` (template values)
- **Dependency**: PAS-001 (skipped if PAS-001 is vulnerable)

### PAS-003: Password Protection for On-Premises Not Enforced
- **Severity**: 1 (Low)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Checks `EnableBannedPasswordCheckOnPremises` in the Password Protection Settings template. Vulnerable if not `true`. Skipped if PAS-001 is vulnerable (list not enabled). Requires verification because enforcement depends on the on-premises Password Protection agent being deployed.
- **API**: `GET /settings` (template values)
- **Dependency**: PAS-001 (skipped if PAS-001 is vulnerable)

### PAS-004: Weak Account Lockout Settings
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `LockoutThreshold` and `LockoutDurationInSeconds` from the Password Protection Settings template. Vulnerable if threshold > 10 or lockout duration < 60 seconds.
- **API**: `GET /settings` (template values)

### PAS-005: Self-Service Password Reset is Enabled for Administrators
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `allowedToUseSSPR` from the authorization policy. Vulnerable if `true`.
- **API**: `GET /policies/authorizationPolicy` (`allowedToUseSSPR`)

---

## Users (USR)

### USR-001: App Creation Not Restricted
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `defaultUserRolePermissions.allowedToCreateApps` from the authorization policy. Vulnerable if `true`.
- **API**: `GET /policies/authorizationPolicy` (`defaultUserRolePermissions`)

### USR-002: Non-Admin Users Can Create New Tenants
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `defaultUserRolePermissions.allowedToCreateTenants` from the authorization policy. Vulnerable if `true`.
- **API**: `GET /policies/authorizationPolicy` (`defaultUserRolePermissions`)

### USR-003: Users Can Read BitLocker Recovery Key of Owned Devices
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice` from the authorization policy. Vulnerable if `true`.
- **API**: `GET /policies/authorizationPolicy` (`defaultUserRolePermissions`)

### USR-004: Users Are Allowed to Consent to Apps
- **Severity**: 2 (Medium); reduced to 0 (Info) for LowSpecific variant
- **Confidence**: Sure (or Requires Verification for LowSpecific variant)
- **Default Status**: NotVulnerable
- **Detection**: Checks `permissionGrantPolicyIdsAssignedToDefaultUserRole` from the authorization policy. Vulnerable if `ManagePermissionGrantsForSelf.microsoft-user-default-legacy` (Microsoft managed) or custom consent policies are found. Also checks consent permission classifications for each SP with `delegatedPermissionClassifications`. Severity varies based on what permissions users can consent to.
- **API**: `GET /policies/authorizationPolicy`, `GET /servicePrincipals` (with `delegatedPermissionClassifications` expansion)
- **Variants**: MicrosoftManaged (severity 2), LowExtensive (severity 2), LowSpecific (severity 0), Secure

### USR-005: Inactive Users
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Iterates all users from the Users report. Vulnerable if any enabled user has `Inactive = true` (no successful sign-in for 180+ days). Includes guest accounts if present. Excludes sync accounts.
- **Data Source**: Users hashtable from `check_Users.psm1`
- **Variants**: Vulnerable, VulnerableWithGuests (enhanced threat text when guests are included)

### USR-006: Least Privilege Principle Not Applied (Entra ID)
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Counts users with Tier-0 Entra ID roles (`EntraMaxTier = Tier-0`). Vulnerable if 5 or more users have Tier-0 roles.
- **Data Source**: Users hashtable, TenantRoleAssignments
- **Threshold**: >= 5 Tier-0 users

### USR-007: Hybrid Users with Tier-0 Entra ID Roles
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies users with `OnPrem = true` who also have `EntraMaxTier = Tier-0`. Vulnerable if any such user exists. Excludes sync accounts (`Sync_*`, `ADToAADSyncServiceAccount*`).
- **Data Source**: Users hashtable

### USR-008: Hybrid Users with Tier-0 Azure Roles
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies users with `OnPrem = true` who also have `AzureMaxTier = Tier-0`. Vulnerable if any such user exists. Skipped if Azure IAM was not assessed.
- **Data Source**: Users hashtable
- **Dependency**: Azure IAM assessment (skipped if not performed)

### USR-009: Least Privilege Principle Not Applied (Azure)
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Counts users with Tier-0 Azure roles (`AzureMaxTier = Tier-0`). Vulnerable if 8 or more users have Tier-0 Azure roles. Skipped if Azure IAM was not assessed.
- **Data Source**: Users hashtable
- **Threshold**: >= 8 Tier-0 Azure users
- **Dependency**: Azure IAM assessment (skipped if not performed)

### USR-010: Weak Protection of Privileged Users (Entra ID)
- **Severity**: 3 (High)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies users with Tier-0 Entra ID roles who are not `Protected`. These users can have their passwords/MFA reset by lower-tier admins (e.g., Authentication Administrator, Helpdesk Administrator, User Administrator) or applications with permissions such as `UserAuthenticationMethod.ReadWrite.All`.
- **Data Source**: Users hashtable

### USR-011: Weak Protection of Privileged Users (Azure)
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies users with Tier-0 Azure roles who are not `Protected`. Vulnerable if any such user exists. Skipped if Azure IAM was not assessed.
- **Data Source**: Users hashtable
- **Dependency**: Azure IAM assessment (skipped if not performed)

### USR-012: Users Without Registered MFA Factors
- **Severity**: 2 (Medium) or 3 (High) if CAP-002 has issues
- **Confidence**: Requires Verification (or Sure if CAP-002 secure)
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled non-agent users with `MfaCap = false`. Severity elevated to 3 if CAP-002 (registration of security info) is also vulnerable, since attackers who compromise the first factor could register their own MFA factor. Excludes sync accounts.
- **Data Source**: Users hashtable, CAP-002 status
- **Variants**: VulnerableCapIssues (severity 3), VulnerableCapSecure (severity 2)

---

## Groups (GRP)

### GRP-001: Security Group Creation Not Restricted
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `defaultUserRolePermissions.allowedToCreateSecurityGroups` from the authorization policy. Vulnerable if `true`.
- **API**: `GET /policies/authorizationPolicy` (`defaultUserRolePermissions`)

### GRP-002: M365 Group Creation Not Restricted
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks `EnableGroupCreation` in the Unified Group Settings template. Vulnerable if `true` or not explicitly set to `false`.
- **API**: `GET /settings` (template values)

### GRP-003: Public M365 Groups
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Iterates all groups. Identifies non-dynamic M365 groups with `Visibility = Public`. Any tenant user can self-join these groups, potentially gaining access to SharePoint, Exchange, and Teams data.
- **Data Source**: AllGroupsDetails hashtable

### GRP-004: Dynamic Groups with Potentially Dangerous Membership Rules
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies dynamic groups whose membership rules reference user-modifiable attributes (`businessPhones`, `mobilePhone`, `preferredLanguage`) or attributes manipulable via guest invitation (`userPrincipalName`, `mail`). The threat description varies based on the tenant's guest invite settings (COL-002 result).
- **Data Source**: AllGroupsDetails hashtable, authorization policy (`allowInvitesFrom`)
- **Variants**: Threat text varies by InviteEveryone, InviteAdminsGuestInvitersAndAllMembers, InviteAdminsAndGuestInviters

### GRP-005: Weak Protection of Sensitive Groups
- **Severity**: 3 (High)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies groups with sensitive permissions (Entra roles, Azure roles, CAP exclusions, or PIM-eligible escalation paths) that are not `Protected` (not role-assignable, not in restricted AU). These groups can have their membership modified by lower-tier admins (Groups Administrator, Knowledge Manager, User Administrator) or applications with `Group.ReadWrite.All`.
- **Data Source**: AllGroupsDetails hashtable

---

## Conditional Access Policies (CAP)

### CAP-001: Device Code Flow Not Restricted
- **Severity**: 3 (High)
- **Confidence**: Sure
- **Default Status**: Vulnerable
- **Detection**: Searches for enabled Conditional Access policies that block the device code authentication flow (`authenticationFlows` contains `deviceCodeFlow`) with grant control `block`. The policy must include all users and target all resources.
- **Data Source**: AllCaps hashtable

### CAP-002: Registration of Security Info Not Restricted
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: Vulnerable
- **Detection**: Searches for enabled Conditional Access policies that target the user action `urn:user:registersecurityinfo` with a grant control that requires MFA, compliant device, or domain-joined device.
- **Data Source**: AllCaps hashtable

### CAP-003: Legacy Authentication Not Blocked
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: Vulnerable
- **Detection**: Searches for enabled Conditional Access policies that target legacy authentication client apps (`exchangeActiveSync`, `other`) with grant control `block`.
- **Data Source**: AllCaps hashtable

### CAP-004: No MFA Required for Joining or Registering a Device
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: Vulnerable
- **Detection**: Checks two sources: (1) the device registration policy (`/policies/deviceRegistrationPolicy`) for `multiFactorAuthConfiguration = required`, and (2) Conditional Access policies targeting user action `urn:user:registerdevice` with MFA requirement. Not vulnerable if either source enforces MFA.
- **Data Source**: AllCaps hashtable, device registration policy
- **Special Token**: Requires Security Findings access token (or BroCi auth flow). Unavailable in DeviceCode flow, resulting in reduced check depth.

### CAP-005: No Phishing-Resistant MFA Enforced
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: Vulnerable
- **Detection**: Searches for enabled Conditional Access policies that require authentication strength. Validates that the referenced authentication strength policy only allows phishing-resistant factors (`windowsHelloForBusiness`, `fido2`, `x509CertificateMultiFactor`). Single-factor indicators (`x509CertificateSingleFactor`, `sms`, `password`, `federatedSingleFactor`, `qrCodePin`) disqualify a strength from being phishing-resistant.
- **Data Source**: AllCaps hashtable, authentication strength policies
- **Special Token**: Requires Security Findings access token (or BroCi auth flow). Unavailable in DeviceCode flow.

### CAP-006: Combined Risk Policy
- **Severity**: 3 (High)
- **Confidence**: Sure
- **Default Status**: Vulnerable
- **Detection**: Searches for Conditional Access policies that combine both user risk AND sign-in risk conditions in the same policy. Because CAP conditions use logical AND, a combined policy only fires when both risk types are present simultaneously, rendering it ineffective. Not vulnerable if no policy combines both risk types, OR if separate policies exist for each risk type.
- **Data Source**: AllCaps hashtable

### CAP-007: Sign-In Risk Not Managed
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: Vulnerable
- **Detection**: Searches for enabled Conditional Access policies that address sign-in risk levels (medium, high) with appropriate grant controls (MFA, block, or password change). Requires Verification because sign-in risk detection depends on Entra ID P2 licensing.
- **Data Source**: AllCaps hashtable

### CAP-008: User Risk Not Managed
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: Vulnerable
- **Detection**: Searches for enabled Conditional Access policies that address user risk levels (medium, high) with appropriate grant controls (MFA, block, or password change). Requires Verification because user risk detection depends on Entra ID P2 licensing.
- **Data Source**: AllCaps hashtable

### CAP-009: MFA Not Enforced
- **Severity**: 3 (High)
- **Confidence**: Sure
- **Default Status**: Vulnerable
- **Detection**: Searches for enabled Conditional Access policies that enforce MFA (`mfa` in grant controls or authentication strength) targeting all users and all cloud applications.
- **Data Source**: AllCaps hashtable

### CAP-010: Conditional Access Policy Missing Used Tier-0/Tier-1 Roles
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: Vulnerable
- **Detection**: For each enabled Conditional Access policy that targets 5 or more directory roles, checks whether all Tier-0 and Tier-1 roles that have active assignments are included. Vulnerable if any policy has missing roles with active assignments.
- **Data Source**: AllCaps hashtable, TenantRoleAssignments

### CAP-011: Conditional Access Policy Includes Roles With Scoped Assignments
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies Conditional Access policies that target directory roles where some assignments are scoped (not tenant-wide). Scoped role assignments are not covered by role-based CAP targeting. Vulnerable if any policy has roles with scoped assignments.
- **Data Source**: AllCaps hashtable, TenantRoleAssignments

---

## Enterprise Applications (ENT)

### ENT-001: Enterprise Applications with Client Credentials
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled enterprise applications that are not SAML-configured and have at least one credential (secret or certificate) directly assigned to the service principal. These credentials are not visible in the Entra portal.
- **Data Source**: EnterpriseApps hashtable

### ENT-002: Inactive Enterprise Applications
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled enterprise applications that are inactive (no sign-in for 180+ days or no sign-in data) and have privileges.
- **Data Source**: EnterpriseApps hashtable

### ENT-003: Enterprise Applications with Non-Tier-0 Owner
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled enterprise applications that have Tier-0 privileges (Dangerous API permissions, Tier-0 Entra/Azure roles) but are owned by non-Tier-0 principals. Represents a privilege escalation path.
- **Data Source**: EnterpriseApps hashtable, Users/ManagedIdentities hashtables

### ENT-004: Foreign Enterprise Applications with Extensive API Privileges (as Application)
- **Severity**: 3 (High)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled foreign enterprise applications with Dangerous or High Application API permissions.
- **Data Source**: EnterpriseApps hashtable (Foreign, ApiDangerous, ApiHigh)

### ENT-005: Foreign Enterprise Applications with Extensive API Privileges (Delegated)
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled foreign enterprise applications with Dangerous or High Delegated API permissions.
- **Data Source**: EnterpriseApps hashtable (Foreign, ApiDelegatedDangerous, ApiDelegatedHigh)

### ENT-006: Foreign Enterprise Applications with Entra ID Roles
- **Severity**: 3 (High)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled foreign enterprise applications with Entra ID role assignments.
- **Data Source**: EnterpriseApps hashtable (Foreign, EntraRoles)

### ENT-007: Foreign Enterprise Applications with Azure Roles
- **Severity**: 3 (High)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled foreign enterprise applications with Azure IAM role assignments.
- **Data Source**: EnterpriseApps hashtable (Foreign, AzureRoles)

### ENT-008: Foreign Enterprise Applications Owning Objects
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled foreign enterprise applications that own groups, app registrations, or service principals.
- **Data Source**: EnterpriseApps hashtable (Foreign, AppOwn, SpOwn, GrpOwn)

### ENT-009: Internal Enterprise Applications with Extensive API Privileges (as Application)
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled internal enterprise applications with Dangerous or High Application API permissions.
- **Data Source**: EnterpriseApps hashtable (ApiDangerous, ApiHigh)

### ENT-010: Internal Enterprise Applications with Extensive API Privileges (Delegated)
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled internal enterprise applications with Dangerous or High Delegated API permissions.
- **Data Source**: EnterpriseApps hashtable (ApiDelegatedDangerous, ApiDelegatedHigh)

### ENT-011: Internal Enterprise Applications with Privileged Entra ID Roles
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled internal enterprise applications with Tier-0 or Tier-1 Entra ID role assignments.
- **Data Source**: EnterpriseApps hashtable (EntraRoles, EntraMaxTier)

### ENT-012: Internal Enterprise Applications with Privileged Azure Roles
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies enabled internal enterprise applications with Tier-0 or Tier-1 Azure IAM role assignments.
- **Data Source**: EnterpriseApps hashtable (AzureRoles, AzureMaxTier)

---

## App Registrations (APP)

### APP-001: App Registrations with Secrets
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies app registrations that have client secrets configured. Secrets are prone to exposure through configuration files, scripts, or logs.
- **Data Source**: AppRegistrations hashtable (SecretsCount)

### APP-002: App Registrations Missing App Instance Property Lock
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies app registrations where the App Instance Property Lock is not enabled. Without this lock, SP owners can modify credentials on the enterprise app side.
- **Data Source**: AppRegistrations hashtable (AppLock)

### APP-003: App Registration with Non-Tier-0 Owner
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies app registrations whose corresponding enterprise app has Tier-0 privileges but the app registration is owned by a non-Tier-0 principal.
- **Data Source**: AppRegistrations hashtable, EnterpriseApps hashtable

---

## Managed Identities (MAI)

### MAI-001: Managed Identities with API Privileges
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies managed identities with Dangerous or High Application API permissions. Any code running on the associated Azure resource can use these permissions.
- **Data Source**: ManagedIdentities hashtable (ApiDangerous, ApiHigh)

### MAI-002: Managed Identities with Privileged Entra ID Roles
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies managed identities with Tier-0 or Tier-1 Entra ID role assignments.
- **Data Source**: ManagedIdentities hashtable (EntraRoles, EntraMaxTier)

### MAI-003: Managed Identities with Privileged Azure Roles
- **Severity**: 2 (Medium)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Identifies managed identities with Tier-0 or Tier-1 Azure IAM role assignments. Requires verification because Azure role scope determines actual risk.
- **Data Source**: ManagedIdentities hashtable (AzureRoles, AzureMaxTier)

---

## PIM (Privileged Identity Management)

PIM findings evaluate the configuration of PIM for Entra ID roles, focusing on Tier-0 roles.

### PIM-001: PIM for Entra Roles Not Used
- **Severity**: 3 (High)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks whether PIM is used for any Entra ID role. Vulnerable if no roles have eligible assignments and all assignments are permanent/active.
- **Data Source**: PimforEntraRoles hashtable

### PIM-002: Tier-0 Roles Only Permanently Assigned
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Identifies Tier-0 roles that have active assignments but no eligible assignments. Vulnerable if any Tier-0 role has only permanent assignments.
- **Data Source**: PimforEntraRoles hashtable, TenantRoleAssignments

### PIM-003: Tier-0 Roles With Long Activation Duration (>4 Hours)
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks the maximum activation duration for Tier-0 roles. Vulnerable if any Tier-0 role allows activation for more than 4 hours.
- **Data Source**: PimforEntraRoles hashtable (PIM policy rules)

### PIM-004: Tier-0 Roles Which Do Not Require Justification on Activation
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks whether justification is required when activating Tier-0 roles. Vulnerable if any Tier-0 role does not require justification.
- **Data Source**: PimforEntraRoles hashtable (PIM policy rules)

### PIM-005: Tier-0 Roles Allow Permanent Active Assignments
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks whether Tier-0 roles allow permanent active assignments (no expiration required).
- **Data Source**: PimforEntraRoles hashtable (PIM policy rules)

### PIM-006: Tier-0 Roles Without Justification on Active Assignments
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks whether justification is required when creating active (permanent) assignments for Tier-0 roles.
- **Data Source**: PimforEntraRoles hashtable (PIM policy rules)

### PIM-007: Tier-0 Roles Without MFA on Active Assignments
- **Severity**: 1 (Low)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks whether MFA is required when creating active (permanent) assignments for Tier-0 roles.
- **Data Source**: PimforEntraRoles hashtable (PIM policy rules)

### PIM-008: Tier-0 Roles Without Notification
- **Severity**: 1 (Low)
- **Confidence**: Requires Verification
- **Default Status**: NotVulnerable
- **Detection**: Checks notification settings for Tier-0 roles. Vulnerable if notifications are not configured for role activations or assignments. Requires verification because notification settings may be handled through external SIEM/SOAR integrations.
- **Data Source**: PimforEntraRoles hashtable (PIM policy rules, notification rules)

### PIM-009: Tier-0 Roles Without Authentication Context or Approval
- **Severity**: 2 (Medium)
- **Confidence**: Sure
- **Default Status**: NotVulnerable
- **Detection**: Checks whether Tier-0 roles require an authentication context or approval workflow on activation. Authentication contexts can link PIM activation to Conditional Access policies for step-up authentication (e.g., phishing-resistant MFA).
- **Data Source**: PimforEntraRoles hashtable (PIM policy rules), AllCaps hashtable

---

## Finding Category Summary

| Category | ID Range | Count | Default Status |
|----------|----------|-------|---------------|
| External Collaboration | COL-001 to COL-003 | 3 | NotVulnerable |
| Passwords | PAS-001 to PAS-005 | 5 | NotVulnerable |
| Users | USR-001 to USR-012 | 12 | NotVulnerable |
| Groups | GRP-001 to GRP-005 | 5 | NotVulnerable |
| Conditional Access Policies | CAP-001 to CAP-011 | 11 | Vulnerable (CAP-001 to CAP-010), NotVulnerable (CAP-011) |
| Enterprise Applications | ENT-001 to ENT-012 | 12 | NotVulnerable |
| App Registrations | APP-001 to APP-003 | 3 | NotVulnerable |
| Managed Identities | MAI-001 to MAI-003 | 3 | NotVulnerable |
| PIM | PIM-001 to PIM-009 | 9 | NotVulnerable |
| **Total** | | **62** | |

---

## API Dependencies

| Endpoint | Used By |
|----------|---------|
| `GET /policies/authorizationPolicy` | COL-001, COL-002, PAS-005, USR-001, USR-002, USR-003, USR-004, GRP-001 |
| `GET /settings` | COL-003, GRP-002, PAS-001, PAS-002, PAS-003, PAS-004 |
| `GET /servicePrincipals` (with `delegatedPermissionClassifications`) | USR-004 |
| `GET /policies/deviceRegistrationPolicy` | CAP-004 (special token, unavailable in DeviceCode flow) |
| `GET /identity/conditionalAccess/authenticationStrength/policies` | CAP-005 (special token, unavailable in DeviceCode flow) |
| Conditional Access Policies (from `check_CAPs.psm1`) | CAP-001 through CAP-011 |
| Users hashtable (from `check_Users.psm1`) | USR-005 through USR-012 |
| AllGroupsDetails hashtable (from `check_Groups.psm1`) | GRP-003, GRP-004, GRP-005 |
| EnterpriseApps hashtable (from `check_EnterpriseApps.psm1`) | ENT-001 through ENT-012 |
| AppRegistrations hashtable (from `check_AppRegistrations.psm1`) | APP-001 through APP-003 |
| ManagedIdentities hashtable (from `check_ManagedIdentities.psm1`) | MAI-001 through MAI-003 |
| PimforEntraRoles hashtable (from `check_PIM.psm1`) | PIM-001 through PIM-009 |

---

## Summary Table

| ID | Title | Severity | Default Status | Confidence |
|----|-------|----------|----------------|------------|
| COL-001 | Guest Access Level Not Set to Restricted | 2 | NotVulnerable | Sure |
| COL-002 | Weak Guest Invite Settings | 2 | NotVulnerable | Sure |
| COL-003 | Guests Allowed to Own M365 Groups | 1 | NotVulnerable | Sure |
| PAS-001 | Custom Banned Password List Not Used | 2 | NotVulnerable | Sure |
| PAS-002 | Custom Banned Password List Provides Limited Protection | 1 | NotVulnerable | Sure |
| PAS-003 | Password Protection for On-Premises Not Enforced | 1 | NotVulnerable | Requires Verification |
| PAS-004 | Weak Account Lockout Settings | 1 | NotVulnerable | Sure |
| PAS-005 | Self-Service Password Reset is Enabled for Administrators | 2 | NotVulnerable | Sure |
| USR-001 | App Creation Not Restricted | 2 | NotVulnerable | Sure |
| USR-002 | Non-Admin Users Can Create New Tenants | 1 | NotVulnerable | Sure |
| USR-003 | Users Can Read BitLocker Recovery Key of Owned Devices | 1 | NotVulnerable | Sure |
| USR-004 | Users Are Allowed to Consent to Apps | 2 | NotVulnerable | Sure |
| USR-005 | Inactive Users | 2 | NotVulnerable | Sure |
| USR-006 | Least Privilege Principle Not Applied (Entra ID) | 2 | NotVulnerable | Requires Verification |
| USR-007 | Hybrid Users with Tier-0 Entra ID Roles | 2 | NotVulnerable | Sure |
| USR-008 | Hybrid Users with Tier-0 Azure Roles | 2 | NotVulnerable | Requires Verification |
| USR-009 | Least Privilege Principle Not Applied (Azure) | 2 | NotVulnerable | Requires Verification |
| USR-010 | Weak Protection of Privileged Users (Entra ID) | 3 | NotVulnerable | Requires Verification |
| USR-011 | Weak Protection of Privileged Users (Azure) | 2 | NotVulnerable | Requires Verification |
| USR-012 | Users Without Registered MFA Factors | 2 | NotVulnerable | Requires Verification |
| GRP-001 | Security Group Creation Not Restricted | 2 | NotVulnerable | Sure |
| GRP-002 | M365 Group Creation Not Restricted | 1 | NotVulnerable | Sure |
| GRP-003 | Public M365 Groups | 2 | NotVulnerable | Sure |
| GRP-004 | Dynamic Groups with Potentially Dangerous Membership Rules | 2 | NotVulnerable | Requires Verification |
| GRP-005 | Weak Protection of Sensitive Groups | 3 | NotVulnerable | Requires Verification |
| CAP-001 | Device Code Flow Not Restricted | 3 | Vulnerable | Sure |
| CAP-002 | Registration of Security Info Not Restricted | 2 | Vulnerable | Sure |
| CAP-003 | Legacy Authentication Not Blocked | 2 | Vulnerable | Sure |
| CAP-004 | No MFA Required for Joining or Registering a Device | 2 | Vulnerable | Sure |
| CAP-005 | No Phishing-Resistant MFA Enforced | 2 | Vulnerable | Sure |
| CAP-006 | Combined Risk Policy | 3 | Vulnerable | Sure |
| CAP-007 | Sign-In Risk Not Managed | 2 | Vulnerable | Requires Verification |
| CAP-008 | User Risk Not Managed | 2 | Vulnerable | Requires Verification |
| CAP-009 | MFA Not Enforced | 3 | Vulnerable | Sure |
| CAP-010 | CAP Missing Used Tier-0/Tier-1 Roles | 2 | Vulnerable | Requires Verification |
| CAP-011 | CAP Includes Roles With Scoped Assignments | 2 | NotVulnerable | Requires Verification |
| ENT-001 | Enterprise Applications with Client Credentials | 1 | NotVulnerable | Sure |
| ENT-002 | Inactive Enterprise Applications | 2 | NotVulnerable | Sure |
| ENT-003 | Enterprise Applications with Non-Tier-0 Owner | 2 | NotVulnerable | Requires Verification |
| ENT-004 | Foreign Apps with Extensive API Privileges (Application) | 3 | NotVulnerable | Sure |
| ENT-005 | Foreign Apps with Extensive API Privileges (Delegated) | 2 | NotVulnerable | Sure |
| ENT-006 | Foreign Enterprise Applications with Entra ID Roles | 3 | NotVulnerable | Sure |
| ENT-007 | Foreign Enterprise Applications with Azure Roles | 3 | NotVulnerable | Requires Verification |
| ENT-008 | Foreign Enterprise Applications Owning Objects | 2 | NotVulnerable | Requires Verification |
| ENT-009 | Internal Apps with Extensive API Privileges (Application) | 2 | NotVulnerable | Sure |
| ENT-010 | Internal Apps with Extensive API Privileges (Delegated) | 2 | NotVulnerable | Sure |
| ENT-011 | Internal Apps with Privileged Entra ID Roles | 2 | NotVulnerable | Sure |
| ENT-012 | Internal Apps with Privileged Azure Roles | 2 | NotVulnerable | Sure |
| APP-001 | App Registrations with Secrets | 1 | NotVulnerable | Sure |
| APP-002 | App Registrations Missing App Instance Property Lock | 1 | NotVulnerable | Sure |
| APP-003 | App Registration with Non-Tier-0 Owner | 2 | NotVulnerable | Requires Verification |
| MAI-001 | Managed Identities with API Privileges | 2 | NotVulnerable | Sure |
| MAI-002 | Managed Identities with Privileged Entra ID Roles | 2 | NotVulnerable | Sure |
| MAI-003 | Managed Identities with Privileged Azure Roles | 2 | NotVulnerable | Requires Verification |
| PIM-001 | PIM for Entra Roles Not Used | 3 | NotVulnerable | Sure |
| PIM-002 | Tier-0 Roles Only Permanently Assigned | 2 | NotVulnerable | Sure |
| PIM-003 | Tier-0 Roles With Long Activation Duration (>4 Hours) | 1 | NotVulnerable | Sure |
| PIM-004 | Tier-0 Roles Without Justification on Activation | 1 | NotVulnerable | Sure |
| PIM-005 | Tier-0 Roles Allow Permanent Active Assignments | 1 | NotVulnerable | Sure |
| PIM-006 | Tier-0 Roles Without Justification on Active Assignments | 1 | NotVulnerable | Sure |
| PIM-007 | Tier-0 Roles Without MFA on Active Assignments | 1 | NotVulnerable | Sure |
| PIM-008 | Tier-0 Roles Without Notification | 1 | NotVulnerable | Requires Verification |
| PIM-009 | Tier-0 Roles Without Authentication Context or Approval | 2 | NotVulnerable | Sure |
