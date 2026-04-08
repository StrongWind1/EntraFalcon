# EntraFalcon Network Endpoint Inventory

This document provides a complete inventory of every network endpoint contacted by EntraFalcon, organized by domain and purpose.

---

## Authentication Endpoints (login.microsoftonline.com)

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| login.microsoftonline.com | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` | OAuth 2.0 authorization endpoint; initiates interactive sign-in | GET (browser) | None (pre-auth) | Always (interactive flows) | AuthCode, ManualCode, BroCi, BroCiManualCode | Yes | Sensitive: user credentials are submitted here; PKCE challenge and state parameter are sent as URL params |
| login.microsoftonline.com | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | OAuth 2.0 token endpoint; exchanges auth codes and refresh tokens for access/refresh tokens | POST | None (token request contains grant material) | Always | All flows | Yes | Sensitive: receives authorization codes, refresh tokens, PKCE verifiers, client secrets |
| login.microsoftonline.com | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` | OAuth 2.0 device code endpoint; initiates device code flow | POST | None (pre-auth) | Conditional (DeviceCode flow only) | DeviceCode | Yes | Returns device code and user code; user code is copied to clipboard |
| login.microsoftonline.com | `https://login.microsoftonline.com/common/oauth2/nativeclient` | Redirect URI for PIM for Groups auth (non-BroCi AuthCode/ManualCode) | N/A (redirect target) | N/A | Conditional (PIM for Groups, non-BroCi) | AuthCode, ManualCode | Yes | Used as redirect_uri parameter; browser navigates here after auth |

---

## Redirect URIs (Various)

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| localhost | `http://localhost:13824/` | Local HTTP listener; captures OAuth authorization code from redirect | GET (redirect) | None (redirect contains auth code) | Always (AuthCode, PIM for Entra AuthCode/ManualCode) | AuthCode, ManualCode | N/A (local) | Authorization code is transmitted in URL query string over HTTP (localhost only) |
| startups.portal.azure.com | `https://startups.portal.azure.com/auth/login/` | Redirect URI for BroCi initial authentication with Azure Portal client | GET (redirect) | None (redirect contains auth code) | Conditional (BroCi flow) | BroCi, BroCiManualCode | Yes | External redirect URI; requires embedded browser (IE) on Windows |
| transition.security.microsoft.com | `https://transition.security.microsoft.com/Blank` | Redirect URI for Security Findings special authentication | GET (redirect) | None (redirect contains auth code) | Conditional (SecurityFindings, non-BroCi, non-DeviceCode) | AuthCode, ManualCode | Yes | External redirect URI; requires embedded browser (IE) on Windows |
| portal.azure.com | `brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com` | Custom URI scheme for BroCi broker token refresh | N/A (used as redirect_uri parameter in token refresh) | N/A | Conditional (BroCi flow, token refresh) | BroCi, BroCiManualCode, BroCiToken | Yes | Used in refresh requests with brk_client_id parameter; not an actual HTTP endpoint |

---

## Microsoft Graph API (graph.microsoft.com) -- Direct Requests

All Graph API requests use the `beta` API version unless otherwise noted. All use the `GLOBALMsGraphAccessToken` unless otherwise specified in the Auth Context column.

### Organization and Tenant

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/organization?$select=id` | Authentication validation; confirms Graph token is working | GET | MainGraph | Always | All | Yes | Connectivity check |
| graph.microsoft.com | `/beta/organization` | Retrieve tenant information (display name, ID, license details) | GET | MainGraph | Always | All | Yes | Returns tenant identifiers |
| graph.microsoft.com | `/beta/subscribedSkus` | Retrieve tenant license SKUs to determine Entra ID license level | GET | MainGraph | Always | All | Yes | License information |
| graph.microsoft.com | `/beta/settings` | Retrieve tenant directory settings (group creation, consent policies) | GET | MainGraph | Always (Security Findings) | All | Yes | Tenant configuration |
| graph.microsoft.com | `/beta/policies/authorizationPolicy` | Retrieve authorization policy (guest access, user permissions, consent) | GET | MainGraph | Always (Security Findings) | All | Yes | Tenant security policy |
| graph.microsoft.com | `/beta/servicePrincipals` (with filter for consent classification) | Retrieve consent permission classifications | GET | MainGraph | Always (Security Findings) | All | Yes | Consent configuration |

### Users

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/users` (with signInActivity, various $select) | Retrieve all users with sign-in activity and account details | GET | MainGraph | Always | All | Yes | Contains UPNs, account status, sign-in timestamps |
| graph.microsoft.com | `/beta/users` (without signInActivity) | Fallback: retrieve users when signInActivity is unavailable | GET | MainGraph | Conditional (fallback) | All | Yes | Reduced user data |
| graph.microsoft.com | `/beta/users/{id}` | Resolve individual user by ID (app registration admin resolution) | GET | MainGraph | Conditional (per app registration owner) | All | Yes | Individual user lookup |
| graph.microsoft.com | `/beta/reports/authenticationMethods/userRegistrationDetails` | Retrieve MFA registration status for all users | GET | MainGraph | Always | All | Yes | MFA enrollment data |
| graph.microsoft.com | `/beta/me?$select=id` | Validate PIM for Groups token by retrieving current user ID | GET | PimForGroup | Conditional (PIM for Groups) | All | Yes | Auth validation |

### Groups

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/groups` | Retrieve all groups with properties (type, dynamic rules, visibility) | GET | MainGraph | Always | All | Yes | Group configurations including dynamic membership rules |
| graph.microsoft.com | `/beta/servicePrincipals` (with tags filter for groups) | Retrieve service principals tagged for groups | GET | MainGraph | Always | All | Yes | App role assignment context |

### Devices

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/devices` | Retrieve all devices registered in Entra ID | GET | MainGraph | Always | All | Yes | Device inventory |

### Enterprise Apps (Service Principals)

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/servicePrincipals` (various filters) | Retrieve all enterprise apps / service principals | GET | MainGraph | Always | All | Yes | Service principal inventory |
| graph.microsoft.com | `/beta/applications` (for enterprise app correlation) | Retrieve all app registrations to correlate with service principals | GET | MainGraph | Always | All | Yes | App registration data |
| graph.microsoft.com | `/beta/reports/servicePrincipalSignInActivities` | Retrieve service principal sign-in activity data | GET | MainGraph | Always | All | Yes | Activity data; may require P1/P2 license |
| graph.microsoft.com | `/beta/servicePrincipals/{id}` | Resolve individual service principal by ID (delegated permission resolution) | GET | MainGraph | Conditional (per unique resource ID) | All | Yes | Individual SP lookup |

### App Registrations

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/applications` | Retrieve all app registrations | GET | MainGraph | Always | All | Yes | App registration inventory including credentials and redirect URIs |

### Conditional Access

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/identity/conditionalAccess/policies` | Retrieve all Conditional Access policies | GET | MainGraph | Always | All | Yes | Full CA policy configurations |
| graph.microsoft.com | `/beta/identity/conditionalAccess/namedLocations` | Retrieve Named Locations referenced by CA policies | GET | MainGraph | Always | All | Yes | Location definitions |
| graph.microsoft.com | `/beta/identity/conditionalAccess/authenticationStrength/policies` | Retrieve authentication strength policies | GET | SecurityFindingsSpecial or MainGraph | Conditional (non-DeviceCode) | AuthCode, ManualCode, BroCi | Yes | Auth strength definitions for CAP-005 |
| graph.microsoft.com | `/beta/policies/deviceRegistrationPolicy` | Retrieve device registration policy | GET | SecurityFindingsSpecial or MainGraph | Conditional (non-DeviceCode) | AuthCode, ManualCode, BroCi | Yes | Device registration settings for CAP-004 |

### Roles

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/roleManagement/directory/roleDefinitions` | Retrieve all Entra ID role definitions (built-in and custom) | GET | MainGraph or PIMGraph | Always | All | Yes | Role definitions |
| graph.microsoft.com | `/beta/roleManagement/directory/roleAssignments` | Retrieve all active Entra ID role assignments | GET | MainGraph | Always | All | Yes | Active role assignments |
| graph.microsoft.com | `/beta/roleManagement/directory/roleEligibilitySchedules` | Retrieve PIM-eligible role assignments | GET | PIMGraph | Conditional (PIM licensed) | All | Yes | Eligible/PIM role data |
| graph.microsoft.com | `/beta/directoryRoleTemplates` | Retrieve directory role templates for CAP analysis | GET | MainGraph | Conditional (CAP analysis) | All | Yes | Role template IDs |
| graph.microsoft.com | `/beta/directoryObjects/getByIds` | Resolve directory objects by ID array (role assignment targets) | POST | MainGraph | Conditional (role resolution) | All | Yes | Bulk object resolution |

### PIM (Privileged Identity Management)

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/policies/roleManagementPolicies` | Retrieve PIM role management policies | GET | PIMGraph | Conditional (PIM licensed) | All | Yes | PIM policy configurations |
| graph.microsoft.com | `/beta/policies/roleManagementPolicyAssignments` | Retrieve PIM policy-to-role assignments | GET | PIMGraph | Conditional (PIM licensed) | All | Yes | Policy assignment mappings |
| graph.microsoft.com | `/beta/privilegedAccess/aadGroups/resources` | Retrieve PIM-enabled groups (non-BroCi fallback) | GET | PimForGroup | Conditional (PIM for Groups, non-BroCi) | AuthCode, DeviceCode, ManualCode | Yes | PIM for Groups resource list |

### Administrative Units

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| graph.microsoft.com | `/beta/directory/administrativeUnits` | Retrieve all administrative units | GET | MainGraph | Always | All | Yes | AU definitions |
| graph.microsoft.com | `/beta/directory/administrativeUnits/{id}/members` | Retrieve members of each administrative unit | GET | MainGraph | Always | All | Yes | AU membership |

---

## Microsoft Graph API (graph.microsoft.com) -- Batch Sub-Requests

All batch requests are sent via `POST https://graph.microsoft.com/{version}/$batch` with up to 20 sub-requests per batch. The sub-request URLs below are relative paths within the batch JSON body.

### User Batch Sub-Requests

| Sub-Request URL Pattern | Purpose | HTTP Method | Auth Context | When Used |
|---|---|---|---|---|
| `/users/{id}/transitiveMemberOf` | Retrieve all group/role memberships for a user (transitive) | GET | MainGraph | Always (per user) |
| `/users/{id}/ownedObjects` | Retrieve objects owned by a user (apps, groups, SPs) | GET | MainGraph | Always (per user) |
| `/users/{id}/ownedDevices` | Retrieve devices owned by a user | GET | MainGraph | Always (per user) |
| `/users/{id}/registeredDevices` | Retrieve devices registered to a user | GET | MainGraph | Always (per user) |

### Group Batch Sub-Requests

| Sub-Request URL Pattern | Purpose | HTTP Method | Auth Context | When Used |
|---|---|---|---|---|
| `/groups/{id}/members` | Retrieve direct members of a group | GET | MainGraph | Always (per group) |
| `/groups/{id}/owners` | Retrieve owners of a group | GET | MainGraph | Always (per group) |
| `/groups/{id}/appRoleAssignments` | Retrieve app role assignments for a group | GET | MainGraph | Always (per group) |

### Enterprise App Batch Sub-Requests

| Sub-Request URL Pattern | Purpose | HTTP Method | Auth Context | When Used |
|---|---|---|---|---|
| `/servicePrincipals/{id}/appRoleAssignments` | Retrieve application permissions (app roles) assigned to an SP | GET | MainGraph | Always (per SP) |
| `/servicePrincipals/{id}/oauth2PermissionGrants` | Retrieve delegated permission grants for an SP | GET | MainGraph | Always (per SP) |
| `/servicePrincipals/{id}/transitiveMemberOf/microsoft.graph.group` | Retrieve group memberships for an SP | GET | MainGraph | Always (per SP) |
| `/servicePrincipals/{id}/ownedObjects` | Retrieve objects owned by an SP | GET | MainGraph | Always (per SP) |
| `/servicePrincipals/{id}/owners` | Retrieve owners of an SP | GET | MainGraph | Always (per SP) |
| `/servicePrincipals/{id}/appRoleAssignedTo` | Retrieve app roles assigned to users/groups for an SP | GET | MainGraph | Always (per SP) |

### Managed Identity Batch Sub-Requests

| Sub-Request URL Pattern | Purpose | HTTP Method | Auth Context | When Used |
|---|---|---|---|---|
| `/servicePrincipals/{id}/appRoleAssignments` | Retrieve app role assignments for a managed identity | GET | MainGraph | Always (per managed identity) |
| `/servicePrincipals/{id}/transitiveMemberOf/microsoft.graph.group` | Retrieve group memberships for a managed identity | GET | MainGraph | Always (per managed identity) |
| `/servicePrincipals/{id}/ownedObjects` | Retrieve objects owned by a managed identity | GET | MainGraph | Always (per managed identity) |

### App Registration Batch Sub-Requests

| Sub-Request URL Pattern | Purpose | HTTP Method | Auth Context | When Used |
|---|---|---|---|---|
| `/applications/{id}/owners` | Retrieve owners of an app registration | GET | MainGraph | Always (per app registration) |
| `/applications/{id}/federatedIdentityCredentials` | Retrieve federated identity credentials for an app registration | GET | MainGraph | Always (per app registration) |

### PIM for Groups Batch Sub-Requests

| Sub-Request URL Pattern | Purpose | HTTP Method | Auth Context | When Used |
|---|---|---|---|---|
| `/identityGovernance/privilegedAccess/group/eligibilitySchedules?$filter=groupId eq '{id}'` | Retrieve PIM eligibility schedules for a specific group | GET | PimForGroup | Conditional (per PIM-enabled group) |

### Object Resolution Batch Sub-Requests

| Sub-Request URL Pattern | Purpose | HTTP Method | Auth Context | When Used |
|---|---|---|---|---|
| `/servicePrincipals/{id}` (with $select=id, $top=1) | Validate existence of service principal objects (report availability check) | GET | MainGraph | Always (startup) |
| `/groups/{id}` (with $select=id, $top=1) | Validate existence of group objects (report availability check) | GET | MainGraph | Always (startup) |
| `/applications/{id}` (with $select=id, $top=1) | Validate existence of application objects (report availability check) | GET | MainGraph | Always (startup) |

---

## Azure Resource Manager API (management.azure.com)

All ARM API requests use the `GLOBALArmAccessToken`.

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| management.azure.com | `https://management.azure.com/subscriptions?api-version=2022-12-01` | Check ARM token validity and list accessible subscriptions | GET | ARM | Conditional (ARM auth succeeds) | All | Yes | Subscription enumeration |
| management.azure.com | `https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01` | Query Azure Resource Graph for management-group-level role assignments | POST | ARM | Conditional (Resource Graph access) | All | Yes | Management group role discovery |
| management.azure.com | `https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01` | Retrieve all built-in Azure role definitions | GET | ARM | Conditional (ARM access) | All | Yes | Role definition enumeration |
| management.azure.com | `https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?$filter=type+eq+'CustomRole'&api-version=2022-04-01` | Retrieve custom Azure role definitions | GET | ARM | Conditional (ARM access) | All | Yes | Custom role enumeration |
| management.azure.com | `https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01` | Retrieve all role assignments for a subscription (includes resource-level) | GET | ARM | Conditional (per subscription) | All | Yes | Full subscription RBAC assignments |
| management.azure.com | `https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01-preview` | Retrieve PIM-eligible Azure role assignments for a subscription | GET | ARM | Conditional (per subscription, PIM available) | All | Yes | Eligible Azure role assignments; uses preview API |

---

## PIM API (api.azrbac.mspim.azure.com)

This is an undocumented Microsoft API used only with the BroCi authentication flow.

| Domain | Full URL Pattern | Purpose | HTTP Method | Auth Context | When Used | Auth Flow(s) | Microsoft-Owned | Security Relevance |
|---|---|---|---|---|---|---|---|---|
| api.azrbac.mspim.azure.com | `https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources?$select=id,displayName&$top=999` | Retrieve list of PIM-enabled groups | GET | PimForGroupAzrbac | Conditional (BroCi flow, PIM for Groups) | BroCi, BroCiManualCode, BroCiToken | Yes | Undocumented API; may change without notice |

---

## Authentication Client IDs Used

The following Microsoft first-party client application IDs are used across different authentication flows:

| Client ID | Application Name | Used For | Auth Flows |
|---|---|---|---|
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Microsoft Azure CLI | Main Graph auth (non-BroCi), ARM refresh, PIM refresh | AuthCode, DeviceCode, ManualCode |
| `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | Azure Portal | BroCi initial auth and as brk_client_id in broker refreshes | BroCi, BroCiManualCode, BroCiToken |
| `74658136-14ec-4630-ad9b-26e160ff0fc6` | Azure Portal (Ibiza) | BroCi Graph token, ARM token, PIM for Entra token via broker refresh | BroCi, BroCiManualCode, BroCiToken |
| `50aaa389-5a33-4f1a-91d7-2c45ecd8dac8` | Azure PIM Portal | PIM for Groups Graph and azrbac tokens via BroCi broker refresh | BroCi, BroCiManualCode, BroCiToken |
| `1b730954-1685-4b74-9bfd-dac224a7b894` | Azure AD PowerShell | PIM for Groups auth (non-BroCi) | AuthCode, DeviceCode, ManualCode |
| `51f81489-12ee-4a9e-aaae-a2591f45987d` | Azure Portal PIM | PIM for Entra Roles auth (non-BroCi) | AuthCode, DeviceCode, ManualCode |
| `80ccca67-54bd-44ab-8625-4b79c4dc7775` | Microsoft Security | Security Findings special auth (device registration policy, auth strengths) | AuthCode, ManualCode |

---

## Request Volume Characteristics

For a typical medium-sized tenant (500 users, 200 groups, 100 enterprise apps, 50 app registrations):

| Request Category | Estimated HTTP Requests | Sub-Requests |
|---|---|---|
| Authentication (token requests) | 5-10 | N/A |
| Direct Graph API calls | 20-40 | N/A |
| Graph Batch requests (main enumeration) | 30-60 | 600-1200 |
| Graph Batch pagination (follow-up) | 10-30 | 200-600 |
| ARM API calls | 3-10 | N/A |
| PIM API calls | 1-5 | N/A |
| **Total** | **~70-155** | **~800-1800** |

The batch request pattern -- frequent POST requests to `/$batch` with 20 sub-requests each, followed by pagination -- is a distinctive fingerprint that can be used for detection.

---

## Network Security Summary

All endpoints are Microsoft-owned and accessed over HTTPS/TLS. No third-party endpoints are contacted during normal operation. The single exception is the `api.azrbac.mspim.azure.com` endpoint, which is Microsoft-owned but undocumented.

The tool does not implement certificate pinning, but relies on the operating system's TLS trust store. A `-Proxy` parameter is available for traffic inspection via tools like Burp Suite or Fiddler, and the `Send-ApiRequest` module supports `-SkipCertificateCheck` for use with intercepting proxies.
