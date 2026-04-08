# EntraFalcon Network Interactions and Detection

This document catalogs every network interaction made by EntraFalcon, including authentication endpoints, API calls, application identifiers, and detection opportunities.

---

## Authentication Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` | GET (browser) | Authorization code request |
| `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | POST | Token exchange and refresh |
| `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` | POST | Device code flow initiation |

---

## Microsoft Graph API

All Graph API calls target `graph.microsoft.com`.

### Direct Requests

| Endpoint | API Version | Method | Purpose |
|----------|-------------|--------|---------|
| `/organization` | Beta | GET | Tenant information |
| `/subscribedSkus` | v1.0 | GET | License detection |
| `/reports/authenticationMethods/userRegistrationDetails` | Beta | GET | MFA status |
| `/users` | Beta | GET | User enumeration |
| `/devices` | Beta | GET | Device enumeration |
| `/directory/administrativeUnits` | Beta | GET | Admin units and members |
| `/identity/conditionalAccess/policies` | Beta | GET | Conditional Access Policy enumeration |
| `/identity/conditionalAccess/namedLocations` | Beta | GET | Named locations |
| `/identity/conditionalAccess/authenticationStrength/policies` | Beta | GET | Authentication strength policies |
| `/roleManagement/directory/roleDefinitions` | Beta | GET | Role definitions |
| `/roleManagement/directory/roleAssignments` | v1.0 | GET | Active role assignments |
| `/roleManagement/directory/roleEligibilitySchedules` | Beta | GET | PIM eligible assignments |
| `/policies/roleManagementPolicies` | Beta | GET | PIM settings |
| `/policies/roleManagementPolicyAssignments` | Beta | GET | PIM policy assignments |
| `/policies/authorizationPolicy` | Beta | GET | Authorization policy |
| `/policies/deviceRegistrationPolicy` | Beta | GET | Device registration policy |
| `/settings` | Beta | GET | Tenant directory settings |
| `/groups` | Beta | GET | Group enumeration |
| `/applications` | Beta | GET | App registration enumeration |
| `/servicePrincipals` | Beta | GET | Enterprise app and managed identity enumeration |
| `/reports/servicePrincipalSignInActivities` | Beta | GET | Service principal sign-in activity |
| `/identityGovernance/privilegedAccess/group/eligibilitySchedules` | Beta | GET (batch) | PIM for Groups |
| `/directoryRoleTemplates` | Beta | GET | Role template names |
| `/me` | Beta | GET | Authentication check |
| `/directoryObjects/getByIds` | Beta | POST | Object resolution by ID |
| `/$batch` | v1.0 / Beta | POST | Batch requests |

### Batch Sub-Requests

Batch payloads (`/$batch`) contain sub-requests targeting the following endpoints:

**User-scoped:**
- `/users/{id}/transitiveMemberOf`
- `/users/{id}/ownedObjects`
- `/users/{id}/ownedDevices`
- `/users/{id}/registeredDevices`

**Group-scoped:**
- `/groups/{id}/members`
- `/groups/{id}/owners`
- `/groups/{id}/appRoleAssignments`

**Service principal-scoped:**
- `/servicePrincipals/{id}/appRoleAssignments`
- `/servicePrincipals/{id}/oauth2PermissionGrants`
- `/servicePrincipals/{id}/transitiveMemberOf`
- `/servicePrincipals/{id}/ownedObjects`
- `/servicePrincipals/{id}/owners`
- `/servicePrincipals/{id}/appRoleAssignedTo`

**Application-scoped:**
- `/applications/{id}/owners`
- `/applications/{id}/federatedIdentityCredentials`

---

## Azure ARM API

| Endpoint | Purpose |
|----------|---------|
| `https://management.azure.com/subscriptions?api-version=2022-12-01` | List subscriptions |
| `https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01` | Management groups |
| `https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01` | Active Azure role assignments |
| `https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01-preview` | Eligible Azure role assignments |
| `https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01` | Azure role definitions |

---

## PIM for Groups (BroCi Only)

| Endpoint | Purpose |
|----------|---------|
| `https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources` | PIM-enabled groups |

This endpoint is only used when the BroCi authentication mode is active.

---

## Application IDs

These application (client) IDs appear in Entra ID sign-in logs when EntraFalcon is used.

### Non-BroCi Flows

| Application ID | Name |
|----------------|------|
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure CLI |
| `1b730954-1685-4b74-9bfd-dac224a7b894` | Azure PowerShell |
| `51f81489-12ee-4a9e-aaae-a2591f45987d` | Managed Meeting Rooms |
| `80ccca67-54bd-44ab-8625-4b79c4dc7775` | Security Portal |

### BroCi Flows

| Application ID | Name |
|----------------|------|
| `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | Azure Portal |
| `74658136-14ec-4630-ad9b-26e160ff0fc6` | Azure Portal (Ibiza) |
| `50aaa389-5a33-4f1a-91d7-2c45ecd8dac8` | Microsoft_Azure_PIMCommon |

## Resource IDs

These resource identifiers appear in token requests as the target audience.

| Resource ID | Name | Purpose |
|-------------|------|---------|
| `00000003-0000-0000-c000-000000000000` | Microsoft Graph | Target for all Graph API tokens |
| `797f4846-ba00-4fd7-ba43-dac1f8f63013` | Windows Azure Service Management API | Target for Azure ARM tokens |
| `01fc33a7-78ba-4d2f-a4b7-768e336e890e` | Azure PIM/RBAC Service | Target for PIM for Groups azrbac API tokens (BroCi only) |

---

## User Agent

All API calls and token endpoint requests use the default user agent string `"EntraFalcon"`.

- Interactive sign-ins (browser-based) use the browser's native User-Agent header instead.
- The default can be overridden with the `-UserAgent` parameter on the entry point script.

---

## IP Addresses

There are no hardcoded IP addresses in the tool. All communication uses DNS-resolved domain names. Runtime IP addresses depend on the Azure region and DNS resolution at the time of execution.

---

## Detection Opportunities

### Sign-In Logs

Monitor Entra ID sign-in logs for the application IDs listed above. The combination of multiple app IDs from the same user session in a short time window is a strong indicator.

### Graph API Audit Logs

EntraFalcon generates a high volume of Microsoft Graph batch requests. Look for:
- Sustained bursts of `/$batch` POST requests.
- Broad enumeration patterns (users, groups, service principals, applications in rapid succession).

### User Agent String

The default user agent `"EntraFalcon"` is present on all API requests. However, this is trivially changed via the `-UserAgent` parameter, so absence of this string does not rule out usage.

### Behavioral Indicators

- **Multiple token acquisitions:** Rapid succession of token requests for different client application IDs from the same user/IP.
- **Broad scope requests:** A single session requesting data across users, groups, applications, roles, policies, and PIM in sequence.
- **PIM for Groups:** Requests to `api.azrbac.mspim.azure.com` are uncommon outside of Azure Portal usage and PIM administration tools.
- **Token refresh pattern:** Multiple refresh token exchanges from the same session as the tool cycles through different resource scopes.

### Network-Level

Monitor DNS queries and HTTPS connections to:
- `graph.microsoft.com`
- `management.azure.com`
- `login.microsoftonline.com`
- `api.azrbac.mspim.azure.com`

The combination of all four domains from a single host in a short time window is characteristic of EntraFalcon execution.
