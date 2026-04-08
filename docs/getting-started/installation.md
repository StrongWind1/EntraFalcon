# Installation Guide

## Requirements

### PowerShell

EntraFalcon requires one of the following PowerShell versions:

- **PowerShell 5.1** -- built into Windows 10 and later
- **PowerShell 7+** -- cross-platform (Windows, Linux, macOS)

No additional PowerShell modules need to be installed. All dependencies are vendored in the `modules/` directory and are imported automatically at runtime.

### Entra ID Permissions

| Role | Scope | Required? | Purpose |
|------|-------|-----------|---------|
| **Global Reader** | Entra ID tenant | **Mandatory** | Core enumeration of users, groups, apps, roles, policies, and PIM settings. The tool cannot function without this role. |
| **Reader** | Management Group or Subscription | Optional | Azure IAM assessment. Required only if you want to enumerate Azure role assignments. Must be granted on each Management Group or Subscription in scope. |

### Network Access

The host running EntraFalcon must be able to reach the following endpoints:

| Endpoint | Required? | Purpose |
|----------|-----------|---------|
| `login.microsoftonline.com` | **Yes** | OAuth2 authentication |
| `graph.microsoft.com` | **Yes** | Microsoft Graph API queries |
| `management.azure.com` | Optional | Azure Resource Manager API (Azure IAM assessment) |
| `api.azrbac.mspim.azure.com` | Optional | PIM for Groups enumeration (BroCi flows only) |

### Conditional Access

Ensure that Conditional Access Policies in the target tenant do not block the authentication flows you intend to use. Common blockers include:

- Policies requiring compliant or Entra-joined devices
- Policies restricting token issuance to specific applications
- Location-based policies that deny access from your assessment host

### Execution Policy

On Windows, the default PowerShell execution policy may prevent the script from running. If you encounter an execution policy error, set the policy to `Unrestricted` for the current process:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
```

This change applies only to the current PowerShell session and does not persist.

## Setup Steps

### 1. Clone the Repository

```bash
git clone https://github.com/CompassSecurity/EntraFalcon.git
cd EntraFalcon
```

### 2. Adjust Execution Policy (If Needed)

On Windows, run this in the PowerShell session where you will execute the tool:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
```

### 3. Run the Script

```powershell
.\run_EntraFalcon.ps1
```

There is no `Install-Module`, `pip install`, or `npm install` step. The script imports everything it needs from the vendored `modules/` directory.

## Platform Notes

### Windows

All six authentication flows are fully supported on Windows:

- `BroCi` (default)
- `AuthCode`
- `DeviceCode`
- `ManualCode`
- `BroCiManualCode`
- `BroCiToken`

### Linux and macOS

Only the following authentication flows work on Linux and macOS:

- `DeviceCode`
- `ManualCode`
- `BroCiManualCode`
- `BroCiToken`

**Why the restriction?**

- The `BroCi` and `AuthCode` flows rely on localhost HTTP listeners or Windows Forms components that are not available on non-Windows platforms.
- The embedded browser mode (`MiscUrl` in EntraTokenAid) uses `System.Windows.Forms.WebBrowser`, which is a Windows-only .NET component.

### Recommended Flow by Platform

| Platform | Recommended Flow | Command |
|----------|-----------------|---------|
| Windows | `BroCi` (default) | `.\run_EntraFalcon.ps1` |
| Linux | `DeviceCode` | `.\run_EntraFalcon.ps1 -AuthFlow DeviceCode` |
| macOS | `DeviceCode` | `.\run_EntraFalcon.ps1 -AuthFlow DeviceCode` |
