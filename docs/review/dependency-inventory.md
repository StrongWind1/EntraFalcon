## 1. Vendored PowerShell Modules

| Name | File | Source Repository | Type | Version | License | Required/Optional | Usage |
|------|------|-------------------|------|---------|---------|-------------------|-------|
| EntraTokenAid | modules/EntraTokenAid.psm1 | github.com/zh54321/EntraTokenAid | Vendored fork | v20260127 | Assumed MIT | Required | OAuth authentication — auth code flow, device code flow, token refresh, JWT parsing |
| Send-ApiRequest | modules/Send-ApiRequest.psm1 | github.com/zh54321/Send-ApiRequest | Vendored fork | Unknown | Assumed MIT | Required | Generic HTTP API client with retry, pagination, error parsing. Used for ARM API calls |
| Send-GraphRequest | modules/Send-GraphRequest.psm1 | github.com/zh54321/GraphRequest | Vendored fork | Unknown | Assumed MIT | Required | Microsoft Graph API client with retry, pagination. Used for single Graph requests |
| Send-GraphBatchRequest | modules/Send-GraphBatchRequest.psm1 | github.com/zh54321/GraphBatchRequest | Vendored fork | Unknown | Assumed MIT | Required | Graph Batch API client. Sends up to 20 sub-requests per batch with retry and pagination |

All four modules are forked and integrated — no external installation needed.

## 2. Embedded JavaScript Libraries

| Name | Version | License | Location | Purpose |
|------|---------|---------|----------|---------|
| Chart.js | 4.5.1 | MIT | Embedded in shared_Functions.psm1 $GLOBALJavaScript_Chart (lines 1824-1841) | Report charts: doughnut, bar, stacked bar charts in HTML reports |

Chart.js is a single minified JS blob embedded directly in the PowerShell string variable. No CDN fetch, fully offline. The version 4.5.1 is identified from the embedded source.

## 3. Built-in PowerShell/.NET Modules and Classes

| Module/Class | Type | Required By | Notes |
|-------------|------|-------------|-------|
| Microsoft.PowerShell.Management | Built-in PS module | All modules | Basic cmdlets (New-Item, Test-Path, etc.) |
| Microsoft.PowerShell.Utility | Built-in PS module | All modules | ConvertTo-Json, ConvertFrom-Json, Invoke-RestMethod, etc. |
| System.Net.HttpListener | .NET BCL | EntraTokenAid | Localhost HTTP server for auth code capture |
| System.Windows.Forms | .NET Framework | EntraTokenAid | Embedded browser for MiscUrl auth mode (Windows only) |
| System.Web.HttpUtility | .NET Framework | EntraTokenAid | URL encoding/decoding |
| System.Security.Cryptography.SHA256 | .NET BCL | EntraTokenAid | PKCE code challenge generation |
| System.Collections.Concurrent.ConcurrentQueue | .NET BCL | EntraTokenAid | Thread-safe queue for HTTP server communication |
| System.Collections.Generic.List | .NET BCL | Multiple modules | Dynamic collections |
| System.Collections.Generic.HashSet | .NET BCL | Check modules | Unique warning tracking |
| System.Text.StringBuilder | .NET BCL | Report modules | Efficient string building for TXT reports |
| System.IO.StreamReader | .NET BCL | Send-ApiRequest | Error response body reading |
| System.Net.Http.HttpResponseMessage | .NET Core | Send-ApiRequest | PS7 HTTP response handling |
| runspacefactory | PowerShell | EntraTokenAid | Parallel runspace for HTTP listener |

None of these require external installation — they are part of the PowerShell/Windows/.NET runtime.

## 4. External PowerShell Modules — NONE

The tool explicitly avoids requiring:
- Microsoft.Graph (Graph PowerShell SDK)
- Az (Azure PowerShell module)
- AzureAD (legacy Azure AD module)
- Any PSGallery module

This is validated by inspecting all files for Import-Module, #Requires, and using module statements. The only Import-Module calls are for the vendored modules in the modules/ directory.

## 5. External Executables — NONE

No calls to external executables beyond what PowerShell provides (Start-Process for browser, which is a standard OS operation).

## 6. Compatibility Notes

| Component | PS 5.1 (Windows) | PS 7 (Windows) | PS 7 (Linux) |
|-----------|-------------------|-----------------|---------------|
| System.Windows.Forms | Yes | Limited | No |
| System.Web.HttpUtility | Needs Add-Type | Available | Available |
| System.Net.HttpListener | Yes | Yes | Yes (limited) |
| Invoke-RestMethod | Yes | Yes (enhanced) | Yes |
| Set-Clipboard/Get-Clipboard | Yes | Yes | Varies |
| Start-Process (browser) | Yes | Yes | Yes (xdg-open) |

The System.Windows.Forms dependency is only used for the MiscUrl auth mode (non-localhost redirect URL), which is already documented as Windows-only. The main auth flows (localhost listener, ManualCode, DeviceCode) work cross-platform.

## 7. Runtime Network Dependencies

The tool requires network access to:
- login.microsoftonline.com (authentication)
- graph.microsoft.com (Graph API)
- management.azure.com (optional, Azure ARM)
- api.azrbac.mspim.azure.com (optional, BroCi PIM for Groups only)

No package managers, update checks, or telemetry calls are made.
