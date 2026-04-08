# EntraFalcon Dependencies

This document inventories all dependencies -- vendored modules, embedded libraries, and runtime requirements.

---

## Vendored PowerShell Modules

These modules are forked from their upstream repositories and included directly in the EntraFalcon repo. No external installation is required.

| Module | Source | Purpose | Version | License |
|--------|--------|---------|---------|---------|
| EntraTokenAid.psm1 | [github.com/zh54321/EntraTokenAid](https://github.com/zh54321/EntraTokenAid) | OAuth authentication flows | v20260127 | MIT |
| Send-ApiRequest.psm1 | [github.com/zh54321/Send-ApiRequest](https://github.com/zh54321/Send-ApiRequest) | Generic HTTP client with retry logic | Unknown | MIT |
| Send-GraphRequest.psm1 | [github.com/zh54321/GraphRequest](https://github.com/zh54321/GraphRequest) | Microsoft Graph API client | Unknown | MIT |
| Send-GraphBatchRequest.psm1 | [github.com/zh54321/GraphBatchRequest](https://github.com/zh54321/GraphBatchRequest) | Microsoft Graph Batch API client | Unknown | MIT |

All four are MIT-licensed.

---

## Embedded JavaScript Libraries

| Library | Purpose | Version | License |
|---------|---------|---------|---------|
| Chart.js | Report charts (doughnut, bar, stacked bar) | 4.5.1 | MIT |

Chart.js is embedded directly in the `$GLOBALJavaScript_Chart` variable within `shared_Functions.psm1` (lines 1824-1841). There is no CDN fetch at report generation time or when viewing reports. The library is fully self-contained and works offline.

---

## Built-in PowerShell / .NET Dependencies

The following .NET types and PowerShell cmdlets are used at runtime. These are part of the standard PowerShell/.NET runtime and do not require separate installation.

### .NET Types

| Type | Purpose |
|------|---------|
| `System.Net.HttpListener` | Localhost HTTP server for the authorization code flow callback |
| `System.Windows.Forms` | Embedded browser for the MiscUrl auth mode (Windows only) |
| `System.Web.HttpUtility` | URL encoding and decoding (may require `Add-Type` on PowerShell 5.1) |
| `System.Security.Cryptography.SHA256` | PKCE code challenge generation |
| `System.Collections.Concurrent.ConcurrentQueue` | Thread-safe communication between HTTP listener and main thread |

### PowerShell Cmdlets and Features

| Cmdlet / Feature | Purpose |
|------------------|---------|
| `Invoke-RestMethod` | All HTTP API calls |
| `ConvertTo-Json` / `ConvertFrom-Json` | Data serialization and deserialization |
| `Start-Process` | Browser launch for interactive auth flows |
| `Set-Clipboard` / `Get-Clipboard` | Clipboard access for ManualCode auth flow |
| `runspacefactory` | Parallel runspace creation for the HTTP listener |

---

## What Is NOT Required

EntraFalcon is deliberately self-contained. It does **not** depend on any of the following:

- **Microsoft.Graph PowerShell SDK** -- Graph calls are made directly via `Invoke-RestMethod` through the vendored `Send-GraphRequest` module.
- **Az PowerShell module** -- ARM calls are made directly via the vendored `Send-ApiRequest` module.
- **AzureAD PowerShell module** -- Not used; the tool targets Microsoft Graph exclusively.
- **Any module from PSGallery** -- No `Install-Module` calls are required.

---

## System Requirements

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 5.1 (Windows) or 7+ (cross-platform) |
| **Network access** | HTTPS connectivity to Microsoft endpoints (see [network-and-detection.md](network-and-detection.md)) |
| **Clipboard access** | Required for ManualCode authentication flows (`Set-Clipboard` / `Get-Clipboard`) |
| **Browser access** | Required for interactive authentication flows (authorization code, device code confirmation) |

### Platform-Specific Notes

- **Windows (PowerShell 5.1):** `System.Web.HttpUtility` may need to be loaded explicitly via `Add-Type`. `System.Windows.Forms` is available for the embedded browser auth mode.
- **Windows (PowerShell 7+):** Full functionality. `System.Windows.Forms` may or may not be available depending on the .NET runtime variant.
- **Linux / macOS (PowerShell 7+):** `System.Windows.Forms` is not available; the MiscUrl embedded browser auth mode will not work. All other authentication flows function normally.
