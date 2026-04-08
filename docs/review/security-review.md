# EntraFalcon Security Review

This document provides a comprehensive security review of the EntraFalcon tool, covering token handling, output rendering, file operations, clipboard usage, trust boundaries, secrets exposure, and detection evasion.

---

## Token Handling

### Cleartext Token Storage

All tokens -- access tokens and refresh tokens -- are stored in PowerShell global variables in cleartext. The affected variables include:

| Global Variable | Purpose |
|---|---|
| `$GLOBALMsGraphAccessToken` | Primary Microsoft Graph access/refresh token |
| `$GLOBALArmAccessToken` | Azure Resource Manager access/refresh token |
| `$GLOBALPIMsGraphAccessToken` | PIM for Entra Roles Graph access/refresh token |
| `$GLOBALPimForGroupAccessToken` | PIM for Groups Graph access/refresh token |
| `$GLOBALPimForGroupAzrbacAccessToken` | PIM for Groups azrbac API access/refresh token |
| `$GLOBALBrociAccessToken` | BroCi (Azure Portal) refresh token |
| `$GLOBALSecurityFindingsGraphAccessTokenSpecial` | Security Findings special Graph token |

These tokens remain in memory for the entire duration of the script execution. The `Start-CleanUp` function (defined in `shared_Functions.psm1`) removes these global variables when the script completes normally. However, if the script crashes, is interrupted (Ctrl+C without a trap), or the user's PowerShell session remains open, the tokens persist in the session's global scope and can be retrieved by any code running in that same session.

No encryption or `SecureString` storage is used for any token at any point.

### BroCiToken Parameter Exposure

The `-BroCiToken` parameter accepts a refresh token as a plaintext string on the command line:

```
.\run_EntraFalcon.ps1 -AuthFlow BroCiToken -BroCiToken "1.AXY..."
```

This is problematic because:

- The token value is visible in the process list (e.g., via `Get-Process` or Task Manager command line column on Windows, `/proc/*/cmdline` on Linux).
- The token is recorded in shell history (PowerShell `PSReadLine` history, bash `~/.bash_history`, fish `~/.local/share/fish/fish_history`).
- The token value is stored in the `$GLOBALAuthMethods` hashtable as a global variable.

The tool does validate that the token starts with `1.` (expected for Azure refresh tokens) and rejects tokens starting with `ey` (JWTs / access tokens), but no further protection is applied.

### Token Expiration Handling

Token expiration is checked with a 30-minute buffer before API calls (via `Invoke-CheckTokenExpiration`). When a token is near expiry, the tool automatically refreshes it using the stored refresh token. The refresh operation replaces the global variable value with the new token object. This means:

- If a refresh fails, the old (expired) token remains in the global variable.
- The refresh request itself transmits the refresh token over HTTPS to `login.microsoftonline.com`.

---

## XSS Risk (Acknowledged in README)

HTML reports render tenant data without HTML sanitization. An attacker who controls any display name, description, UPN, group name, or dynamic membership rule in the tenant could inject JavaScript into reports.

### How Data Flows into Reports

1. Tenant data is collected via Microsoft Graph API and Azure ARM API.
2. Data is assembled into PowerShell objects.
3. These objects are serialized to JSON and embedded in HTML reports inside `<script id="mainTableData" type="application/json">` blocks.
4. Client-side JavaScript (`GLOBALJavaScript_Table`) deserializes the JSON and renders it into HTML table cells.
5. The Security Findings report additionally embeds finding descriptions and affected object names/identifiers.

### Specific Injection Points

| Data Source | Rendered In | Risk |
|---|---|---|
| User display names / UPNs | User report, Role report, Security Findings | XSS via display name |
| Group display names | Group report, Role report, CAP report, Security Findings | XSS via group name |
| Group descriptions | Group report detail views | XSS via description |
| Dynamic group membership rules | Group report detail views | XSS via membership rule |
| Enterprise App display names | Enterprise App report, Security Findings | XSS via app name |
| Enterprise App publisher names | Enterprise App report | XSS via publisher |
| App Registration display names | App Registration report | XSS via app name |
| Managed Identity display names | Managed Identity report | XSS via identity name |
| Role definition display names | Role report, PIM report | XSS via custom role name |
| Administrative Unit names | Multiple reports | XSS via AU name |
| Finding descriptions and affected objects | Security Findings report | XSS via any controlled name |

### Current Mitigations

The reports use a mix of `innerHTML` and `innerText` in JavaScript rendering. The JSON data is embedded via `type="application/json"` script tags, which prevents direct script execution from the JSON block itself. However, once the data is deserialized and inserted into DOM elements, unsanitized values can still execute if inserted via `innerHTML`.

### Recommendation

Sanitize all tenant-derived data before HTML rendering. Apply HTML entity encoding (`<` to `&lt;`, `>` to `&gt;`, `"` to `&quot;`, `'` to `&#39;`, `&` to `&amp;`) to every value sourced from the tenant before it is rendered in any HTML context.

---

## CSV Injection Risk

### How CSV Export Works

CSV export is performed entirely client-side in JavaScript. The export function extracts visible table data from the HTML report and constructs a CSV file for download.

### The Risk

Values containing formula-triggering characters (`=`, `+`, `-`, `@`) at the start of a cell value could trigger formula injection when the CSV file is opened in Microsoft Excel or other spreadsheet applications. Tenant-controlled data such as display names, descriptions, and UPNs could contain these characters.

### Current Mitigations

No CSV sanitization is performed. There is no prefixing of values with a single quote, tab character, or other neutralization technique.

### Recommendation

Prefix CSV cell values that begin with `=`, `+`, `-`, or `@` with a single quote or tab character to prevent formula interpretation.

---

## Path Traversal / File Write

### Output Folder Handling

The output folder is user-controlled via the `-OutputFolder` parameter. When not specified, it defaults to `Results_<TenantDisplayName>_<Timestamp>`.

The only validation performed is:
1. Check if the directory already exists (`Test-Path`).
2. Attempt to create it (`New-Item -ItemType Directory`).
3. If creation fails, abort.

### Tenant Name in File Paths

Filenames are derived from the tenant display name combined with a timestamp:
```
SecurityFindings_<Timestamp>_<TenantDisplayName>.html
```

A malicious tenant display name could potentially influence file paths. For example, a display name containing `..` or path separator characters could attempt to write files outside the intended output directory. However, PowerShell's `New-Item` and `Set-Content` cmdlets may sanitize or reject invalid path characters on most platforms.

### Current Mitigations

There is no explicit sanitization of the tenant display name before it is used in file paths. The tool relies on the operating system and PowerShell to reject invalid characters.

### Recommendation

Sanitize the tenant display name by removing or replacing characters that are invalid in file paths (`/`, `\`, `:`, `*`, `?`, `"`, `<`, `>`, `|`, `..`).

---

## Clipboard Usage

### ManualCode Flow

The ManualCode authentication flow:
1. Writes the full authentication URL to the clipboard (`Set-Clipboard $Url`).
2. Prompts the user to authenticate in a browser.
3. Reads the redirected URL (containing the authorization code) from the clipboard (`Get-Clipboard`).

### DeviceCode Flow

The DeviceCode authentication flow:
1. Writes the user code to the clipboard (`Set-Clipboard $DeviceCodeDetails.user_code`).

### Risks

- **Other applications can read the clipboard**: Any application running on the same desktop session can access clipboard contents. This includes the authentication URL (which contains the OAuth state parameter), the authorization code, and the device code.
- **Clipboard history**: Windows 10/11 clipboard history (Win+V) may retain these values even after the clipboard is overwritten. Third-party clipboard managers may also persist the data.
- **Authorization codes are short-lived**: The authorization code is single-use and short-lived, reducing the window for exploitation. However, the authentication URL and state parameter remain valid until used.

### Recommendation

Document the clipboard exposure risk. Consider clearing the clipboard after reading the authorization code. Warn users to disable clipboard history during assessment runs.

---

## Trust Boundaries

### Tenant Data as Untrusted Input

The fundamental trust boundary in EntraFalcon is between collected tenant data (untrusted, attacker-controllable) and the report rendering context (trusted, executing JavaScript in the user's browser).

| Trust Boundary | Current State |
|---|---|
| API response data -> PowerShell objects | No schema validation; API responses are trusted as-is |
| PowerShell objects -> JSON in reports | No sanitization of values |
| JSON in reports -> HTML DOM rendering | Partial; uses JSON script tags but still renders unsanitized values |
| Batch response IDs | Trusted without verification; batch sub-request IDs are matched to original request IDs by string comparison |

### No Separation of Concerns

There is no architectural boundary between the data collection phase and the report rendering phase. The same functions that collect data also format it for output. A compromised or malicious API response would flow directly into the report without any intermediate validation or sanitization step.

### Batch Response ID Trust

When batch requests are sent to the Graph API, the response includes sub-request IDs that are matched back to original request IDs. The tool trusts these IDs without verification. In the `Invoke-GraphNextLinkBatch` function, pagination response IDs prefixed with `nl_` are parsed with string manipulation (`$resp.id -replace 'nl_', ''`) and used as array indices. A malicious response (in a man-in-the-middle scenario) could potentially cause incorrect data association, though HTTPS mitigates this significantly.

---

## Secrets in Output

### Report Contents

Generated reports contain sensitive tenant information:

| Data Type | Present In |
|---|---|
| Tenant object IDs | All reports |
| User UPNs and display names | User report, Role report, Security Findings |
| Group memberships and owners | Group report, User report |
| Role assignments (Entra ID and Azure) | Role report, User report, Group report |
| Enterprise App permissions (application and delegated) | Enterprise App report, Security Findings |
| App Registration credentials (expiry info, not secrets) | App Registration report |
| Conditional Access Policy configurations | CAP report, Security Findings |
| PIM role settings and eligible assignments | PIM report |
| Dynamic group membership rules | Group report |
| Administrative Unit memberships | Multiple reports |

### Output File Protection

- Reports are written as HTML, TXT, and optionally CSV files.
- No encryption is applied to any output file.
- No access control is set on output files; permissions inherit from the parent directory.
- The output folder is created with default permissions (`New-Item -ItemType Directory`).

### Recommendation

Document that output files contain sensitive tenant data and should be protected accordingly. Consider setting restrictive permissions on the output directory at creation time. Warn users to encrypt or secure report files when transmitting them.

---

## Detection Evasion

### Configurable UserAgent

The `-UserAgent` parameter allows the user to set a custom User-Agent header for all HTTP requests:

```powershell
.\run_EntraFalcon.ps1 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

This could be used to impersonate legitimate tools or browsers in sign-in logs and network monitoring.

The default User-Agent is `EntraFalcon`, which is transparent and identifiable.

### What Cannot Be Spoofed

- **Application IDs**: The client IDs used during authentication (e.g., `04b07795-8ddb-461a-bbee-02f9e1bf7b46` for Azure CLI, `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` for Azure Portal) appear in Entra ID sign-in logs and cannot be altered by the tool.
- **Token issuance patterns**: The specific sequence of token requests (initial auth, refresh for different APIs, BroCi broker pattern) creates a distinctive fingerprint.
- **Batch request patterns**: The high volume of batch requests with 20 sub-requests each is characteristic of automated enumeration tools.

### Additional Detection Indicators

The EntraTokenAid module sends specific HTTP headers that emulate Azure CLI or MSAL.Python:

| Header | Value |
|---|---|
| `X-Client-Sku` | `MSAL.Python` |
| `X-Client-Ver` | `1.31.0` |
| `X-Client-Os` | `win32` |

These headers are sent on token endpoint requests and could be used for detection if the actual client is not Python-based.
