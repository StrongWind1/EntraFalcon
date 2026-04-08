# Automating EntraFalcon with roadtx PRT on Windows

---

## Summary

This guide sets up a daily automated EntraFalcon scan on Windows using PowerShell 5.1. No EntraFalcon code is modified. The authentication is handled entirely by roadtx using a device-registered Primary Refresh Token enriched with MFA claims.

We chose this path specifically because it produces the most fully featured token available in Azure AD. A device-registered PRT with MFA enrichment satisfies every Conditional Access policy you're likely to encounter: MFA required, compliant device, Azure AD joined device. Tokens minted from this PRT work across every Microsoft API that EntraFalcon needs (Graph, ARM, PIM, Security Findings) without additional authentication prompts.

The alternative approaches all have gaps. Client credentials can't carry MFA claims. Regular refresh tokens eventually expire and can't satisfy device policies. Deviceless PRTs can't be enriched after the fact because converting the enriched refresh token back into a PRT requires a device certificate. The device-registered path with prtenrich is the only flow where MFA is guaranteed at every step and the PRT renews indefinitely.

The tradeoff is a few extra commands during initial setup. After that, the daily automation is three commands: renew, mint, scan.

---

## What you need before starting

1. Python 3.8 or newer installed on the Windows machine that will run the scheduled task
2. roadtx: `pip install roadtx`
3. Firefox and geckodriver (for the one-time MFA enrichment step): download geckodriver from https://github.com/mozilla/geckodriver/releases and put it somewhere in your system PATH
4. PowerShell 5.1 (ships with Windows 10/11 and Server 2016+)
5. EntraFalcon downloaded to `C:\EntraFalcon\EntraFalcon\`
6. A user account with the Global Reader role in your target tenant
7. That user account must be able to complete MFA (you will do this once during setup)
8. Optional: Reader role on one or more Azure subscriptions if you want the Azure IAM assessment

Create a working directory for the scanner files:

```
mkdir C:\EntraFalcon
cd C:\EntraFalcon
```

All roadtx commands in this guide should be run from `C:\EntraFalcon`.

---

## Manual setup (one time, interactive)

These steps require you at a keyboard. You will sign in, complete MFA, and generate the files that the automation uses. After this section is done you won't need to touch it again unless something expires.

### Step 1: Get an access token for device registration

```
roadtx gettokens --device-code -c dd762716-544d-4aeb-a526-687b73838a22 -r urn:ms-drs:enterpriseregistration.windows.net -t yourtenant.onmicrosoft.com
```

This prints a device code and a URL. Open a browser, go to https://microsoft.com/devicelogin, type in the code, and sign in with your Global Reader account. Complete MFA if prompted. When the browser says "You have signed in," go back to the terminal. The token is saved to `.roadtools_auth` in the current directory.

### Step 2: Register a device in Azure AD

```
roadtx device -a join -n "ENTRAFALCON-SCANNER" -c scanner.pem -k scanner.key
```

This creates a cloud-joined device called `ENTRAFALCON-SCANNER` in your tenant. Two files appear in the current directory:

- `scanner.pem` is the device certificate signed by Azure AD
- `scanner.key` is the private key for that certificate

These files are the device's identity. Keep them in `C:\EntraFalcon` and lock down permissions later.

### Step 3: Request the initial PRT

```
roadtx prt -a request -c scanner.pem -k scanner.key -u globalreader@yourtenant.onmicrosoft.com -p "YourPassword" -t yourtenant.onmicrosoft.com -f scanner.prt
```

This creates `scanner.prt` containing the PRT and its session key. The PRT at this point does not have MFA claims because username and password authentication is single factor. The next two steps fix that.

### Step 4: Enrich the PRT with MFA

```
roadtx prtenrich -f scanner.prt
```

A Firefox window opens automatically. Your existing PRT handles the password portion of sign in, so you skip straight to the MFA prompt. Complete MFA however your tenant requires (authenticator app push, SMS code, FIDO key, etc.).

When it finishes, roadtx saves a refresh token to `.roadtools_auth`. This refresh token carries the MFA claim. The PRT in `scanner.prt` does not have MFA yet though. The next step converts that refresh token into a proper enriched PRT.

If you have a TOTP seed for your authenticator app, you can automate this step:

```
roadtx prtenrich -f scanner.prt --otpseed "JBSWY3DPEHPK3PXP"
```

### Step 5: Create the enriched PRT

Extract the refresh token from `.roadtools_auth` and use it to request a new PRT:

```
python -c "import json; print(json.load(open('.roadtools_auth'))['refreshToken'])"
```

Copy that value, then run:

```
roadtx prt -a request -c scanner.pem -k scanner.key --refresh-token PASTE_THE_REFRESH_TOKEN_HERE -t yourtenant.onmicrosoft.com -f scanner.prt
```

This overwrites `scanner.prt` with a new PRT that carries MFA claims. This is the PRT your automation will use going forward.

### Step 6: Verify MFA claims

Mint a test token and inspect it:

```
roadtx prtauth -f scanner.prt -c c44b4083-3bb0-49c1-b47d-974e53cbdf3c -r https://graph.microsoft.com --tokens-stdout > test_token.json
roadtx describe test_token.json
```

Look at the `amr` field in the decoded output. It should contain `mfa` or `ngcmfa`. If it does, the enrichment worked and your PRT is fully featured.

Also check the `refreshToken` field in `test_token.json`. EntraFalcon expects refresh tokens that start with `"1."` (the Azure Portal format). Confirm the prefix before moving on.

### Step 7: Test an actual EntraFalcon run

Before automating, verify the full flow works end to end. This is the same thing the automation script will do, just done by hand so you can see it work:

```
roadtx prt -a renew -f scanner.prt
roadtx prtauth -f scanner.prt -c c44b4083-3bb0-49c1-b47d-974e53cbdf3c -r https://graph.microsoft.com --tokens-stdout > tokens.json
```

Then in PowerShell:

```powershell
$tokens = Get-Content C:\EntraFalcon\tokens.json -Raw | ConvertFrom-Json
cd C:\EntraFalcon\EntraFalcon
.\run_EntraFalcon.ps1 -AuthFlow BroCiToken -BroCiToken $tokens.refreshToken -OutputFolder C:\EntraFalcon\reports\test -Csv -LogLevel Verbose
```

If the assessment completes and you see HTML reports in the output folder, everything is working. Clean up the test files:

```powershell
Remove-Item C:\EntraFalcon\tokens.json -Force
Remove-Item C:\EntraFalcon\test_token.json -Force
```

---

## What the automation does (step by step, explained)

The daily script does three things. Here's what each one is doing and why.

**1. Renew the PRT.** PRTs expire after about 14 days. Renewal extends the lifetime by another 14 days using just the session key stored in `scanner.prt`. No password, no MFA, no interaction. MFA claims carry forward through renewal. Running this daily means you always have at least 13 days of buffer, so even if the task fails for a week the PRT is still valid.

**2. Mint a refresh token for the Azure Portal client.** EntraFalcon's BroCiToken flow expects a refresh token from the Azure Portal client (`c44b4083-3bb0-49c1-b47d-974e53cbdf3c`). The `prtauth` command uses the PRT to get one. This refresh token inherits all the MFA and device claims from the PRT, so EntraFalcon can exchange it for tokens across all the APIs it needs (Graph, ARM, PIM, Security Findings) without hitting any Conditional Access blocks.

**3. Run EntraFalcon.** The script passes the refresh token to EntraFalcon's `-BroCiToken` parameter. EntraFalcon handles everything from there: exchanging for scoped tokens, enumerating the tenant, scoring risks, and writing the HTML/TXT/CSV reports.

---

## The automation script

Download [Run-ScheduledScan.ps1](https://github.com/StrongWind1/EntraFalcon/raw/main/docs/automation/Run-ScheduledScan.ps1) and save it to `C:\EntraFalcon\Run-ScheduledScan.ps1`. This script passes PSScriptAnalyzer with zero violations across all 75 rules at all severity levels.

Here is a summary of what the script contains:

```powershell
# See Run-ScheduledScan.ps1 for the complete, commented, PSSA-clean script.
# Summary of the structure:
#
# Parameters:  -ScanDir, -PrtFileName, -EntraFalconSubDir, -ReportSubDir,
#              -LogSubDir, -EntraFalconLogLevel, -IncludeCsv
#
# Functions:   Send-LogMessage      Writes to console + log file
#              Test-Prerequisite    Checks PRT file, EntraFalcon dir, roadtx in PATH
#              Invoke-PrtRenewal    Calls roadtx prt -a renew
#              Get-EntraFalconRefreshToken  Calls roadtx prtauth, parses JSON
#              Invoke-EntraFalconScan       Runs run_EntraFalcon.ps1 with splatting
#              Remove-ScanTokenFile         Cleans up temp credential file
#
# Main flow:   1. Preflight checks
#              2. Renew PRT
#              3. Mint refresh token
#              4. Run EntraFalcon
#              5. Clean up temp files
#              6. Exit 0 on success, 1 on any failure
```

---


## Setting up the scheduled task

Open Task Scheduler (`taskschd.msc`) and create a new task:

General tab:
- Name: `EntraFalcon Daily Scan`
- Security options: Run whether user is logged on or not
- Run with highest privileges: checked

Trigger tab:
- New trigger: Daily at 02:00

Action tab:
- Action: Start a program
- Program/script: `powershell.exe`
- Add arguments: `-NoProfile -ExecutionPolicy Bypass -File "C:\EntraFalcon\Run-ScheduledScan.ps1" -IncludeCsv`

Settings tab:
- Allow task to be run on demand: checked
- Stop the task if it runs longer than: 4 hours
- If the task is already running, do not start a new instance

---

## File security

After setup is complete, lock down the sensitive files. `scanner.prt` is the most sensitive because anyone who has it can mint MFA-stamped tokens as your Global Reader. `scanner.key` is the device private key.

```powershell
foreach ($File in @("C:\EntraFalcon\scanner.prt", "C:\EntraFalcon\scanner.key", "C:\EntraFalcon\scanner.pem")) {
    if (Test-Path $File) {
        $Acl = Get-Acl $File
        $Acl.SetAccessRuleProtection($true, $false)
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "Allow"
        )
        $Acl.AddAccessRule($Rule)
        Set-Acl $File $Acl
    }
}
```

---

## Maintenance

The PRT lasts about 14 days. The automation script renews it every run, so as long as the task runs at least once every two weeks the PRT stays alive and MFA claims carry forward.

The device certificate lasts about a year. When it expires, re-run steps 1 through 6 of the manual setup.

You need to redo the manual setup if:
- The PRT expires because the task didn't run for more than 14 days
- An admin revokes the user's sessions in Azure AD
- An admin disables or deletes the ENTRAFALCON-SCANNER device in Azure AD
- The device certificate expires (yearly)

Password changes on the user account do not invalidate an active PRT. The PRT renews using the session key, not the password.

---

## Monitoring and revoking access

All sign ins from the PRT appear in Azure AD sign in logs under the device name ENTRAFALCON-SCANNER. Set up a SIEM alert for this device name to track when scans run and catch anything unexpected.

To shut down the scanner immediately:
1. Azure AD > Devices > search for ENTRAFALCON-SCANNER > Disable or Delete
2. Azure AD > Users > find the Global Reader account > Revoke sessions
3. Delete `scanner.prt`, `scanner.key`, and `scanner.pem` from disk

Disabling the device invalidates all tokens derived from the PRT right away.

---

## Troubleshooting

**PRT renewal fails.** The PRT expired. Re-run the manual setup from step 1.

**Refresh token prefix is not "1.".** EntraFalcon expects the Azure Portal refresh token format which starts with "1." Try adding an explicit scope to the prtauth command:

```
roadtx prtauth -f scanner.prt -c c44b4083-3bb0-49c1-b47d-974e53cbdf3c -s "openid offline_access https://graph.microsoft.com/.default" --tokens-stdout
```

If it still comes back with a different prefix, use EntraFalcon's DeviceCode flow once interactively to get a valid BroCi token, then let the PRT renewal keep it alive going forward.

**EntraFalcon fails on a specific API.** EntraFalcon authenticates to multiple APIs (Graph, ARM, PIM, Security Findings). Check the log to see which one failed. Common causes: the Global Reader role was removed, a Conditional Access policy is blocking the token, or the Reader role on Azure subscriptions was removed (only affects the Azure IAM section).

**Geckodriver won't start during prtenrich.** Make sure the geckodriver version matches your installed Firefox version. If you don't want to deal with Firefox at all, use `--otpseed` with your TOTP authenticator seed to skip the browser entirely.

**MFA claims missing after enrichment.** Run `roadtx describe test_token.json` and check the `amr` field. If it doesn't contain `mfa` or `ngcmfa`, the enrichment didn't stick. Re-run steps 4 and 5 of the manual setup, making sure you complete the MFA prompt fully before the browser window closes.
