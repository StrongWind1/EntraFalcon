<#
    .SYNOPSIS
        Automated daily EntraFalcon assessment using a roadtx PRT.

    .DESCRIPTION
        EntraFalcon is a PowerShell tool that audits your Azure AD (Entra ID)
        tenant for security issues. It checks users, groups, apps, roles, and
        Conditional Access policies, then produces HTML/TXT/CSV reports.

        EntraFalcon needs an authenticated session to talk to Microsoft's APIs.
        This script handles that authentication automatically using a Primary
        Refresh Token (PRT) managed by roadtx, a Python tool for Azure AD
        token operations.

        The workflow is:
          1. Renew the PRT so it does not expire (PRTs last about 14 days)
          2. Use the PRT to get a refresh token for the Azure Portal client
          3. Pass that refresh token to EntraFalcon's -BroCiToken parameter
          4. EntraFalcon runs the full tenant assessment and writes reports

        This script is designed to run unattended via Windows Task Scheduler.
        If any step fails, it logs the error and exits with code 1 so Task
        Scheduler marks the run as failed.

    .PARAMETER ScanDir
        Root directory where scanner files, EntraFalcon, reports, and logs
        are stored. Default: C:\EntraFalcon

    .PARAMETER PrtFileName
        Name of the PRT file (created during manual setup with roadtx).
        This file contains the Primary Refresh Token and its session key.
        Default: scanner.prt

    .PARAMETER EntraFalconSubDir
        Folder name inside ScanDir where EntraFalcon is installed.
        Default: EntraFalcon

    .PARAMETER ReportSubDir
        Folder name inside ScanDir where daily report folders are created.
        Each run creates a subfolder named by date (e.g. reports\2026-03-23).
        Default: reports

    .PARAMETER LogSubDir
        Folder name inside ScanDir where log files are written.
        Default: logs

    .PARAMETER EntraFalconLogLevel
        How much detail EntraFalcon writes to the console during the scan.
        Off shows nothing, Verbose shows progress, Debug and Trace show
        internal details useful for troubleshooting.
        Default: Verbose

    .PARAMETER IncludeCsv
        When set, EntraFalcon also produces CSV files alongside the HTML
        and TXT reports. Useful if you want to import results into Excel
        or a SIEM.

    .EXAMPLE
        .\Run-ScheduledScan.ps1
        Runs with all defaults. Expects files in C:\EntraFalcon.

    .EXAMPLE
        .\Run-ScheduledScan.ps1 -ScanDir D:\Security\EntraFalcon -IncludeCsv
        Runs from a custom directory and includes CSV output.

    .NOTES
        Prerequisites:
          - roadtx (install with: pip install roadtx)
          - EntraFalcon (download from GitHub)
          - PowerShell 5.1 or newer
          - A PRT file created by following the manual setup steps in
            automated_entrafalcon_guide.md

        If this script fails with "PRT renewal failed", the PRT has expired
        and you need to redo the manual setup steps (interactive, about 5 min).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ScanDir = 'C:\EntraFalcon',

    [Parameter(Mandatory = $false)]
    [string]$PrtFileName = 'scanner.prt',

    [Parameter(Mandatory = $false)]
    [string]$EntraFalconSubDir = 'EntraFalcon',

    [Parameter(Mandatory = $false)]
    [string]$ReportSubDir = 'reports',

    [Parameter(Mandatory = $false)]
    [string]$LogSubDir = 'logs',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Off', 'Verbose', 'Debug', 'Trace')]
    [string]$EntraFalconLogLevel = 'Verbose',

    [Parameter(Mandatory = $false)]
    [switch]$IncludeCsv
)

# Stop on any unhandled error. Combined with try/catch in each function,
# this makes sure failures are always caught and logged rather than silent.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------
# Build all file and directory paths from the parameters above.
# Everything lives under $ScanDir so there is one place to configure.
# -----------------------------------------------------------------

# Path to the PRT file created during manual setup with roadtx
$PrtFile = Join-Path -Path $ScanDir -ChildPath $PrtFileName

# Path to the EntraFalcon installation (contains run_EntraFalcon.ps1)
$EntraFalconDir = Join-Path -Path $ScanDir -ChildPath $EntraFalconSubDir

# Today's date, used for report folder names and log file names
$DateStamp = Get-Date -Format 'yyyy-MM-dd'

# Each day's reports go in their own dated subfolder
$OutputDir = Join-Path -Path $ScanDir -ChildPath (Join-Path -Path $ReportSubDir -ChildPath $DateStamp)

# All log files go in one folder, named by date
$LogDir  = Join-Path -Path $ScanDir -ChildPath $LogSubDir
$LogFile = Join-Path -Path $LogDir -ChildPath "scan-$DateStamp.log"

# Temporary file for the JSON token response from roadtx. Uses a random
# name so multiple runs can't collide. Deleted after use.
$TokenFile = Join-Path -Path $env:TEMP -ChildPath "entrafalcon-tokens-$([guid]::NewGuid().ToString('N')).json"

# This is the Azure Portal's OAuth client ID. EntraFalcon's BroCiToken
# flow requires a refresh token issued to this specific client. roadtx
# uses it when minting tokens from the PRT.
$AzurePortalClientId = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'

# -----------------------------------------------------------------
# Send-LogMessage
#
# Writes a timestamped message to both the console and a log file.
# Uses Write-Information instead of Write-Host so the output can be
# captured by the PowerShell pipeline if needed (also passes PSSA
# linting). The -InformationAction Continue makes it visible in the
# console even though it is an information stream message.
# -----------------------------------------------------------------
function Send-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Line = "[$Timestamp] [$Level] $Message"

    # Show in the console
    Write-Information -MessageData $Line -InformationAction Continue

    # Append to the daily log file. SilentlyContinue so a locked log
    # file does not crash the entire scan.
    Add-Content -Path $LogFile -Value $Line -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------
# Test-Prerequisite
#
# Checks that everything the script needs is in place before doing
# any real work. Returns $true if all checks pass, $false if any
# fail. Logs a specific error for each missing item so the operator
# knows exactly what to fix.
# -----------------------------------------------------------------
function Test-Prerequisite {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $Pass = $true

    # The PRT file is created during the one-time manual setup with
    # roadtx. Without it there is no way to authenticate.
    if (-not (Test-Path -Path $PrtFile)) {
        Send-LogMessage -Message "PRT file not found: $PrtFile" -Level ERROR
        $Pass = $false
    }

    # EntraFalcon must be installed in the expected subdirectory.
    if (-not (Test-Path -Path $EntraFalconDir)) {
        Send-LogMessage -Message "EntraFalcon directory not found: $EntraFalconDir" -Level ERROR
        $Pass = $false
    }

    # roadtx is a Python tool that handles PRT operations. It must be
    # installed (pip install roadtx) and available in the system PATH.
    $RoadtxCmd = Get-Command -Name 'roadtx' -ErrorAction SilentlyContinue
    if ($null -eq $RoadtxCmd) {
        Send-LogMessage -Message "roadtx not found in PATH. Install with: pip install roadtx" -Level ERROR
        $Pass = $false
    }

    return $Pass
}

# -----------------------------------------------------------------
# Invoke-PrtRenewal
#
# A PRT (Primary Refresh Token) expires after about 14 days. This
# function asks roadtx to renew it, which extends the lifetime by
# another 14 days. Renewal uses the session key stored in the PRT
# file and does not need a password or any user interaction.
#
# If renewal fails, the PRT has probably expired and the operator
# needs to redo the manual setup steps.
#
# Returns $true on success, $false on failure.
# -----------------------------------------------------------------
function Invoke-PrtRenewal {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Send-LogMessage -Message "Renewing PRT..."

    # roadtx is a Python CLI. We call it as an external process.
    # 2>&1 captures both stdout and stderr so we can log errors.
    $Output = & roadtx prt -a renew -f $PrtFile 2>&1

    # $LASTEXITCODE is set by external processes. 0 means success.
    if ($LASTEXITCODE -ne 0) {
        Send-LogMessage -Message "PRT renewal failed (exit code $LASTEXITCODE)" -Level ERROR
        Send-LogMessage -Message "roadtx output: $Output" -Level ERROR
        Send-LogMessage -Message "The PRT may have expired. Re-run the manual setup steps." -Level ERROR
        return $false
    }

    Send-LogMessage -Message "PRT renewed"
    return $true
}

# -----------------------------------------------------------------
# Get-EntraFalconRefreshToken
#
# Uses the PRT to get a refresh token for the Azure Portal client.
# EntraFalcon's -BroCiToken parameter expects a refresh token from
# this specific client (c44b4083-3bb0-49c1-b47d-974e53cbdf3c).
#
# roadtx's "prtauth" command does the token exchange: it takes the
# PRT, signs a request with the session key, and Azure AD returns
# a fresh access token and refresh token for the requested client.
#
# The token is written to a temporary JSON file, parsed, validated,
# and returned as a string. The temp file is cleaned up separately.
#
# Returns the refresh token string on success, $null on failure.
# -----------------------------------------------------------------
function Get-EntraFalconRefreshToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Send-LogMessage -Message "Minting refresh token for EntraFalcon..."

    # Call roadtx prtauth to exchange the PRT for Azure Portal tokens.
    # --tokens-stdout writes JSON to stdout which we redirect to a file.
    # -c is the client ID, -r is the resource (Microsoft Graph API).
    & roadtx prtauth -f $PrtFile -c $AzurePortalClientId -r 'https://graph.microsoft.com' --tokens-stdout > $TokenFile 2>&1

    if ($LASTEXITCODE -ne 0) {
        # If roadtx failed, try to read whatever it wrote for the log
        $ErrorContent = ''
        if (Test-Path -Path $TokenFile) {
            $ErrorContent = Get-Content -Path $TokenFile -Raw -ErrorAction SilentlyContinue
        }
        Send-LogMessage -Message "Token acquisition failed (exit code $LASTEXITCODE)" -Level ERROR
        if ($ErrorContent) {
            Send-LogMessage -Message "roadtx output: $ErrorContent" -Level ERROR
        }
        return $null
    }

    # Make sure the file actually exists and is not empty
    if (-not (Test-Path -Path $TokenFile)) {
        Send-LogMessage -Message "Token file was not created" -Level ERROR
        return $null
    }

    $RawContent = Get-Content -Path $TokenFile -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($RawContent)) {
        Send-LogMessage -Message "Token file is empty" -Level ERROR
        return $null
    }

    # Parse the JSON response from roadtx
    try {
        $TokenJson = $RawContent | ConvertFrom-Json
    }
    catch {
        Send-LogMessage -Message "Could not parse token JSON: $_" -Level ERROR
        return $null
    }

    # Extract the refresh token from the JSON. roadtx uses camelCase
    # field names (refreshToken, accessToken, etc.)
    $RefreshToken = $TokenJson.refreshToken
    if ([string]::IsNullOrEmpty($RefreshToken)) {
        Send-LogMessage -Message "No refreshToken field in prtauth response" -Level ERROR
        return $null
    }

    # Log the first few characters of the token for debugging. Never
    # log the full token since it is a sensitive credential.
    $Prefix = $RefreshToken.Substring(0, [Math]::Min(4, $RefreshToken.Length))
    Send-LogMessage -Message "Got refresh token ($($RefreshToken.Length) chars, prefix: $Prefix)"

    # EntraFalcon validates that the BroCiToken starts with "1." which
    # is the Azure Portal refresh token format. If roadtx returns a
    # token with a different prefix, EntraFalcon will reject it. We
    # warn here but still try, since the format may vary by tenant.
    if (-not $RefreshToken.StartsWith('1.')) {
        Send-LogMessage -Message "Refresh token prefix is '$Prefix' but EntraFalcon expects '1.'" -Level WARN
        Send-LogMessage -Message "The scan may fail. See troubleshooting in the setup guide." -Level WARN
    }

    return $RefreshToken
}

# -----------------------------------------------------------------
# Invoke-EntraFalconScan
#
# Runs the EntraFalcon assessment. EntraFalcon is a PowerShell script
# (run_EntraFalcon.ps1) that enumerates your Azure AD tenant and
# produces security reports in HTML, TXT, and optionally CSV format.
#
# We pass it the refresh token via -BroCiToken, which tells it to
# use the Azure Portal token exchange flow for authentication. This
# means EntraFalcon can get tokens for all the Microsoft APIs it
# needs (Graph, ARM, PIM, Security Findings) without any prompts.
#
# EntraFalcon must be run from its own directory because it loads
# modules from relative paths. We save the current location, change
# into EntraFalcon's directory, run the scan, then change back.
#
# Returns $true on success, $false on failure.
# -----------------------------------------------------------------
function Invoke-EntraFalconScan {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The refresh token from Get-EntraFalconRefreshToken
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken,

        # Where to write the HTML/TXT/CSV report files
        [Parameter(Mandatory = $true)]
        [string]$ScanOutputDir,

        # How much logging EntraFalcon should produce
        [Parameter(Mandatory = $true)]
        [string]$ScanLogLevel,

        # Whether to include CSV output alongside HTML and TXT
        [Parameter(Mandatory = $false)]
        [switch]$ScanCsv
    )

    Send-LogMessage -Message "Starting EntraFalcon assessment..."

    # Verify the EntraFalcon entry point script exists
    $RunScript = Join-Path -Path $EntraFalconDir -ChildPath 'run_EntraFalcon.ps1'
    if (-not (Test-Path -Path $RunScript)) {
        Send-LogMessage -Message "run_EntraFalcon.ps1 not found at $RunScript" -Level ERROR
        return $false
    }

    # Save current directory so we can restore it after the scan.
    # EntraFalcon loads its modules with relative paths, so it must
    # be run from inside its own directory.
    $OriginalLocation = Get-Location
    try {
        Set-Location -Path $EntraFalconDir

        # Build the parameter hashtable for splatting. Splatting passes
        # a hashtable as named parameters to a command, which is cleaner
        # than a very long command line.
        $ScanParams = @{
            AuthFlow     = 'BroCiToken'
            BroCiToken   = $RefreshToken
            OutputFolder = $ScanOutputDir
            LogLevel     = $ScanLogLevel
        }

        # Only add -Csv if the caller asked for it
        if ($ScanCsv) {
            $ScanParams['Csv'] = $true
        }

        # Run EntraFalcon. The & operator runs a script by path.
        # @ScanParams splats the hashtable as named parameters.
        & $RunScript @ScanParams

        Send-LogMessage -Message "Assessment complete. Reports saved to $ScanOutputDir"
        return $true
    }
    catch {
        Send-LogMessage -Message "EntraFalcon failed: $_" -Level ERROR
        return $false
    }
    finally {
        # Always restore the original directory, even if the scan failed
        Set-Location -Path $OriginalLocation
    }
}

# -----------------------------------------------------------------
# Remove-ScanTokenFile
#
# Deletes the temporary JSON file that held the refresh token. This
# file is sensitive (it contains a usable credential) and should not
# be left on disk after the scan finishes. Called on every exit path
# (success or failure) to make sure it gets cleaned up.
# -----------------------------------------------------------------
function Remove-ScanTokenFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ((Test-Path -Path $TokenFile) -and $PSCmdlet.ShouldProcess($TokenFile, 'Remove temporary token file')) {
        Remove-Item -Path $TokenFile -Force -ErrorAction SilentlyContinue
    }
}

# =================================================================
# MAIN EXECUTION
#
# The steps below run in order. If any step fails, the script logs
# the error, cleans up the temp token file, and exits with code 1
# so Task Scheduler knows the run failed.
# =================================================================

# Create the output and log directories if they do not exist yet.
# -Force means "don't error if it already exists."
foreach ($Dir in @($OutputDir, $LogDir)) {
    if (-not (Test-Path -Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }
}

Send-LogMessage -Message '===== EntraFalcon Scheduled Scan Starting ====='

# Step 1: Make sure all required files and tools are present
if (-not (Test-Prerequisite)) {
    Send-LogMessage -Message 'Preflight checks failed. Exiting.' -Level ERROR
    exit 1
}

# Step 2: Renew the PRT to keep it from expiring
if (-not (Invoke-PrtRenewal)) {
    Remove-ScanTokenFile
    exit 1
}

# Step 3: Use the PRT to get a refresh token for EntraFalcon
$RefreshToken = Get-EntraFalconRefreshToken
if ($null -eq $RefreshToken) {
    Remove-ScanTokenFile
    exit 1
}

# Step 4: Run the EntraFalcon assessment
$ScanResult = Invoke-EntraFalconScan -RefreshToken $RefreshToken -ScanOutputDir $OutputDir -ScanLogLevel $EntraFalconLogLevel -ScanCsv:$IncludeCsv

# Step 5: Clean up the temp token file (contains sensitive credential)
Remove-ScanTokenFile

# Step 6: Exit with appropriate code for Task Scheduler
if (-not $ScanResult) {
    Send-LogMessage -Message 'Scan failed. Check the log for details.' -Level ERROR
    exit 1
}

Send-LogMessage -Message '===== EntraFalcon Scheduled Scan Complete ====='
