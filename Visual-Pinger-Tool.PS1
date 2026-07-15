<#
.SYNOPSIS
    Multi-Threaded Network Endpoint Visual Pinger
.DESCRIPTION
    Concurrently pings network endpoints using native .NET Runspace Pools, 
    renders a live dashboard, and features custom settings, nicknames,
    and automatic live traceroute diagnostics with bulletproof menu routing.
#>
[CmdletBinding()]
param (
    [string]$EncryptedFile = "pinger_presets.enc",
    [switch]$DebugMode
)

# Set strict error behavior if debugging is enabled
if ($DebugMode) {
    $ErrorActionPreference = "Stop"
    Write-Host "[DEBUG MODE ACTIVE] High-verbosity diagnostics enabled." -ForegroundColor Magenta
    Start-Sleep -Seconds 1
} else {
    $ErrorActionPreference = "Continue"
}

# 1. Enforce Administrative Access
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[-] Access Denied: This script requires Administrative privileges." -ForegroundColor Red
    Write-Host "[*] Please restart PowerShell as an Administrator and try again." -ForegroundColor Yellow
    Exit
}

# Add .NET assembly for cryptographic functions
Add-Type -AssemblyName System.Security

# --- DIAGNOSTIC LOGGING UTILITY ---
function Export-DebugLog {
    param ([string]$Message, $Exception = $null)
    $logPath = "pinger_debug.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    if ($null -ne $Exception) {
        if ($Exception -is [System.Management.Automation.ErrorRecord]) {
            $logMessage += "`n[EXCEPTION] $($Exception.Exception.Message)`n[STACK TRACE] $($Exception.ScriptStackTrace)"
        } else {
            $logMessage += "`n[EXCEPTION] $($Exception.Message)"
        }
    }
    $logMessage | Out-File -FilePath $logPath -Append
}

# --- CRYPTOGRAPHIC UTILITIES ---
function Protect-Data {
    param ([string]$Data)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String($encryptedBytes)
}

function Unprotect-Data {
    param ([string]$Base64Data)
    try {
        $encryptedBytes = [Convert]::FromBase64String($Base64Data)
        $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    } catch {
        Export-DebugLog -Message "Failed to decrypt base64 string data blocks." -Exception $_
        return $null
    }
}

# --- SAFETY & GOVERNOR UTILITIES ---
function Validate-SafetyLimits {
    param (
        [int]$Threads,
        [int]$Interval,
        [bool]$GovernorEnabled
    )

    $MaxAllowedThreads = 25
    $MinAllowedInterval = 5

    $validatedThreads = $Threads
    $validatedInterval = $Interval

    # If governor is active, enforce safety cap restrictions
    if ($GovernorEnabled) {
        if ($Threads -gt $MaxAllowedThreads) { $validatedThreads = $MaxAllowedThreads }
        if ($Interval -lt $MinAllowedInterval) { $validatedInterval = $MinAllowedInterval }
    } else {
        if ($Threads -lt 1) { $validatedThreads = 1 }
        if ($Interval -lt 1) { $validatedInterval = 1 }
    }

    return [PSCustomObject]@{
        Threads  = $validatedThreads
        Interval = $validatedInterval
    }
}

# --- DNS RESOLUTION CHECK ---
function Test-DNSResolve {
    param ([string]$Hostname)
    if ($Hostname -as [System.Net.IPAddress]) { return $true }
    try {
        [System.Net.Dns]::GetHostAddresses($Hostname) | Out-Null
        return $true
    } catch {
        return $false
    }
}

# --- HTML REPORT GENERATOR ---
function Export-HtmlReport {
    param ($Results, [string]$PresetName)
    $htmlPath = "status.html"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $rows = foreach ($item in $Results) {
        $class = if ($item.Status -eq "ONLINE") { "ONLINE" } else { "OFFLINE" }
        $displayName = if ($item.Nickname) { "$($item.Nickname) ($($item.Target))" } else { $item.Target }
        "<tr><td>$displayName</td><td class='$class'>$($item.Status)</td><td>$($item.Latency)</td></tr>"
    }
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
    <title>Network Status - $PresetName</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #121212; color: #e0e0e0; margin: 40px; }
        .container { max-width: 800px; margin: auto; background: #1e1e1e; padding: 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        h1 { color: #00bcd4; border-bottom: 2px solid #333; padding-bottom: 10px; margin-top: 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #252525; color: #00bcd4; }
        tr:hover { background: #2a2a2a; }
        .ONLINE { color: #4caf50; font-weight: bold; }
        .OFFLINE { color: #f44336; font-weight: bold; }
        .timestamp { color: #888; font-size: 0.9em; margin-top: 15px; text-align: right; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Status: $PresetName</h1>
        <table>
            <thead>
                <tr><th>Target</th><th>Status</th><th>Latency</th></tr>
            </thead>
            <tbody>
                $($rows -join "`n")
            </tbody>
        </table>
        <div class="timestamp">Last updated: $timestamp</div>
    </div>
</body>
</html>
"@
    $htmlContent | Out-File -FilePath $htmlPath -Force -Encoding UTF8
}

# --- DATABASE MANAGEMENT FUNCTIONS ---
function Load-PresetsDB {
    param ([string]$Path)
    $myHashtable = [ordered]@{}
    if (Test-Path $Path) {
        try {
            $encryptedContent = Get-Content $Path -Raw
            if (-not [string]::IsNullOrEmpty($encryptedContent)) {
                $decryptedContent = Unprotect-Data -Base64Data $encryptedContent
                if ($null -ne $decryptedContent) {
                    $jsonObj = ConvertFrom-Json $decryptedContent
                    if ($null -ne $jsonObj) {
                        foreach ($prop in $jsonObj.psobject.Properties) {
                            if ($prop.Name -eq '_Settings') {
                                $settingsHash = [ordered]@{}
                                foreach ($sProp in $prop.Value.psobject.Properties) {
                                    $settingsHash[$sProp.Name] = $sProp.Value
                                }
                                $myHashtable[$prop.Name] = $settingsHash
                            } else {
                                $val = $prop.Value
                                $targets = @()
                                if ($val.psobject.Properties.Name -contains "Targets") {
                                    foreach ($t in $val.Targets) {
                                        if ($t.psobject.Properties.Name -contains "Address") {
                                            $targets += [PSCustomObject]@{
                                                Address  = $t.Address
                                                Nickname = $t.Nickname
                                            }
                                        } else {
                                            $targets += [PSCustomObject]@{
                                                Address  = [string]$t
                                                Nickname = ""
                                            }
                                        }
                                    }
                                    $customConfig = $null
                                    if ($null -ne $val.CustomConfig) {
                                        $customConfig = [ordered]@{}
                                        foreach ($ccProp in $val.CustomConfig.psobject.Properties) {
                                            $customConfig[$ccProp.Name] = $ccProp.Value
                                        }
                                    }
                                    $myHashtable[$prop.Name] = [ordered]@{
                                        Targets      = $targets
                                        CustomConfig = $customConfig
                                    }
                                } else {
                                    # Seamless legacy migration path
                                    foreach ($t in @($val)) {
                                        $targets += [PSCustomObject]@{
                                            Address  = [string]$t
                                            Nickname = ""
                                        }
                                    }
                                    $myHashtable[$prop.Name] = [ordered]@{
                                        Targets      = $targets
                                        CustomConfig = $null
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Write-Host "[-] Cryptographic Error: Unable to decrypt database file." -ForegroundColor Red
                    Exit
                }
            }
        } catch {
            Export-DebugLog -Message "Critical crash inside Load-PresetsDB parsing execution framework." -Exception $_
            throw $_
        }
    }
    
    # Initialize global defaults if metadata block does not exist
    if (-not $myHashtable.Contains('_Settings')) {
        $myHashtable['_Settings'] = [ordered]@{
            RefreshInterval    = 5
            MaxThreads         = 10
            StaggerDelay       = 50
            EnableJitter       = $false
            IsGovernorEnabled  = $true
            EnableAutoTrace    = $false
            EnableDnsPreFlight = $false
            EnableHtmlReport   = $false
        }
    } else {
        # Backwards compatible safety check to insert missing keys to existing DBs
        $defaults = @{
            RefreshInterval    = 5
            MaxThreads         = 10
            StaggerDelay       = 50
            EnableJitter       = $false
            IsGovernorEnabled  = $true
            EnableAutoTrace    = $false
            EnableDnsPreFlight = $false
            EnableHtmlReport   = $false
        }
        foreach ($key in $defaults.Keys) {
            if (-not $myHashtable['_Settings'].Contains($key)) {
                $myHashtable['_Settings'][$key] = $defaults[$key]
            }
        }
    }
    return $myHashtable
}

function Save-PresetsDB {
    param ([hashtable]$DbObject, [string]$Path)
    $json = ConvertTo-Json $DbObject -Depth 5
    $encryptedString = Protect-Data -Data $json
    Set-Content -Path $Path -Value $encryptedString
}

# --- MONITOR ENGINE ---
function Start-Monitor {
    param (
        [string]$PresetName, 
        [array]$TargetsList, 
        $GlobalConfig, 
        $CustomConfig
    )
    
    if ($null -eq $TargetsList -or $TargetsList.Count -eq 0) {
        Write-Host "[-] Error: No targets found in this configuration profile." -ForegroundColor Red
        Start-Sleep -Seconds 3
        return
    }

    # Inheritance Resolver: Use preset custom settings if they exist; fallback to globals if not
    $activeConfig = [ordered]@{}
    $configProperties = @("RefreshInterval", "MaxThreads", "StaggerDelay", "EnableJitter", "IsGovernorEnabled", "EnableAutoTrace", "EnableDnsPreFlight", "EnableHtmlReport")
    foreach ($property in $configProperties) {
        if ($null -ne $CustomConfig -and $null -ne $CustomConfig[$property]) {
            $activeConfig[$property] = $CustomConfig[$property]
        } else {
            $activeConfig[$property] = $GlobalConfig[$property]
        }
    }

    # Run configuration through the Safety Governor Validation Engine
    $SafetyResult      = Validate-SafetyLimits -Threads $activeConfig.MaxThreads -Interval $activeConfig.RefreshInterval -GovernorEnabled $activeConfig.IsGovernorEnabled
    $MaxThreads        = $SafetyResult.Threads
    $RefreshInterval   = $SafetyResult.Interval
    $StaggerDelay      = $activeConfig.StaggerDelay
    $EnableJitter      = $activeConfig.EnableJitter
    $EnableAutoTrace   = $activeConfig.EnableAutoTrace
    $EnableDnsPre      = $activeConfig.EnableDnsPreFlight
    $EnableHtmlReport  = $activeConfig.EnableHtmlReport

    Write-Host "[+] Initializing Concurrency Engine for profile: '$PresetName'..." -ForegroundColor Cyan
    Write-Host "[*] Diagnostics Specs: Trace=$EnableAutoTrace | DNSPreCheck=$EnableDnsPre | WebReport=$EnableHtmlReport" -ForegroundColor DarkGray
    Start-Sleep -Seconds 2

    $PingScriptBlock = {
        param($Target)
        $nodeResult = [PSCustomObject]@{ Target = $Target; Status = "OFFLINE"; Latency = "N/A" }
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($Target, 1000)
            if ($reply.Status -eq "Success") {
                $nodeResult.Status = "ONLINE"
                $nodeResult.Latency = "$($reply.RoundtripTime) ms"
            }
        } catch {
            $nodeResult.Status = "OFFLINE"
        }
        return $nodeResult
    }

    # Tracking tables for state changes and diagnostic background jobs
    $PreviousStates   = @{}
    $ActiveTraces     = @{} # IPAddress -> PowerShellJobObject
    $CompletedTraces  = [System.Collections.Generic.List[string]]::new()
    
    $RunspacePool = $null
    
    # Intercept Ctrl+C Keypress Interrupts
    [Console]::TreatControlCAsInput = $true
    while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null } # Clean buffer

    try {
        while ($true) {
            $resolvedTargets = @()
            $dnsFailedResults = @()

            # Pre-Flight DNS resolution check
            foreach ($node in $TargetsList) {
                # Immediate check for user abort
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                        throw "UserInterrupt"
                    }
                }

                if ($EnableDnsPre) {
                    if (Test-DNSResolve -Hostname $node.Address) {
                        $resolvedTargets += $node
                    } else {
                        $dnsFailedResults += [PSCustomObject]@{
                            Target   = $node.Address
                            Nickname = $node.Nickname
                            Status   = "OFFLINE"
                            Latency  = "DNS Error"
                        }
                    }
                } else {
                    $resolvedTargets += $node
                }
            }

            $results = @()
            if ($resolvedTargets.Count -gt 0) {
                $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
                $RunspacePool.Open()
                $Threads = @()

                foreach ($Node in $resolvedTargets) {
                    if ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                            throw "UserInterrupt"
                        }
                    }

                    $PowerShellInstance = [powershell]::Create().AddScript($PingScriptBlock).AddArgument($Node.Address)
                    $PowerShellInstance.RunspacePool = $RunspacePool
                    $Threads += [PSCustomObject]@{
                        Instance = $PowerShellInstance
                        Context  = $PowerShellInstance.BeginInvoke()
                    }
                    
                    if ($StaggerDelay -gt 0) {
                        $stgElapsed = 0
                        while ($stgElapsed -lt $StaggerDelay) {
                            if ([Console]::KeyAvailable) {
                                $key = [Console]::ReadKey($true)
                                if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                                    throw "UserInterrupt"
                                }
                            }
                            Start-Sleep -Milliseconds 50
                            $stgElapsed += 50
                        }
                    }
                }

                while ($Threads.Context.IsCompleted -contains $false) {
                    if ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                            throw "UserInterrupt"
                        }
                    }
                    Start-Sleep -Milliseconds 100
                }

                $rawResults = foreach ($Thread in $Threads) {
                    $Thread.Instance.EndInvoke($Thread.Context)
                    $Thread.Instance.Dispose()
                }
                $RunspacePool.Close()
                $RunspacePool.Dispose()
                $RunspacePool = $null

                # Remap names and metadata
                foreach ($raw in $rawResults) {
                    $match = $TargetsList | Where-Object { $_.Address -eq $raw.Target } | Select-Object -First 1
                    $results += [PSCustomObject]@{
                        Target   = $raw.Target
                        Nickname = if ($match) { $match.Nickname } else { "" }
                        Status   = $raw.Status
                        Latency  = $raw.Latency
                    }
                }
            }

            # Merge DNS-failed targets directly into output array
            $finalResults = $results + $dnsFailedResults

            # Evaluate Auto-Traceroute trigger criteria
            foreach ($item in $finalResults) {
                $addr = $item.Target
                $currentStatus = $item.Status
                
                if ($EnableAutoTrace) {
                    if ($PreviousStates.ContainsKey($addr)) {
                        $oldStatus = $PreviousStates[$addr]
                        # Target transitioned from ONLINE directly to OFFLINE
                        if ($oldStatus -eq "ONLINE" -and $currentStatus -eq "OFFLINE") {
                            Export-DebugLog -Message "ALERT: Target '$addr' went OFFLINE. Executing automated traceroute diagnostics."
                            
                            # Fire diagnostic traceroute job in background
                            $traceJob = Start-Job -Name "Trace-$addr" -ArgumentList $addr -ScriptBlock {
                                param($Dest)
                                $timestamp = Get-Date -Format "HH:mm:ss"
                                try {
                                    $trace = Test-NetConnection -ComputerName $Dest -TraceRoute -WarningAction SilentlyContinue
                                    $hops = $trace.TraceRoute -join " -> "
                                    if (-not $hops) { $hops = "No hops resolved (Firewall block/ICMP disabled)" }
                                    return [PSCustomObject]@{
                                        Dest      = $Dest
                                        Timestamp = $timestamp
                                        Route     = $hops
                                        Success   = $true
                                    }
                                } catch {
                                    return [PSCustomObject]@{
                                        Dest      = $Dest
                                        Timestamp = $timestamp
                                        Route     = "Failed: $_"
                                        Success   = $false
                                    }
                                }
                            }
                            $ActiveTraces[$addr] = $traceJob
                        }
                    }
                    $PreviousStates[$addr] = $currentStatus
                }
            }

            # Harvest Completed Background Traceroute results
            $completedJobKeys = @()
            foreach ($addr in $ActiveTraces.Keys) {
                $job = $ActiveTraces[$addr]
                if ($job.State -eq "Completed") {
                    $jobOutput = Receive-Job -Job $job
                    if ($null -ne $jobOutput) {
                        $logLine = "[$($jobOutput.Timestamp)] TRACEROUTE ALERT: Host '$($jobOutput.Dest)' went OFFLINE. Route: $($jobOutput.Route)"
                        
                        # Commits route directly to debugging log file
                        $logLine | Out-File -FilePath "pinger_debug.log" -Append
                        
                        # Queue status alert directly to console display (stores last 5 records)
                        $CompletedTraces.Add($logLine)
                        if ($CompletedTraces.Count -gt 5) { $CompletedTraces.RemoveAt(0) }
                    }
                    Remove-Job -Job $job -Force
                    $completedJobKeys += $addr
                } elseif ($job.State -eq "Failed") {
                    Remove-Job -Job $job -Force
                    $completedJobKeys += $addr
                }
            }
            foreach ($key in $completedJobKeys) { $ActiveTraces.Remove($key) }

            # Generate HTML report if enabled
            if ($EnableHtmlReport) {
                Export-HtmlReport -Results $finalResults -PresetName $PresetName
            }

            # UI Rendering
            Clear-Host
            Write-Host "====================================================" -ForegroundColor Cyan
            Write-Host "   LIVE MONITORING PRESET: [ $PresetName ]" -ForegroundColor Cyan
            Write-Host "   Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')      " -ForegroundColor DarkGray
            Write-Host "====================================================" -ForegroundColor Cyan
            Write-Host ""

            foreach ($item in $finalResults) {
                $displayName = if ($item.Nickname) { "$($item.Nickname) ($($item.Target))" } else { $item.Target }
                $targetPad = $displayName.PadRight(35)
                $latencyPad = $item.Latency.PadRight(10)

                if ($item.Status -eq "ONLINE") {
                    Write-Host "  [ONLINE]  " -ForegroundColor Green -NoNewline
                    Write-Host "$targetPad | Latency: $latencyPad" -ForegroundColor Gray
                } else {
                    Write-Host "  [OFFLINE] " -ForegroundColor Red -NoNewline
                    Write-Host "$targetPad | Latency: $latencyPad" -ForegroundColor DarkGray
                }
            }
            
            # Real-Time UI diagnostics engine output
            if ($ActiveTraces.Count -gt 0) {
                Write-Host ""
                Write-Host "----------------------------------------------------" -ForegroundColor Yellow
                Write-Host "   ACTIVE DIAGNOSTIC RUNS (BACKGROUND):" -ForegroundColor Yellow
                foreach ($addr in $ActiveTraces.Keys) {
                    Write-Host "   [*] Running Traceroute for $addr..." -ForegroundColor Cyan
                }
            }

            if ($CompletedTraces.Count -gt 0) {
                Write-Host ""
                Write-Host "----------------------------------------------------" -ForegroundColor Yellow
                Write-Host "   RECENT DIAGNOSTIC EVENT ALERTS:" -ForegroundColor Yellow
                foreach ($traceLog in $CompletedTraces) {
                    Write-Host "   $traceLog" -ForegroundColor DarkYellow
                }
            }

            Write-Host ""
            Write-Host "====================================================" -ForegroundColor Cyan
            Write-Host "Press [CTRL + C] to terminate the script monitor." -ForegroundColor DarkGray
            
            $FinalSleep = $RefreshInterval
            if ($EnableJitter) {
                $RandomOffset = Get-Random -Minimum -2 -Maximum 3
                $FinalSleep = $RefreshInterval + $RandomOffset
                if ($FinalSleep -lt 1) { $FinalSleep = 1 }
            }
            
            # Check for Interrupted keypresses during interval sleep
            $msToSleep = $FinalSleep * 1000
            $sleepElapsed = 0
            while ($sleepElapsed -lt $msToSleep) {
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                        throw "UserInterrupt"
                    }
                }
                Start-Sleep -Milliseconds 100
                $sleepElapsed += 100
            }
        }
    }
    catch {
        # Check if the caught exception is our custom UserInterrupt
        if ($_.Exception.Message -eq "UserInterrupt") {
            Write-Host "`n[+] Monitoring session stopped." -ForegroundColor Yellow
            Write-Host "[*] Safely returning to Main Menu..." -ForegroundColor Cyan
            Start-Sleep -Seconds 1.5
        }
        else {
            Export-DebugLog -Message "Fatal termination loop caught inside active monitor pipeline." -Exception $_
            Clear-Host
            Write-Host "[!] Monitor Pipeline Crashed. Exception written to diagnostic log." -ForegroundColor Red
            Start-Sleep -Seconds 3
        }
    }
    finally {
        # Restore native console behavior (important so standard prompt interfaces function)
        [Console]::TreatControlCAsInput = $false
        
        # Clean up background diagnostics jobs safely
        foreach ($job in $ActiveTraces.Values) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        
        # Clean up runspace pool cleanly
        if ($null -ne $RunspacePool) {
            try {
                $RunspacePool.Close()
                $RunspacePool.Dispose()
            } catch {}
        }
    }
}

# --- MAIN INTERFACE LOOP ---
$db = Load-PresetsDB -Path $EncryptedFile

while ($true) {
    try {
        Clear-Host
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "           NETWORK ENDPOINT VISUAL PINGER           " -ForegroundColor Cyan
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "1. Select a Saved Preset & Start Monitor"
        Write-Host "2. Create New Preset (Import from text file)"
        Write-Host "3. Create New Preset (Manually type)"
        Write-Host "4. Manage Presets (View / Edit / Delete)"
        Write-Host "5. Configure Global Settings & Safety limits"
        Write-Host "6. Exit System"
        Write-Host "====================================================" -ForegroundColor Cyan
        $mainChoice = Read-Host "Select option (1-6)"

        switch ($mainChoice) {
            "1" {
                $keys = @( $db.Keys | Where-Object { $_ -ne '_Settings' } )
                if ($keys.Count -eq 0) {
                    Write-Host "[-] No presets currently exist. Create one first." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                    break
                }
                Clear-Host
                Write-Host "--- AVAILABLE PRESETS ---" -ForegroundColor Cyan
                for ($i = 0; $i -lt $keys.Count; $i++) {
                    $presetKey = $keys[$i]
                    Write-Host "[$($i + 1)] $presetKey ($($db[$presetKey].Targets.Count) targets)"
                }
                $selection = Read-Host "`nSelect a preset number to monitor"
                
                if ($selection -match '^\d+$') {
                    $idx = [int]$selection
                    if ($idx -gt 0 -and $idx -le $keys.Count) {
                        $chosenKey = $keys[$idx - 1]
                        $presetObject = $db[$chosenKey]
                        Start-Monitor -PresetName $chosenKey -TargetsList $presetObject.Targets -GlobalConfig $db['_Settings'] -CustomConfig $presetObject.CustomConfig
                    } else {
                        Write-Host "[-] Error: Selection index out of bounds." -ForegroundColor Red ; Start-Sleep -Seconds 2
                    }
                } else {
                    Write-Host "[-] Error: Non-numeric input identified." -ForegroundColor Red ; Start-Sleep -Seconds 2
                }
            }

            "2" {
                $importPath = Read-Host "Enter path to plain-text target file"
                if (Test-Path $importPath) {
                    $rawContent = Get-Content $importPath | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
                    if ($rawContent.Count -gt 0) {
                        $presetName = Read-Host "Enter a name for this new preset"
                        if (-not [string]::IsNullOrEmpty($presetName) -and $presetName -ne '_Settings') {
                            
                            # Standardize raw content targets to objects
                            $targetObjects = @()
                            foreach ($t in $rawContent) {
                                $targetObjects += [PSCustomObject]@{ Address = $t; Nickname = "" }
                            }

                            $db[$presetName] = [ordered]@{
                                Targets      = $targetObjects
                                CustomConfig = $null
                            }
                            Save-PresetsDB -DbObject $db -Path $EncryptedFile
                            Write-Host "[+] Preset '$presetName' saved securely." -ForegroundColor Green
                        }
                    } else { Write-Host "[-] File was empty." -ForegroundColor Yellow }
                } else { Write-Host "[-] File path not found." -ForegroundColor Red }
                Start-Sleep -Seconds 2
            }

            "3" {
                Write-Host "Enter target details. Type 'DONE' for the target to finish." -ForegroundColor Yellow
                $manualList = @()
                while ($true) {
                    $inputTarget = Read-Host "Target Address (IP or Hostname)"
                    if ([string]::IsNullOrEmpty($inputTarget) -or $inputTarget.ToUpper() -eq "DONE") { break }
                    
                    $inputNickname = Read-Host "Target Nickname (Optional - Press Enter to Skip)"
                    
                    $manualList += [PSCustomObject]@{
                        Address  = $inputTarget.Trim()
                        Nickname = $inputNickname.Trim()
                    }
                }
                if ($manualList.Count -gt 0) {
                    $presetName = Read-Host "Enter a name for this manual preset"
                    if (-not [string]::IsNullOrEmpty($presetName) -and $presetName -ne '_Settings') {
                        $db[$presetName] = [ordered]@{
                            Targets      = $manualList
                            CustomConfig = $null
                        }
                        Save-PresetsDB -DbObject $db -Path $EncryptedFile
                        Write-Host "[+] Preset '$presetName' saved securely." -ForegroundColor Green
                    }
                } else { Write-Host "[-] No targets entered." -ForegroundColor Yellow }
                Start-Sleep -Seconds 2
            }

            "4" {
                $mgmtLoop = $true
                while ($mgmtLoop) {
                    Clear-Host
                    Write-Host "=== PRESET MANAGEMENT DASHBOARD ===" -ForegroundColor Cyan
                    Write-Host "1. View Stored Profiles & Active Targets"
                    Write-Host "2. Edit Preset (Targets and Overrides)"
                    Write-Host "3. Delete a Preset Configuration"
                    Write-Host "4. Back to Main Menu"
                    $mgmtChoice = Read-Host "Select option (1-4)"

                    switch ($mgmtChoice) {
                        "1" {
                            Clear-Host
                            Write-Host "--- REGISTERED SECURE PRESETS ---`n" -ForegroundColor Cyan
                            $profileKeys = @( $db.Keys | Where-Object { $_ -ne '_Settings' } )
                            if ($profileKeys.Count -eq 0) { Write-Host "[No profiles found]" -ForegroundColor DarkGray }
                            foreach ($key in $profileKeys) {
                                $presetObj = $db[$key]
                                Write-Host "Profile: [ $key ] ($($presetObj.Targets.Count) Elements)" -ForegroundColor Yellow
                                if ($null -ne $presetObj.CustomConfig) {
                                    $cc = $presetObj.CustomConfig
                                    Write-Host "  -> [Custom Settings Active] Threads: $($cc.MaxThreads) | Refresh: $($cc.RefreshInterval)s | Gov: $(if ($cc.IsGovernorEnabled) { 'ON' } else { 'OFF' })" -ForegroundColor Cyan
                                    Write-Host "  -> [Custom Diagnostics] Trace: $(if ($cc.EnableAutoTrace) { 'ON' } else { 'OFF' }) | DNSPreCheck: $(if ($cc.EnableDnsPreFlight) { 'ON' } else { 'OFF' }) | Report: $(if ($cc.EnableHtmlReport) { 'ON' } else { 'OFF' })" -ForegroundColor Cyan
                                } else {
                                    Write-Host "  -> [Inheriting Global Defaults]" -ForegroundColor DarkGray
                                }
                                foreach ($t in $presetObj.Targets) { 
                                    $showName = if ($t.Nickname) { "$($t.Nickname) ($($t.Address))" } else { $t.Address }
                                    Write-Host "     -> $showName" -ForegroundColor Gray 
                                }
                                Write-Host ""
                            }
                            Read-Host "Press Enter to return to management panel"
                        }
                        "2" {
                            $keys = @( $db.Keys | Where-Object { $_ -ne '_Settings' } )
                            if ($keys.Count -eq 0) { Write-Host "[-] No configurations found." -ForegroundColor Yellow ; Start-Sleep -Seconds 1; break }
                            for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host "[$($i + 1)] $($keys[$i])" }
                            $sel = Read-Host "Choose preset to modify"
                            
                            if ($sel -match '^\d+$' -and [int]$sel -le $keys.Count -and [int]$sel -gt 0) {
                                $targetKey = $keys[[int]$sel - 1]
                                $presetObj = $db[$targetKey]
                                
                                Write-Host "`n=== OPTIONS FOR: [ $targetKey ] ===" -ForegroundColor Cyan
                                Write-Host "1. Append new endpoints to targets list"
                                Write-Host "2. Remove a specific target line"
                                Write-Host "3. Edit a target's nickname"
                                Write-Host "4. Edit/Configure Preset-Specific Settings Override"
                                $editAction = Read-Host "Select action"
                                
                                if ($editAction -eq "1") {
                                    Write-Host "Enter endpoints to add. Type 'DONE' when complete." -ForegroundColor Yellow
                                    while ($true) {
                                        $newT = Read-Host "Address"
                                        if ([string]::IsNullOrEmpty($newT) -or $newT.ToUpper() -eq "DONE") { break }
                                        $newN = Read-Host "Nickname (Optional)"
                                        $presetObj.Targets += [PSCustomObject]@{ Address = $newT.Trim(); Nickname = $newN.Trim() }
                                    }
                                    Save-PresetsDB -DbObject $db -Path $EncryptedFile
                                    Write-Host "[+] Configuration database committed." -ForegroundColor Green ; Start-Sleep -Seconds 1
                                }
                                elseif ($editAction -eq "2") {
                                    $currentTargets = @($presetObj.Targets)
                                    for ($tIdx = 0; $tIdx -lt $currentTargets.Count; $tIdx++) {
                                        $showName = if ($currentTargets[$tIdx].Nickname) { "$($currentTargets[$tIdx].Nickname) ($($currentTargets[$tIdx].Address))" } else { $currentTargets[$tIdx].Address }
                                        Write-Host "[$($tIdx + 1)] $showName"
                                    }
                                    $remSel = Read-Host "Select number line to erase"
                                    if ($remSel -match '^\d+$' -and [int]$remSel -le $currentTargets.Count -and [int]$remSel -gt 0) {
                                        $presetObj.Targets = @( $currentTargets | Where-Object { $_.Address -ne $currentTargets[[int]$remSel - 1].Address } )
                                        Save-PresetsDB -DbObject $db -Path $EncryptedFile
                                        Write-Host "[+] Node dropped. Database updated." -ForegroundColor Green ; Start-Sleep -Seconds 1
                                    }
                                }
                                elseif ($editAction -eq "3") {
                                    $currentTargets = @($presetObj.Targets)
                                    for ($tIdx = 0; $tIdx -lt $currentTargets.Count; $tIdx++) {
                                        $showName = if ($currentTargets[$tIdx].Nickname) { "$($currentTargets[$tIdx].Nickname) ($($currentTargets[$tIdx].Address))" } else { $currentTargets[$tIdx].Address }
                                        Write-Host "[$($tIdx + 1)] $showName"
                                    }
                                    $nickSel = Read-Host "Select number line to assign/edit nickname"
                                    if ($nickSel -match '^\d+$' -and [int]$nickSel -le $currentTargets.Count -and [int]$nickSel -gt 0) {
                                        $newNick = Read-Host "Enter new Nickname (Press Enter to clear)"
                                        $presetObj.Targets[[int]$nickSel - 1].Nickname = $newNick.Trim()
                                        Save-PresetsDB -DbObject $db -Path $EncryptedFile
                                        Write-Host "[+] Nickname mapped. Database updated." -ForegroundColor Green ; Start-Sleep -Seconds 1
                                    }
                                }
                                elseif ($editAction -eq "4") {
                                    if ($null -eq $presetObj.CustomConfig) {
                                        $presetObj.CustomConfig = [ordered]@{
                                            RefreshInterval    = $db['_Settings'].RefreshInterval
                                            MaxThreads         = $db['_Settings'].MaxThreads
                                            StaggerDelay       = $db['_Settings'].StaggerDelay
                                            EnableJitter       = $db['_Settings'].EnableJitter
                                            IsGovernorEnabled  = $db['_Settings'].IsGovernorEnabled
                                            EnableAutoTrace    = $db['_Settings'].EnableAutoTrace
                                            EnableDnsPreFlight = $db['_Settings'].EnableDnsPreFlight
                                            EnableHtmlReport   = $db['_Settings'].EnableHtmlReport
                                        }
                                    }

                                    $customSettingLoop = $true
                                    while ($customSettingLoop) {
                                        Clear-Host
                                        $cc = $presetObj.CustomConfig
                                        Write-Host "=== CUSTOM SETTINGS FOR PRESET: [ $targetKey ] ===" -ForegroundColor Cyan
                                        Write-Host "1. Refresh Interval   : $($cc.RefreshInterval) seconds"
                                        Write-Host "2. Max Concurrency    : $($cc.MaxThreads) threads"
                                        Write-Host "3. Stagger Delay      : $($cc.StaggerDelay) ms"
                                        Write-Host "4. Randomize Jitter   : $(if ($cc.EnableJitter) { 'ENABLED' } else { 'DISABLED' })"
                                        Write-Host "5. Safety Governor    : $(if ($cc.IsGovernorEnabled) { 'ENABLED' } else { 'DISABLED (Expert Mode)' })"
                                        Write-Host "6. Auto-Traceroute    : $(if ($cc.EnableAutoTrace) { 'ENABLED' } else { 'DISABLED' })"
                                        Write-Host "7. DNS Pre-Flight     : $(if ($cc.EnableDnsPreFlight) { 'ENABLED' } else { 'DISABLED' })"
                                        Write-Host "8. HTML Status Report : $(if ($cc.EnableHtmlReport) { 'ENABLED' } else { 'DISABLED' })"
                                        Write-Host "9. REMOVE Custom Settings (Revert to using Global Settings)"
                                        Write-Host "10. Save & Return"
                                        Write-Host "==================================================" -ForegroundColor Cyan
                                        $ccChoice = Read-Host "Select configuration option (1-10)"

                                        switch ($ccChoice) {
                                            "1" {
                                                $val = Read-Host "Enter scan refresh frequency (seconds)"
                                                if ($val -match '^\d+$' -and [int]$val -gt 0) { $cc.RefreshInterval = [int]$val }
                                            }
                                            "2" {
                                                $val = Read-Host "Enter max worker pool limit"
                                                if ($val -match '^\d+$' -and [int]$val -gt 0) { $cc.MaxThreads = [int]$val }
                                            }
                                            "3" {
                                                $val = Read-Host "Enter launch delay value (milliseconds)"
                                                if ($val -match '^\d+$') { $cc.StaggerDelay = [int]$val }
                                            }
                                            "4" { $cc.EnableJitter = -not $cc.EnableJitter }
                                            "5" { $cc.IsGovernorEnabled = -not $cc.IsGovernorEnabled }
                                            "6" { $cc.EnableAutoTrace = -not $cc.EnableAutoTrace }
                                            "7" { $cc.EnableDnsPreFlight = -not $cc.EnableDnsPreFlight }
                                            "8" { $cc.EnableHtmlReport = -not $cc.EnableHtmlReport }
                                            "9" {
                                                $presetObj.CustomConfig = $null
                                                $customSettingLoop = $false
                                                Write-Host "[+] Custom configuration scrubbed. Reset to inherit Global settings." -ForegroundColor Yellow
                                                Start-Sleep -Seconds 1
                                            }
                                            "10" { $customSettingLoop = $false }
                                        }
                                    }
                                    Save-PresetsDB -DbObject $db -Path $EncryptedFile
                                }
                            }
                        }
                        "3" {
                            $keys = @( $db.Keys | Where-Object { $_ -ne '_Settings' } )
                            if ($keys.Count -eq 0) { Write-Host "[-] No configurations found." -ForegroundColor Yellow ; Start-Sleep -Seconds 1; break }
                            for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host "[$($i + 1)] $($keys[$i])" }
                            $delSel = Read-Host "Choose preset number to PERMANENTLY drop"
                            if ($delSel -match '^\d+$' -and [int]$delSel -le $keys.Count -and [int]$delSel -gt 0) {
                                $confirm = Read-Host "Are you sure you want to drop '$($keys[[int]$delSel - 1])'? (Y/N)"
                                if ($confirm.ToUpper() -eq "Y") {
                                    $db.Remove($keys[[int]$delSel - 1])
                                    Save-PresetsDB -DbObject $db -Path $EncryptedFile
                                    Write-Host "[!] Preset dropped successfully." -ForegroundColor Red ; Start-Sleep -Seconds 1
                                }
                            }
                        }
                        "4" { $mgmtLoop = $false }
                    }
                }
            }

            "5" {
                $settingsLoop = $true
                while ($settingsLoop) {
                    Clear-Host
                    $currentSettings = $db['_Settings']
                    Write-Host "====================================================" -ForegroundColor Cyan
                    Write-Host "         GLOBAL DEFAULT PERFORMANCE & SAFETY        " -ForegroundColor Cyan
                    Write-Host "====================================================" -ForegroundColor Cyan
                    Write-Host "1. Refresh Interval   : $($currentSettings.RefreshInterval) seconds"
                    Write-Host "2. Max Concurrency    : $($currentSettings.MaxThreads) threads"
                    Write-Host "3. Stagger Delay      : $($currentSettings.StaggerDelay) ms"
                    Write-Host "4. Randomize Jitter   : $(if ($currentSettings.EnableJitter) { 'ENABLED' } else { 'DISABLED' })"
                    Write-Host "5. Safety Governor    : $(if ($currentSettings.IsGovernorEnabled) { 'ENABLED (Safe)' } else { 'DISABLED (Expert Mode)' })"
                    Write-Host "6. Auto-Traceroute    : $(if ($currentSettings.EnableAutoTrace) { 'ENABLED' } else { 'DISABLED' })"
                    Write-Host "7. DNS Pre-Flight Check: $(if ($currentSettings.EnableDnsPreFlight) { 'ENABLED' } else { 'DISABLED' })"
                    Write-Host "8. HTML Status Report : $(if ($currentSettings.EnableHtmlReport) { 'ENABLED' } else { 'DISABLED' })"
                    Write-Host "9. Back to Main Menu"
                    Write-Host "====================================================" -ForegroundColor Cyan
                    $setChoice = Read-Host "Select configuration option (1-9)"

                    switch ($setChoice) {
                        "1" {
                            $val = Read-Host "Enter default scan refresh frequency (seconds)"
                            if ($val -match '^\d+$' -and [int]$val -gt 0) {
                                $db['_Settings'].RefreshInterval = [int]$val
                            }
                        }
                        "2" {
                            $val = Read-Host "Enter default max worker pool limit"
                            if ($val -match '^\d+$' -and [int]$val -gt 0) {
                                $db['_Settings'].MaxThreads = [int]$val
                            }
                        }
                        "3" {
                            $val = Read-Host "Enter default launch delay value (milliseconds)"
                            if ($val -match '^\d+$') {
                                $db['_Settings'].StaggerDelay = [int]$val
                            }
                        }
                        "4" {
                            $db['_Settings'].EnableJitter = -not $db['_Settings'].EnableJitter
                        }
                        "5" {
                            $db['_Settings'].IsGovernorEnabled = -not $db['_Settings'].IsGovernorEnabled
                            if (-not $db['_Settings'].IsGovernorEnabled) {
                                Write-Host "[!] WARNING: Safety Governor disabled. High traffic output could strain networks." -ForegroundColor Red
                                Start-Sleep -Seconds 2
                            }
                        }
                        "6" { $db['_Settings'].EnableAutoTrace = -not $db['_Settings'].EnableAutoTrace }
                        "7" { $db['_Settings'].EnableDnsPreFlight = -not $db['_Settings'].EnableDnsPreFlight }
                        "8" { $db['_Settings'].EnableHtmlReport = -not $db['_Settings'].EnableHtmlReport }
                        "9" { $settingsLoop = $false }
                    }
                    Save-PresetsDB -DbObject $db -Path $EncryptedFile
                }
            }

            "6" {
                Write-Host "[+] Exiting secure shell ecosystem. Goodbye." -ForegroundColor Green
                Exit
            }
        }
    }
    catch {
        Export-DebugLog -Message "Global runtime processing crash experienced." -Exception $_
        Clear-Host
        Write-Host "=== SELECTION EXECUTION FRAMEWORK CRASH ===" -ForegroundColor Red
        Read-Host "`nPress Enter to restart main engine process mapping..."
    }
}