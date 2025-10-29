The results will be in the C folder called "win-enum-outputs"
inside that folder there will be a folder with the "year""month""day" _ "Hour""minutes""seconds"











# Windows enumeration collector (with common service port checks)
# Run as Administrator
$ts = (Get-Date -Format "yyyyMMdd_HHmmss")
$outDir = "C:\win-enum-outputs\$ts"
New-Item -Path $outDir -ItemType Directory -Force | Out-Null

# Pipeline-friendly saver (same as before)
function Save-Output {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(ValueFromPipeline=$true)]
        $InputObject
    )
    begin {
        $file = Join-Path $outDir "$Name.txt"
        "" | Out-File -FilePath $file -Encoding utf8
    }
    process {
        try {
            if ($null -ne $InputObject) {
                $InputObject | Out-File -FilePath $file -Encoding utf8 -Append
            }
        } catch {
            "ERROR saving $Name : $_" | Out-File -FilePath (Join-Path $outDir "errors.txt") -Append
        }
    }
}

"Start collection: $(Get-Date)" | Save-Output -Name "collection_start"

### 1) OS / Version
try {
    $os   = Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime
    $comp = Get-CimInstance Win32_ComputerSystem    | Select Manufacturer,Model,Domain
    ("=== OS ===", ($os | Format-List | Out-String), "`n=== Computer ===", ($comp | Format-List | Out-String), "`n=== systeminfo ===", (systeminfo | Out-String)) -join "`r`n" |
        Save-Output -Name "os_version_systeminfo"
} catch { "Failed to get OS info: $_" | Save-Output -Name "os_version_error" }

### 2) Running processes
try {
    Get-Process | Sort-Object CPU -Descending |
        Select Id,ProcessName,CPU,Handles,StartTime -ErrorAction SilentlyContinue |
        Format-Table -AutoSize | Out-String | Save-Output -Name "running_processes"
} catch { "Failed to list processes: $_" | Save-Output -Name "running_processes_error" }

### 3) Listening ports & owning processes
try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        Get-NetTCPConnection -State Listen |
            Select LocalAddress,LocalPort,OwningProcess |
            Sort LocalPort |
            Format-Table -AutoSize | Out-String | Save-Output -Name "tcp_listening"

        Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess |
            ForEach-Object {
                $p    = $_
                $proc = try { Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue } catch { $null }
                [PSCustomObject]@{
                    LocalAddress = $p.LocalAddress
                    LocalPort    = $p.LocalPort
                    PID          = $p.OwningProcess
                    ProcessName  = if ($proc) { $proc.ProcessName } else { "<not found>" }
                }
            } | Format-Table -AutoSize | Out-String | Save-Output -Name "tcp_listening_with_process"

        if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
            Get-NetUDPEndpoint |
                Select LocalAddress,LocalPort,OwningProcess |
                ForEach-Object {
                    $p    = $_
                    $proc = try { Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue } catch { $null }
                    [PSCustomObject]@{
                        LocalAddress = $p.LocalAddress
                        LocalPort    = $p.LocalPort
                        PID          = $p.OwningProcess
                        ProcessName  = if ($proc) { $proc.ProcessName } else { "<not found>" }
                    }
                } | Format-Table -AutoSize | Out-String | Save-Output -Name "udp_endpoints"
        }
    } else {
        netstat -ano | Out-String | Save-Output -Name "netstat_ano"
        Get-Process | Select Id,ProcessName | Format-Table -AutoSize | Out-String | Save-Output -Name "process_id_map"
    }
} catch { "Failed to enumerate ports: $_" | Save-Output -Name "ports_error" }

### 3b) Common service port checks (AD, SSH, SMB, web, DBs, RDP, WinRM, etc.)
try {
    # Define common services and their well-known ports (TCP unless noted)
    $commonServices = @(
        @{Name="Kerberos"; Ports=@(88)}
        @{Name="LDAP"; Ports=@(389)}
        @{Name="LDAPS"; Ports=@(636)}
        @{Name="GlobalCatalog"; Ports=@(3268,3269)}
        @{Name="SMB"; Ports=@(445)}
        @{Name="RPC"; Ports=@(135)}
        @{Name="RDP"; Ports=@(3389)}
        @{Name="SSH"; Ports=@(22)}
        @{Name="HTTP"; Ports=@(80)}
        @{Name="HTTPS"; Ports=@(443)}
        @{Name="HTTP_Alt"; Ports=@(8080,8000)}
        @{Name="MSSQL"; Ports=@(1433,1434)} # 1434 UDP for SQL Browser
        @{Name="MySQL"; Ports=@(3306)}
        @{Name="PostgreSQL"; Ports=@(5432)}
        @{Name="OracleDB"; Ports=@(1521)}
        @{Name="WinRM"; Ports=@(5985,5986)}
        @{Name="SNMP"; Ports=@(161)} # UDP
        @{Name="DNS"; Ports=@(53)}    # UDP/TCP (will test TCP)
    )

    $results = @()

    foreach ($svc in $commonServices) {
        foreach ($port in $svc.Ports) {
            $entry = [ordered]@{
                Service    = $svc.Name
                Port       = $port
                Protocol   = "TCP"
                Listening  = $false
                PID        = $null
                Process    = $null
                ConnectOK  = $false
                TcpTest    = $null
            }

            # If port is commonly UDP-only (like 161 or 53 UDP), mark protocol accordingly for UDP-only ports
            if ($port -in 161) { $entry.Protocol = "UDP" }

            # 1) Try to find listening process via Get-NetTCPConnection (or netstat fallback)
            if ($entry.Protocol -eq "TCP") {
                if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
                    $ln = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
                    if ($ln) {
                        $entry.Listening = $true
                        $entry.PID = ($ln | Select-Object -First 1).OwningProcess
                        $proc = try { Get-Process -Id $entry.PID -ErrorAction SilentlyContinue } catch { $null }
                        if ($proc) { $entry.Process = $proc.ProcessName }
                    }
                } else {
                    # netstat fallback parsing for TCP
                    $ns = netstat -ano | Select-String -Pattern "LISTENING" | Select-String -Pattern "[:.]$port\s" -SimpleMatch
                    if ($ns) {
                        $entry.Listening = $true
                        # extract PID from netstat line
                        if ($ns -match '\s+(\d+)$') { $entry.PID = [int]$matches[1] }
                        if ($entry.PID) {
                            $proc = try { Get-Process -Id $entry.PID -ErrorAction SilentlyContinue } catch { $null }
                            if ($proc) { $entry.Process = $proc.ProcessName }
                        }
                    }
                }
            } else {
                # UDP check -- use Get-NetUDPEndpoint if present
                if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
                    $ud = Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue
                    if ($ud) {
                        $entry.Listening = $true
                        $entry.PID = ($ud | Select-Object -First 1).OwningProcess
                        $proc = try { Get-Process -Id $entry.PID -ErrorAction SilentlyContinue } catch { $null }
                        if ($proc) { $entry.Process = $proc.ProcessName }
                        $entry.Protocol = "UDP"
                    }
                } else {
                    # no easy UDP endpoint check available; skip listening detection for UDP
                    $entry.TcpTest = "UDP - listening detection not available"
                }
            }

            # 2) Test TCP connectivity to localhost port (useful even if not listening there could be firewall)
            if ($entry.Protocol -eq "TCP") {
                if (Get-Command Test-NetConnection -ErrorAction SilentlyContinue) {
                    $tnc = Test-NetConnection -ComputerName 127.0.0.1 -Port $port -WarningAction SilentlyContinue
                    if ($tnc) {
                        $entry.ConnectOK = $tnc.TcpTestSucceeded
                        $entry.TcpTest   = ($tnc | Select-Object -Property PingSucceeded,RemoteAddress,RemotePort,TcpTestSucceeded,RoundtripTime | Out-String).Trim()
                    }
                } else {
                    # .NET TcpClient fallback
                    try {
                        $client = New-Object System.Net.Sockets.TcpClient
                        $iar = $client.BeginConnect('127.0.0.1',$port,$null,$null)
                        $wait = $iar.AsyncWaitHandle.WaitOne(1000) # 1s timeout
                        if ($wait -and $client.Connected) {
                            $client.EndConnect($iar)
                            $entry.ConnectOK = $true
                            $entry.TcpTest = "TcpClient: connected"
                            $client.Close()
                        } else {
                            $entry.ConnectOK = $false
                            $entry.TcpTest = "TcpClient: not connected/timeout"
                        }
                    } catch {
                        $entry.ConnectOK = $false
                        $entry.TcpTest = "TcpClient: error $($_.Exception.Message)"
                    }
                }
            }

            $results += New-Object PSObject -Property $entry
        }
    }

    # Save a nice table and a CSV for easier analysis
    $results | Sort-Object Service,Port |
        Format-Table Service,Port,Protocol,Listening,PID,Process,ConnectOK | Out-String | Save-Output -Name "common_service_ports_table"

    $results | Export-Csv -Path (Join-Path $outDir "common_service_ports.csv") -NoTypeInformation -Force

    # Also save extended details
    ($results | Format-List * | Out-String) | Save-Output -Name "common_service_ports_detailed"
} catch { "Failed common service port checks: $_" | Save-Output -Name "common_ports_error" }

### 4) Services (installed + running + service account)
try {
    Get-CimInstance Win32_Service |
        Select Name,DisplayName,State,StartMode,StartName,ProcessId |
        Sort DisplayName |
        Format-Table -AutoSize | Out-String | Save-Output -Name "installed_services_and_service_accounts"

    Get-Service | Where-Object {$_.Status -eq 'Running'} |
        Select Name,DisplayName,Status,StartType |
        Format-Table -AutoSize | Out-String | Save-Output -Name "running_services"
} catch { "Failed to list services: $_" | Save-Output -Name "services_error" }

### 5) Local user accounts
try {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select Name,Enabled,Description,LastLogon |
            Format-Table -AutoSize | Out-String | Save-Output -Name "local_users"
    } else {
        Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
            Select Name,Disabled,Lockout,Status,SID |
            Format-Table -AutoSize | Out-String | Save-Output -Name "local_users_wmi"
    }
} catch { "Failed to enumerate users: $_" | Save-Output -Name "users_error" }

### 6) Admin accounts (robust + diagnostics)
try {
    # Find local Administrators group by well-known SID (language-agnostic)
    $adminGroup = Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'" -ErrorAction SilentlyContinue

    # If nothing found, try without SID filter (rare)
    if (-not $adminGroup) {
        $adminGroup = Get-CimInstance Win32_Group | Where-Object { $_.Name -match 'Admin' -or $_.SID -eq 'S-1-5-32-544' } | Select-Object -First 1
    }

    if ($adminGroup) {
        # Save the admin group basic info for debugging
        $adminGroup | Format-List * | Out-String | Save-Output -Name "admin_group_info"

        # Get associated members via Win32_GroupUser
        $assoc = Get-CimAssociatedInstance -InputObject $adminGroup -Association Win32_GroupUser -ErrorAction SilentlyContinue

        # Dump raw association objects so we can inspect what came back (helps debug domain cases)
        if ($assoc) {
            $assoc | Format-List * | Out-String | Save-Output -Name "admin_group_assoc_raw"
        } else {
            "No association objects returned by Get-CimAssociatedInstance." | Save-Output -Name "admin_group_assoc_raw"
        }

        $rows = @()
        if ($assoc) {
            foreach ($a in $assoc) {
                # PartComponent usually contains the member reference (Win32_UserAccount or Win32_Group)
                $raw = $a.PartComponent.ToString()
                # Try to extract Class, Domain and Name using regex
                if ($raw -match 'Win32_(UserAccount|Group)\.Domain="([^"]+)",Name="([^"]+)"') {
                    $cls    = $matches[1]       # UserAccount or Group
                    $domain = $matches[2]
                    $name   = $matches[3]

                    # Try to resolve to a Win32_Account (generic) which covers local+domain accounts
                    $acct = Get-CimInstance -ClassName Win32_Account -Filter "Name='$name' AND Domain='$domain'" -ErrorAction SilentlyContinue

                    # If Win32_Account failed (domain not reachable), try Win32_UserAccount / Win32_Group locally
                    if (-not $acct) {
                        $acct = Get-CimInstance -ClassName "Win32_$cls" -Filter "Name='$name' AND Domain='$domain'" -ErrorAction SilentlyContinue
                    }

                    # Build a helpful row; include raw PartComponent for later inspection
                    $rows += [PSCustomObject]@{
                        Name         = "$domain\$name"
                        MemberClass  = $cls
                        Resolved     = $([bool]$acct)
                        SID          = if ($acct) { $acct.SID } else { $null }
                        Disabled     = if ($acct -and $acct.PSObject.Properties.Match('Disabled')) { $acct.Disabled } else { $null }
                        LocalAccount = if ($acct -and $acct.PSObject.Properties.Match('LocalAccount')) { $acct.LocalAccount } else { $null }
                        RawPart      = $raw
                    }
                } else {
                    # Unknown formatting — still capture raw
                    $rows += [PSCustomObject]@{
                        Name         = "<unparsed>"
                        MemberClass  = "<unknown>"
                        Resolved     = $false
                        SID          = $null
                        Disabled     = $null
                        LocalAccount = $null
                        RawPart      = $raw
                    }
                }
            }
        }

        if ($rows.Count -gt 0) {
            $rows | Sort-Object Resolved,Name |
                Format-Table Name,MemberClass,Resolved,SID,Disabled,LocalAccount -AutoSize | Out-String | Save-Output -Name "admin_group_members"

            # Also save raw CSV with RawPart so you can inspect domain strings easily
            $rows | Export-Csv -Path (Join-Path $outDir "admin_group_members.csv") -NoTypeInformation -Force
        } else {
            # If CIM returned no members, fall back to net localgroup which always shows the group membership (may include DOMAIN\user entries)
            "CIM returned no member rows; falling back to 'net localgroup' output." | Save-Output -Name "admin_group_members"
            (net localgroup Administrators | Out-String) | Save-Output -Name "admin_group_members_net_raw"
        }
    } else {
        "Administrators group could not be found via SID or name." | Save-Output -Name "admin_group_error"
        (net localgroup Administrators | Out-String) | Save-Output -Name "admin_group_members_net_raw"
    }
} catch {
    "Failed to list Administrators group members (robust block): $_" | Save-Output -Name "admin_group_error"
}


### 8) Scheduled tasks (“cronjobs”)
try {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        Get-ScheduledTask | Select TaskName,TaskPath,State,Principal |
            Format-Table -AutoSize | Out-String | Save-Output -Name "scheduled_tasks_list"

        Get-ScheduledTask | ForEach-Object {
            $t = $_
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                TaskName       = $t.TaskName
                TaskPath       = $t.TaskPath
                State          = $t.State
                LastRunTime    = if ($info) { $info.LastRunTime } else { $null }
                LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
                Author         = $t.Principal.UserId
                RunLevel       = $t.Principal.RunLevel
            }
        } | Format-Table -AutoSize | Out-String | Save-Output -Name "scheduled_tasks_detailed"
    } else {
        schtasks /query /fo LIST /v | Out-String | Save-Output -Name "schtasks_list_verbose"
    }
    if (Get-Command at -ErrorAction SilentlyContinue) {
        at | Out-String | Save-Output -Name "legacy_at_jobs"
    }
} catch { "Failed to enumerate scheduled tasks: $_" | Save-Output -Name "scheduled_tasks_error" }

### 9) Firewall rules (summary)
try {
    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        Get-NetFirewallRule |
            Select DisplayName,Direction,Action,Enabled,Profile |
            Format-Table -AutoSize | Out-String | Save-Output -Name "firewall_rules_summary"
    } else {
        "Get-NetFirewallRule not available on this system" | Save-Output -Name "firewall_info"
    }
} catch { "Failed to get firewall rules: $_" | Save-Output -Name "firewall_error" }

### 10) Network config
try {
    ipconfig /all | Out-String | Save-Output -Name "ipconfig_all"
    arp -a        | Out-String | Save-Output -Name "arp_a"
    route print   | Out-String | Save-Output -Name "route_print"
} catch { "Failed to capture network configuration: $_" | Save-Output -Name "network_error" }

"Collection finished: $(Get-Date)" | Save-Output -Name "collection_end"

# Manifest
Get-ChildItem -Path $outDir -File | Select Name,Length |
    Format-Table -AutoSize | Out-String | Save-Output -Name "manifest"

Write-Host "Enumeration complete. Outputs saved to: $outDir"
