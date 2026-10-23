# laptop-probe.ps1 - run on the VPN laptop WITH THE VPN CONNECTED.
# Read-only: changes nothing, sends nothing anywhere. Writes
# vpn-probe.txt on the Desktop; read it before sharing it.
#   powershell -ExecutionPolicy Bypass -File .\laptop-probe.ps1 [-Targets host:port, ...]
# -Targets are services behind the VPN to test, e.g. 10.20.30.40:80,app.corp.example:443
param([string[]]$Targets = @())

$out = Join-Path ([Environment]::GetFolderPath('Desktop')) 'vpn-probe.txt'
$match = 'SonicWall|Connect ?Tunnel|Aventail|NetExtender|SMA'

function Section($title, [scriptblock]$body) {
    "`n===== $title =====" | Out-File $out -Append -Encoding utf8
    try { & $body 2>&1 | Out-String -Width 250 | Out-File $out -Append -Encoding utf8 }
    catch { "error: $_" | Out-File $out -Append -Encoding utf8 }
}

"probe $(Get-Date -Format s)" | Out-File $out -Encoding utf8

Section 'System' {
    $os = Get-CimInstance Win32_OperatingSystem
    "$env:COMPUTERNAME  user=$env:USERNAME  $($os.Caption) $($os.Version)"
    "admin: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
    # Company-managed? (Intune / domain / policies may forbid what we install)
    "domain joined: $((Get-CimInstance Win32_ComputerSystem).PartOfDomain)"
    dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|MDMUrl'
}

Section 'Installed VPN software' {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                     HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                     HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "$match|WireGuard|OpenSSH" } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation | Format-List
}

Section 'Program files (looking for a CLI)' {
    $dirs = 'C:\Program Files', 'C:\Program Files (x86)', $env:LOCALAPPDATA, $env:ProgramData |
        ForEach-Object { Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue } |
        Where-Object Name -match $match
    foreach ($d in $dirs) {
        "--- $($d.FullName)"
        Get-ChildItem $d.FullName -Recurse -Include *.exe, *.dll, *.ps1, *.cmd, *.bat -ErrorAction SilentlyContinue |
            Select-Object @{n='file'; e={$_.FullName.Substring($d.FullName.Length)}},
                          @{n='version'; e={$_.VersionInfo.FileVersion}}, Length | Format-Table -AutoSize
    }
}

Section 'Config and log files (names only, contents NOT read)' {
    $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData |
        ForEach-Object { Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue } |
        Where-Object Name -match $match |
        ForEach-Object { Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue } |
        Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
}

Section 'Recent disconnect lines in VPN logs' {
    $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData |
        ForEach-Object { Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue } |
        Where-Object Name -match $match |
        ForEach-Object { Get-ChildItem $_.FullName -Recurse -File -Include *.log, *.txt -ErrorAction SilentlyContinue } |
        ForEach-Object {
            "--- $($_.FullName)"
            Select-String -Path $_.FullName -Pattern 'idle|timeout|disconnect|re-?auth|expire|keepalive' -ErrorAction SilentlyContinue |
                Select-Object -Last 25 | ForEach-Object { $_.Line }
        }
}

Section 'Services and processes' {
    Get-Service | Where-Object { $_.DisplayName -match "$match|sshd|WireGuard" } |
        Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
    Get-CimInstance Win32_Process | Where-Object { $_.Name -match $match -or $_.ExecutablePath -match $match } |
        Select-Object Name, ProcessId, ExecutablePath, CommandLine | Format-List
}

Section 'Scheduled tasks from the VPN vendor' {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath + $_.TaskName + $_.Author -match $match } |
        Select-Object TaskPath, TaskName, State | Format-Table -AutoSize
}

Section 'Network adapters and addresses' {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Format-Table -AutoSize
    Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize
    Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | Format-Table -AutoSize
}

Section 'Routes (split or full tunnel?)' {
    Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -notmatch '^(224|255)\.' } |
        Sort-Object DestinationPrefix | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric | Format-Table -AutoSize
}

Section 'DNS rules (NRPT) and suffixes' {
    Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | Format-List
    Get-DnsClient | Where-Object ConnectionSpecificSuffix | Select-Object InterfaceAlias, ConnectionSpecificSuffix | Format-Table -AutoSize
}

Section 'Reachability over the VPN' {
    foreach ($t in $Targets) {
        $h, $p = $t -split ':', 2
        if ($h -notmatch '^[\d.]+$') { Resolve-DnsName $h -ErrorAction SilentlyContinue | Select-Object Name, Type, IPAddress | Format-Table -AutoSize }
        $r = Test-NetConnection $h -Port ([int]$p) -WarningAction SilentlyContinue
        "${h}:$p  tcp=$($r.TcpTestSucceeded)  via=$($r.InterfaceAlias)  src=$($r.SourceAddress.IPAddress)"
    }
    if (-not $Targets) { '(no -Targets given)' }
}

Section 'LAN side (can the home network reach this laptop?)' {
    Get-NetConnectionProfile | Select-Object InterfaceAlias, Name, NetworkCategory | Format-Table -AutoSize
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize
}

Section 'Power (sleep kills the VPN)' {
    powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Select-String 'Current (AC|DC) Power Setting Index'
    powercfg /a
}

Write-Host "Done: $out"
