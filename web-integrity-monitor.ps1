<#
web-integrity-monitor.ps1
Purpose: Detect unexpected changes to IIS web content using SHA-256 hashes.
Usage:
  # Build / refresh baseline after verifying content:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Integrity\web-integrity-monitor.ps1 -Init

  # Monitor run (intended for scheduled task):
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Integrity\web-integrity-monitor.ps1
#>

param(
  [switch]$Init
)

$ErrorActionPreference = "Stop"

# --- CONFIG ---
$WebRoot    = "C:\inetpub\wwwroot"
$Baseline   = "C:\Integrity\baseline_sha256.json"
$LogFile    = "C:\Integrity\integrity.log"
$EventSource= "WebIntegrityMonitor"

# Email (optional) - replace with your SMTP + recipients
$EnableEmail = $true
$SmtpServer  = "mail.fullsoft.local"
$MailFrom    = "web-integrity@fullsoft.local"
$MailTo      = "server-mgmt@fullsoft.local"

# Only monitor typical static web content
$Extensions = @(".htm",".html",".css",".js",".png",".jpg",".jpeg",".gif",".svg")
$ExcludeDirs = @("C:\inetpub\wwwroot\logs","C:\inetpub\wwwroot\uploads")  # optional

function Write-Log([string]$Level,[string]$Message){
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  "$ts $Level $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

function Ensure-EventSource {
  if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    New-EventLog -LogName Application -Source $EventSource
  }
}

function Send-AlertEmail([string]$Subject,[string]$Body){
  if (-not $EnableEmail) { return }
  Send-MailMessage -SmtpServer $SmtpServer -From $MailFrom -To $MailTo -Subject $Subject -Body $Body
}

function Get-WebFiles {
  $files = Get-ChildItem -Path $WebRoot -Recurse -File | Where-Object {
    $Extensions -contains $_.Extension.ToLower()
  }

  if ($ExcludeDirs.Count -gt 0) {
    $files = $files | Where-Object {
      $full = $_.FullName
      -not ($ExcludeDirs | Where-Object { $full.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })
    }
  }
  return $files
}

function Compute-Hashes {
  $map = @{}
  foreach ($f in (Get-WebFiles)) {
    $rel = $f.FullName.Substring($WebRoot.Length).TrimStart('\')
    $map[$rel] = (Get-FileHash -Algorithm SHA256 -Path $f.FullName).Hash
  }
  return $map
}

# --- MAIN ---
New-Item -ItemType Directory -Force -Path (Split-Path $Baseline) | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $LogFile) | Out-Null

if ($Init) {
  $baselineMap = Compute-Hashes
  $baselineMap | ConvertTo-Json -Depth 4 | Out-File -FilePath $Baseline -Encoding utf8
  Write-Log "OK" "Baseline created/updated. Entries: $($baselineMap.Count). Baseline: $Baseline"
  exit 0
}

if (-not (Test-Path $Baseline)) {
  Write-Log "ERROR" "Baseline missing. Run with -Init after verifying web content. Baseline: $Baseline"
  exit 2
}

Ensure-EventSource

$baseline = Get-Content $Baseline -Raw | ConvertFrom-Json
$current  = Compute-Hashes

# Detect added/removed/changed
$changed = @()
$added   = @()
$removed = @()

foreach ($k in $current.Keys) {
  if (-not $baseline.PSObject.Properties.Name -contains $k) { $added += $k; continue }
  if ($current[$k] -ne $baseline.$k) { $changed += $k }
}

foreach ($k in $baseline.PSObject.Properties.Name) {
  if (-not $current.ContainsKey($k)) { $removed += $k }
}

$mismatchCount = $changed.Count + $added.Count + $removed.Count

if ($mismatchCount -eq 0) {
  Write-Log "OK" "baseline entries: $($baseline.PSObject.Properties.Count) checked: $($current.Count) mismatches: 0"
  exit 0
}

# Build alert text
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("Integrity change detected under $WebRoot")
$lines.Add("")
if ($changed.Count -gt 0) {
  $lines.Add("CHANGED:")
  foreach ($k in $changed) {
    $lines.Add("  $k")
    $lines.Add("    baseline: $($baseline.$k)")
    $lines.Add("    current : $($current[$k])")
  }
  $lines.Add("")
}
if ($added.Count -gt 0) {
  $lines.Add("ADDED:")
  $added | ForEach-Object { $lines.Add("  $_") }
  $lines.Add("")
}
if ($removed.Count -gt 0) {
  $lines.Add("REMOVED:")
  $removed | ForEach-Object { $lines.Add("  $_") }
  $lines.Add("")
}
$body = $lines -join "`r`n"

Write-Log "ALERT" "mismatches: $mismatchCount changed: $($changed.Count) added: $($added.Count) removed: $($removed.Count)"
Write-EventLog -LogName Application -Source $EventSource -EntryType Warning -EventId 3002 -Message $body

Send-AlertEmail -Subject "[ALERT] Web page integrity change on $env:COMPUTERNAME" -Body $body

exit 1
