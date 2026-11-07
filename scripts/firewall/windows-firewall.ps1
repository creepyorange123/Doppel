# Shadow Profile: OS-level outbound rules on Windows (Phase 5).
# Run in an elevated PowerShell after reviewing. Nothing here runs automatically.
#
# - The app (Electron) and the analyzer may reach only loopback.
# - The research agent may reach only Tavily and Exa on 443 (resolved now; rerun if their IPs change).
# - Zero-network mode: run with -ZeroNetwork to block the research agent entirely.
#
# Windows Firewall matches programs, not scripts: in release builds these paths are
# the signed PyInstaller binaries. In development they are the venv's python.exe,
# which is shared by both, so use release builds for the real check.

param(
  [Parameter(Mandatory = $true)] [string] $AppExe,        # Shadow Profile.exe
  [Parameter(Mandatory = $true)] [string] $AnalyzerExe,   # analyzer.exe
  [Parameter(Mandatory = $true)] [string] $ResearchExe,   # research.exe
  [switch] $ZeroNetwork,
  [switch] $Remove
)

$group = "Shadow Profile"
Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) { Write-Output "Removed Shadow Profile rules."; return }

foreach ($exe in @($AppExe, $AnalyzerExe)) {
  New-NetFirewallRule -Group $group -DisplayName "Shadow Profile loopback only: $exe" -Direction Outbound `
    -Program $exe -RemoteAddress 127.0.0.1, ::1 -Action Allow | Out-Null
  New-NetFirewallRule -Group $group -DisplayName "Shadow Profile block: $exe" -Direction Outbound `
    -Program $exe -RemoteAddress Internet, Intranet, LocalSubnet -Action Block | Out-Null
}

if ($ZeroNetwork) {
  New-NetFirewallRule -Group $group -DisplayName "Shadow Profile research blocked (zero-network)" -Direction Outbound `
    -Program $ResearchExe -Action Block | Out-Null
} else {
  $ips = @("api.tavily.com", "api.exa.ai") | ForEach-Object { (Resolve-DnsName $_ -Type A_AAAA).IPAddress } | Sort-Object -Unique
  New-NetFirewallRule -Group $group -DisplayName "Shadow Profile research: Tavily and Exa" -Direction Outbound `
    -Program $ResearchExe -Protocol TCP -RemotePort 443 -RemoteAddress $ips -Action Allow | Out-Null
  # LIMITATION: in Windows Firewall a Block rule always beats an Allow rule, and the default
  # outbound action is profile-wide, so "TCP 443 to these IPs only" can't be expressed for one
  # program without blocking outbound for the whole machine. We block every other port and UDP;
  # HTTPS to other hosts is stopped by the egress gate in analyzer/research/egress.py and is
  # visible in the ledger. Confirm with Wireshark during the Phase 5 check.
  New-NetFirewallRule -Group $group -DisplayName "Shadow Profile research: block other ports" -Direction Outbound `
    -Program $ResearchExe -Protocol TCP -RemotePort 1-442, 444-65535 -Action Block | Out-Null
  New-NetFirewallRule -Group $group -DisplayName "Shadow Profile research: block UDP" -Direction Outbound `
    -Program $ResearchExe -Protocol UDP -Action Block | Out-Null
}
Write-Output "Shadow Profile firewall rules installed."
