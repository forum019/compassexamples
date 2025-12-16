<# 
Compass Academy — Midterm Concept Lab (PowerShell)
Topics: Integrity, Hashing+Salting, Typosquatting, Functions, DHCP/Router/Switch, UDP vs TCP
#>

Write-Host "`n=== Security+ Midterm Concept Lab ===`n" -ForegroundColor Cyan

# ---------------------------
# 1) INTEGRITY DEMO (tampering)
# ---------------------------
Write-Host "1) INTEGRITY DEMO — detecting unauthorized modification" -ForegroundColor Yellow

$originalText = "Meet at 3:15 in Room 204."
$originalHash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($originalText))) -Algorithm SHA256).Hash

Write-Host "Original message: $originalText"
Write-Host "Original SHA256:  $originalHash"

# Simulate tampering (like a grade/record being modified)
$tamperedText = "Meet at 3:15 in Room 404."
$tamperedHash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($tamperedText))) -Algorithm SHA256).Hash

Write-Host "`nTampered message: $tamperedText"
Write-Host "Tampered SHA256:  $tamperedHash"

if ($originalHash -ne $tamperedHash) {
  Write-Host "`nResult: Hash changed -> Integrity violation detected (content was modified)." -ForegroundColor Green
}

# ---------------------------
# 2) HASHING + SALTING DEMO
# ---------------------------
Write-Host "`n2) HASHING + SALTING DEMO — same password, different stored values" -ForegroundColor Yellow

function Get-Sha256Hex {
  param([Parameter(Mandatory)] [string]$Text)
  $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
  $sha = [Security.Cryptography.SHA256]::Create()
  ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
}

function New-SaltHex {
  param([int]$Bytes = 16) # 16 bytes = 128-bit salt
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $b = New-Object byte[] $Bytes
  $rng.GetBytes($b)
  ($b | ForEach-Object { $_.ToString("x2") }) -join ""
}

$password = "Password1!"   # demo only — never hardcode real passwords

# Without salt
$hash1 = Get-Sha256Hex $password
$hash2 = Get-Sha256Hex $password

Write-Host "Password: $password"
Write-Host "`nWithout salt:"
Write-Host "Hash #1: $hash1"
Write-Host "Hash #2: $hash2"
Write-Host "Same input -> same hash (this is why rainbow tables work)." -ForegroundColor DarkGray

# With salt (two users with SAME password)
$saltA = New-SaltHex
$saltB = New-SaltHex

# One common storage approach: store salt + hash(salt + password)
$storedA = Get-Sha256Hex ($saltA + $password)
$storedB = Get-Sha256Hex ($saltB + $password)

Write-Host "`nWith salt (two different users, same password):"
Write-Host "User A Salt:  $saltA"
Write-Host "User A Hash:  $storedA"
Write-Host "User B Salt:  $saltB"
Write-Host "User B Hash:  $storedB"

if ($storedA -ne $storedB) {
  Write-Host "`nResult: Same password -> different stored hashes because of salting." -ForegroundColor Green
}

Write-Host "Key idea: attackers can't reuse one precomputed table for everyone if each account has a unique salt." -ForegroundColor DarkGray

# ---------------------------
# 3) TYPOSQUATTING DEMO (safe)
# ---------------------------
Write-Host "`n3) TYPOSQUATTING AWARENESS — generate common typo domains (do NOT visit random ones)" -ForegroundColor Yellow

function Get-TypoCandidates {
  param([Parameter(Mandatory)] [string]$Domain)

  # super simple educational generator — not exhaustive
  $base = $Domain.ToLower()
  $candidates = New-Object System.Collections.Generic.List[string]

  # Missing a character
  for ($i = 0; $i -lt $base.Length; $i++) {
    $candidates.Add(($base.Remove($i,1)))
  }

  # Swap adjacent characters
  for ($i = 0; $i -lt $base.Length - 1; $i++) {
    $chars = $base.ToCharArray()
    $tmp = $chars[$i]
    $chars[$i] = $chars[$i+1]
    $chars[$i+1] = $tmp
    $candidates.Add((-join $chars))
  }

  # Common TLD confusion (only if looks like a domain)
  if ($base -match "\.") {
    $candidates.Add($base -replace "\.com$",".co")
    $candidates.Add($base -replace "\.com$",".net")
    $candidates.Add($base -replace "\.org$",".com")
  }

  $candidates | Select-Object -Unique | Select-Object -First 20
}

$targetDomain = "microsoft.com"
Write-Host "Target domain: $targetDomain"
Write-Host "Sample typo candidates (education only):"
Get-TypoCandidates $targetDomain | ForEach-Object { " - $_" }

Write-Host "`nSafety rule: never trust the page branding—verify the EXACT domain before typing passwords." -ForegroundColor DarkGray

# ---------------------------
# 4) POWERSHELL FUNCTION DEMO (reusability)
# ---------------------------
Write-Host "`n4) POWERSHELL FUNCTION — reuse code without copy/paste" -ForegroundColor Yellow

function Get-QuickNetInfo {
  Write-Host "IPv4 / Gateway / DHCP / DNS summary:" -ForegroundColor Cyan
  ipconfig /all | Select-String -Pattern "IPv4 Address|Default Gateway|DHCP Enabled|DHCP Server|DNS Servers" -Context 0,1
}

Write-Host "Calling the function twice (no duplicate code needed):"
Get-QuickNetInfo
Write-Host ""
Get-QuickNetInfo

# ---------------------------
# 5) NETWORK DEVICES + DHCP (what you can observe)
# ---------------------------
Write-Host "`n5) DHCP + ROUTER + SWITCH — what your PC can actually see" -ForegroundColor Yellow

# DHCP + Router evidence (gateway)
$ipInfo = ipconfig
Write-Host "Your Default Gateway is usually your ROUTER (Network Layer device connecting networks)."
(ipconfig | Select-String "Default Gateway") | ForEach-Object { $_.Line }

Write-Host "`nDHCP gives you your IP configuration dynamically:"
(ipconfig /all | Select-String "DHCP Enabled|DHCP Server") | ForEach-Object { $_.Line }

# Switch evidence: ARP table shows MAC addresses of local neighbors (switch forwards frames by MAC)
Write-Host "`nA SWITCH forwards traffic inside the LAN using MAC addresses."
Write-Host "You can't 'see' the switch directly, but you can see MAC addresses of LAN devices via ARP:"
arp -a

# Bonus: trace route shows the router hop(s) out of your LAN
Write-Host "`nTraceroute (first hop is often your router):"
tracert -d 1.1.1.1 | Select-Object -First 6

# ---------------------------
# 6) UDP vs TCP (real connection evidence)
# ---------------------------
Write-Host "`n6) UDP vs TCP — speed vs reliability in real life" -ForegroundColor Yellow

Write-Host "TCP connections on your machine right now (reliable, ordered):" -ForegroundColor Cyan
netstat -ano -p tcp | Select-Object -First 15

Write-Host "`nUDP endpoints on your machine right now (fast, no delivery guarantees):" -ForegroundColor Cyan
netstat -ano -p udp | Select-Object -First 15

Write-Host "`nStory time:" -ForegroundColor DarkGray
Write-Host " - Video calls / live streams / many games often prefer UDP: late packets are worse than missing packets."
Write-Host " - Web pages / downloads prefer TCP: missing data must be retransmitted correctly."

Write-Host "`n=== End of Lab ===`n" -ForegroundColor Cyan
