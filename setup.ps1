$ErrorActionPreference = 'Stop'
$appDir = $PSScriptRoot
if (Test-Path (Join-Path $appDir '.env')) { throw 'A .env file already exists. Keep it; it contains your encryption keys.' }
$nodeExe = Join-Path $appDir 'node.exe'
if (-not (Test-Path $nodeExe)) {
  $installed = Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue
  if ($installed) { $nodeExe = $installed.Source }
}
$nodeVersion = ''
if (Test-Path $nodeExe) { try { $nodeVersion = (& $nodeExe -p 'process.versions.node' 2>$null).Trim() } catch {} }
if (-not $nodeVersion) {
  $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  $nodeFolder = switch ($architecture) { 'X64' { 'win-x64' } 'Arm64' { 'win-arm64' } default { throw "Automatic Node setup does not support $architecture. Install Node.js 22.5 or newer from nodejs.org." } }
  $baseUrl = 'https://nodejs.org/dist/v24.22.3'
  $portablePath = Join-Path $appDir 'node.exe'
  try {
    Write-Host 'Downloading verified standalone Node.js (about 45 MB). The byte counter will rise until the download finishes.'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $checksums = (Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/SHASUMS256.txt").Content
    $pattern = "(?m)^([a-fA-F0-9]{64})\s+$nodeFolder/node\.exe\s*$"
    $match = [regex]::Match($checksums, $pattern)
    if (-not $match.Success) { throw 'Could not find the official checksum for this Windows architecture.' }
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$nodeFolder/node.exe" -OutFile $portablePath
    $actualHash = (Get-FileHash -LiteralPath $portablePath -Algorithm SHA256).Hash
    if ($actualHash -ne $match.Groups[1].Value) { throw 'The downloaded Node file did not match the official SHA-256 checksum.' }
    $nodeExe = $portablePath
    $nodeVersion = (& $nodeExe -p 'process.versions.node' 2>$null).Trim()
    Write-Host "Downloaded and verified portable Node.js $nodeVersion."
  } catch {
    throw "Node.js was not found and automatic download failed. Download the official portable binary from https://nodejs.org/dist/v24.22.3/$nodeFolder/node.exe, save it beside setup.cmd as node.exe, then run setup.cmd again. Details: $($_.Exception.Message)"
  }
}
try { $parsedVersion = [version]$nodeVersion } catch { throw "Could not read the Node.js version from $nodeExe." }
if ($parsedVersion -lt [version]'22.5') { throw "Node.js 22.5 or newer is required. Found $nodeVersion." }
$username = Read-Host 'Choose a developer username (3–60 letters, numbers, dot, underscore, hyphen)'
$securePassword = Read-Host 'Choose a strong developer password (14+ characters)' -AsSecureString
$secureConfirm = Read-Host 'Enter the developer password again' -AsSecureString
$ptr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$ptr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureConfirm)
try {
  $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr1)
  $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr2)
  if ($plain1 -cne $plain2) { throw 'The passwords did not match.' }
  $env:FF_SETUP_USERNAME = $username
  $env:FF_SETUP_PASSWORD = $plain1
  Push-Location $appDir
  try { & $nodeExe setup.mjs; if ($LASTEXITCODE -ne 0) { throw 'Setup failed.' } }
  finally { Pop-Location }
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $secretFile = Join-Path $appDir '.env'
    $acl = Get-Acl -LiteralPath $secretFile
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $access = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow')
    [void]$acl.AddAccessRule($access)
    Set-Acl -LiteralPath $secretFile -AclObject $acl
  } catch { Write-Warning 'Could not restrict .env file permissions automatically. Keep that file private.' }
  Write-Host "`nSetup complete. Start the local app with: .\run.cmd"
  Write-Host 'Open the website at http://localhost:3000/ and developer dashboard at http://localhost:3000/admin/'
} finally {
  if ($ptr1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr1) }
  if ($ptr2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr2) }
  Remove-Item Env:FF_SETUP_USERNAME -ErrorAction SilentlyContinue
  Remove-Item Env:FF_SETUP_PASSWORD -ErrorAction SilentlyContinue
  $plain1 = $null; $plain2 = $null
}

