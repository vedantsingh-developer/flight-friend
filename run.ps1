$ErrorActionPreference = 'Stop'
$appDir = $PSScriptRoot
if (-not (Test-Path (Join-Path $appDir '.env'))) { throw 'Run .\setup.cmd first to create your developer login and encryption keys.' }
$nodeExe = Join-Path $appDir 'node.exe'
if (-not (Test-Path $nodeExe)) {
  $installed = Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue
  if ($installed) { $nodeExe = $installed.Source } else { throw 'Node.exe is missing. Keep it beside run.cmd, or install Node.js 22.5 or newer.' }
}
Push-Location $appDir
try { & $nodeExe --env-file=.env server.mjs }
finally { Pop-Location }

