param(
    [ValidateSet('Serve', 'Build', 'Check', 'Install', 'Lock')]
    [string]$Task = 'Serve'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$driveLetter = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxPath = '/mnt/' + $driveLetter + $projectRoot.Substring(2).Replace('\', '/') + '/tools/local.sh'
& wsl -d Ubuntu -- bash $linuxPath $Task.ToLowerInvariant()
if ($LASTEXITCODE -ne 0) { throw "Jekyll task failed with exit code $LASTEXITCODE." }
