param(
    [ValidateSet('Serve', 'Build', 'Check', 'Install', 'Lock')]
    [string]$Task = 'Serve',
    [switch]$Drafts
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$driveLetter = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxPath = '/mnt/' + $driveLetter + $projectRoot.Substring(2).Replace('\', '/') + '/tools/local.sh'
$previewArgs = @($linuxPath, $Task.ToLowerInvariant())
if ($Drafts) {
    if ($Task -notin @('Serve', 'Build')) { throw '-Drafts is supported only with Serve or Build.' }
    $previewArgs += '--drafts'
}
& wsl -d Ubuntu -- bash @previewArgs
if ($LASTEXITCODE -ne 0) { throw "Jekyll task failed with exit code $LASTEXITCODE." }
