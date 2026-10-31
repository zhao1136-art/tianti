# Push this repository to the mirror remote and verify it landed.
#
# Why this exists
# ---------------
# The working tree lives on a removable USB disk (G:) and the repo originally
# had NO remote at all -- 14 commits existed only on that one drive.
# A local bare mirror is on the internal SATA disk (D:), i.e. a *different
# physical device*, so losing/breaking the USB stick no longer loses the repo.
#
# This is still machine-local: it does not survive losing the whole computer.
# For off-machine backup add a hosted remote, e.g.:
#   git remote add github https://github.com/<user>/<repo>.git
#   git push --all github; git push --tags github
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\backup.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\backup.ps1 -Remote github
#
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads .ps1 as ANSI
# (GBK here) unless it has a BOM, so non-ASCII comments would be mangled.

param(
    [string]$Remote = "backup"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "repo   : $root"
Write-Host "remote : $Remote"

# ---- 1) remote must exist ------------------------------------------------
$remotes = @(git remote)
if ($remotes -notcontains $Remote) {
    Write-Host "[ERROR] remote '$Remote' is not configured."
    Write-Host "        add it first, e.g.:"
    Write-Host "        git remote add $Remote file:///D:/git-backup/tianti.git"
    exit 1
}
$url = git remote get-url $Remote
Write-Host "url    : $url"
Write-Host ""

# ---- 2) push branches + tags --------------------------------------------
Write-Host "[1/2] pushing branches ..."
git push --all $Remote
if ($LASTEXITCODE -ne 0) { Write-Host "[FAILED] push --all"; exit 2 }

Write-Host "[2/2] pushing tags ..."
git push --tags $Remote
if ($LASTEXITCODE -ne 0) { Write-Host "[FAILED] push --tags"; exit 2 }
Write-Host ""

# ---- 3) verify the mirror HEAD matches local HEAD -----------------------
# A push that reports success is not proof the mirror is current; compare SHAs.
$branch = git rev-parse --abbrev-ref HEAD
$local = (git rev-parse HEAD).Trim()

$path = ""
if ($url -like "file://*") {
    $path = ($url -replace '^file:///', '') -replace '/', '\'
}

$remoteSha = ""
if ($path -and (Test-Path $path)) {
    $remoteSha = (git --git-dir="$path" rev-parse $branch 2>$null)
    if ($remoteSha) { $remoteSha = $remoteSha.Trim() }
} elseif ($url -notlike "file://*") {
    # hosted remote: ask the server directly
    $remoteSha = (git ls-remote $Remote "refs/heads/$branch" 2>$null)
    if ($remoteSha) { $remoteSha = ($remoteSha -split "\s+")[0].Trim() }
}

Write-Host "branch      : $branch"
Write-Host "local  HEAD : $local"
Write-Host "remote HEAD : $(if($remoteSha){$remoteSha}else{'(unavailable)'})"

if (-not $remoteSha) {
    Write-Host "[WARN] could not read remote HEAD; push reported OK but unverified."
    exit 0
}
if ($local -ne $remoteSha) {
    Write-Host "[FAILED] mirror is out of sync with local HEAD."
    exit 3
}

$count = ""
if ($path -and (Test-Path $path)) {
    $count = (git --git-dir="$path" rev-list --count --all 2>$null)
}
Write-Host "[OK] mirror matches local HEAD$(if($count){" ($count commits)"})."
exit 0
