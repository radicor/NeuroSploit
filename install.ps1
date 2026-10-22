# NeuroSploit installer for Windows (PowerShell) — by Joas A Santos & Red Team Leaders
#
#   irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex
#
# Downloads the prebuilt neurosploit.exe + agent library, installs them, and sets
# your User PATH + NEUROSPLOIT_BASE so you can run `neurosploit` from ANY folder —
# no need to cd into the repo. Falls back to building from source if needed.
# Env: NEUROSPLOIT_DIR (install dir), NEUROSPLOIT_REF (release tag),
#      NEUROSPLOIT_BUILD=1 (force source build).
$ErrorActionPreference = "Stop"

function Say($m) { Write-Host "  > $m" -ForegroundColor Magenta }
function Ok ($m) { Write-Host "  + $m" -ForegroundColor Green }
function Warn($m){ Write-Host "  ! $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  NeuroSploit installer (Windows)" -ForegroundColor Cyan

# arch → asset arch (only x64 prebuilt today; arm64 falls back to source)
$rawArch = $env:PROCESSOR_ARCHITECTURE
$arch = if ($rawArch -match 'ARM64') { "arm64" } else { "x64" }
Say "Platform: Windows / $arch"

$slug = "JoasASantos/NeuroSploit"
$dir  = if ($env:NEUROSPLOIT_DIR) { $env:NEUROSPLOIT_DIR } else { Join-Path $env:LOCALAPPDATA "NeuroSploit" }
$ref  = $env:NEUROSPLOIT_REF

# resolve latest release tag unless pinned
if (-not $ref) {
  try { $ref = (Invoke-RestMethod "https://api.github.com/repos/$slug/releases/latest").tag_name } catch { }
}
if (-not $ref) {
  # never invent a version: a checkout knows its own, otherwise fail
  $ct = Join-Path $PSScriptRoot "neurosploit-rs\Cargo.toml"
  if (Test-Path $ct) {
    $m = Select-String -Path $ct -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($m) { $ref = "v" + $m.Matches[0].Groups[1].Value }
  }
}
if (-not $ref) { throw "cannot determine the release tag; set NEUROSPLOIT_REF=vX.Y.Z" }
Say "Release: $ref"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
$installed = $false

# A mismatch ALWAYS throws. NEUROSPLOIT_INSECURE=1 exempts only a missing sums
# file (old tags), never altered bytes.
function Assert-Checksum {
  param([string]$Path, [string]$Name, [string]$SumsPath)
  if (-not (Test-Path $SumsPath)) {
    if ($env:NEUROSPLOIT_INSECURE -eq "1") {
      Write-Warning "SHA256SUMS missing for this release - continuing because NEUROSPLOIT_INSECURE=1"
      return
    }
    throw "SHA256SUMS missing; refusing to install unverified (set NEUROSPLOIT_INSECURE=1 only for old tags)"
  }
  $line = Get-Content $SumsPath | Where-Object { $_ -match "\s\*?$([regex]::Escape($Name))$" } | Select-Object -First 1
  if (-not $line) { throw "SHA256SUMS has no entry for $Name" }
  $expected = ($line -split '\s+')[0].ToLower()
  $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw "checksum mismatch for $Name" }
}

# ---- try the prebuilt asset (no Rust needed; x64 only) ----
if ($env:NEUROSPLOIT_BUILD -ne "1" -and $arch -eq "x64") {
  $asset = "neurosploit-$ref-windows-x64.zip"
  $url   = "https://github.com/$slug/releases/download/$ref/$asset"
  $tmp   = Join-Path $env:TEMP ("ns-dl-" + [guid]::NewGuid().ToString("N"))
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  try {
    Say "Downloading prebuilt binary: $asset"
    Invoke-WebRequest $url -OutFile (Join-Path $tmp "a.zip")
    try { Invoke-WebRequest "https://github.com/$slug/releases/download/$ref/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS") } catch { }
    Assert-Checksum -Path (Join-Path $tmp "a.zip") -Name $asset -SumsPath (Join-Path $tmp "SHA256SUMS")
    Expand-Archive -Path (Join-Path $tmp "a.zip") -DestinationPath $tmp -Force
    $exe = Get-ChildItem -Path $tmp -Recurse -Filter neurosploit.exe | Select-Object -First 1
    if (-not $exe) { throw "no neurosploit.exe in archive" }
    $srcdir = $exe.DirectoryName
    Copy-Item (Join-Path $srcdir "neurosploit.exe") (Join-Path $dir "neurosploit.exe") -Force
    Remove-Item -Recurse -Force (Join-Path $dir "agents_md") -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $srcdir "agents_md") (Join-Path $dir "agents_md") -Recurse -Force
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    $installed = $true
    Ok "Downloaded & unpacked -> $dir"
  } catch {
    Warn "Prebuilt download failed ($($_.Exception.Message)) — building from source."
  }
}

# ---- build from source (needs git + Rust) ----
if (-not $installed) {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is required to build from source (install Git for Windows)." }
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Say "Rust not found — installing rustup..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      winget install -e --id Rustlang.Rustup --accept-source-agreements --accept-package-agreements
    } else {
      $rdir = Join-Path $env:TEMP ("ns-rustup-" + [guid]::NewGuid().ToString("N"))
      New-Item -ItemType Directory -Force -Path $rdir | Out-Null
      $ri = Join-Path $rdir "rustup-init.exe"
      Invoke-WebRequest "https://win.rustup.rs/$rawArch" -OutFile $ri
      if ($env:NEUROSPLOIT_RUSTUP_SHA256) {
        $h = (Get-FileHash -Path $ri -Algorithm SHA256).Hash.ToLower()
        if ($h -ne $env:NEUROSPLOIT_RUSTUP_SHA256.ToLower()) { throw "rustup-init.exe failed checksum verification" }
      } else {
        Write-Warning "no pinned checksum for rustup-init.exe - set NEUROSPLOIT_RUSTUP_SHA256 to verify it"
      }
      & $ri -y --default-toolchain stable --profile minimal
    }
    $env:Path = "$HOME\.cargo\bin;$env:Path"
  }
  Ok ("Rust: " + (cargo --version))
  $src = Join-Path $dir "src"
  if (Test-Path (Join-Path $src ".git")) {
    Say "Updating $src..."; git -C $src fetch --depth 1 origin $ref; git -C $src checkout -q FETCH_HEAD
  } else {
    Say "Cloning to $src..."; git clone --depth 1 --branch $ref "https://github.com/$slug.git" $src
  }
  Say "Building release binary (first build downloads crates)..."
  Push-Location (Join-Path $src "neurosploit-rs"); cargo build --release; Pop-Location
  Copy-Item (Join-Path $src "neurosploit-rs\target\release\neurosploit.exe") (Join-Path $dir "neurosploit.exe") -Force
  Remove-Item -Recurse -Force (Join-Path $dir "agents_md") -ErrorAction SilentlyContinue
  Copy-Item (Join-Path $src "agents_md") (Join-Path $dir "agents_md") -Recurse -Force
  Ok "Built -> $dir"
}

$exePath = Join-Path $dir "neurosploit.exe"
if (-not (Test-Path $exePath)) { throw "install did not produce $exePath" }

# ---- set User PATH + NEUROSPLOIT_BASE (so it runs from any folder) ----
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$dir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
  Ok "Added $dir to your User PATH."
}
[Environment]::SetEnvironmentVariable("NEUROSPLOIT_BASE", $dir, "User")
Ok "Set NEUROSPLOIT_BASE=$dir (User)."
# make it work in THIS session too
$env:Path = "$dir;$env:Path"; $env:NEUROSPLOIT_BASE = $dir

Ok ("Version: " + (& $exePath --version))

# ---- dependencies: install what winget can (best-effort, never fatal) ----
if ($env:NEUROSPLOIT_NO_DEPS -ne "1") {
  Say "Checking dependencies..."
  $have = { param($c) [bool](Get-Command $c -ErrorAction SilentlyContinue) }
  $deps = @(
    @{ cmd = "node";  id = "OpenJS.NodeJS";       why = "web console" },
    @{ cmd = "nmap";  id = "Insecure.Nmap";       why = "recon (optional)" },
    @{ cmd = "git";   id = "Git.Git";             why = "source build / updates" }
  )
  foreach ($d in $deps) {
    if (& $have $d.cmd) { Ok ("{0} present" -f $d.cmd) }
    elseif (Get-Command winget -ErrorAction SilentlyContinue) {
      Say ("installing {0} ({1})..." -f $d.cmd, $d.why)
      try { winget install -e --id $d.id --accept-source-agreements --accept-package-agreements | Out-Null; Ok ("{0} installed" -f $d.cmd) }
      catch { Warn ("could not install {0} automatically — install it manually" -f $d.cmd) }
    } else { Warn ("{0} missing (winget unavailable) — install manually for: {1}" -f $d.cmd, $d.why) }
  }
  if (& $have cargo) {
    if (-not (& $have typst)) { Say "installing typst (cargo, PDF reports)..."; try { cargo install typst-cli | Out-Null; Ok "typst installed" } catch { Warn "typst optional — skipped" } }
  }
}

Write-Host ""
Ok "Installed. Open a NEW terminal, then from ANY folder:"
Write-Host "      neurosploit                 # interactive session"
Write-Host "      neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v"
Write-Host "      neurosploit --help"
Warn "Update later: just re-run this script."

# ---- optionally launch now (NEUROSPLOIT_RUN=1, or confirm when interactive) ----
$runNow = $env:NEUROSPLOIT_RUN
if (-not $runNow -and [Environment]::UserInteractive) {
  $ans = Read-Host "`n  Launch the interactive session now? [y/N]"
  if ($ans -match '^(y|yes)$') { $runNow = "1" }
}
if ($runNow -eq "1") { Say "Starting NeuroSploit..."; & $exePath }
