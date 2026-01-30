@echo off
setlocal EnableExtensions

rem ==========================================================
rem  O-cer v1.7
rem
rem  Fix:
rem   - Some Windows 11 (notably VMware Fusion ARM VMs) do not expose
rem     HKLM\...\Control\PEFirmwareType.
rem   - v1.7 detects UEFI by *evidence*:
rem       1) Try PEFirmwareType (if present)
rem       2) Try Confirm-SecureBootUEFI (if available)
rem       3) Require an ESP (GPT EFI System Partition) to exist
rem          and contain EFI\Microsoft\Boot\bootmgfw.efi
rem
rem  Everything else unchanged.
rem ==========================================================

title O-cer Prep v1.7

echo.
echo === O-cer v1.7 ===
echo.

net session >nul 2>&1
if errorlevel 1 (
  echo [!] Run this as Administrator.
  pause
  exit /b 1
)

set "PSFILE=%TEMP%\ocer_%RANDOM%%RANDOM%.ps1"

for /f "tokens=1 delims=:" %%A in ('findstr /n /c:"__OCER_PS_BEGIN__" "%~f0"') do set "PSBEGIN=%%A"
for /f "tokens=1 delims=:" %%A in ('findstr /n /c:"__OCER_PS_END__" "%~f0"') do set "PSEND=%%A"

if not defined PSBEGIN (
  echo [!] Internal error: PS begin marker not found.
  pause
  exit /b 1
)
if not defined PSEND (
  echo [!] Internal error: PS end marker not found.
  pause
  exit /b 1
)

set /a PSBEGIN=PSBEGIN+1
set /a PSLEN=PSEND-PSBEGIN

powershell -NoProfile -ExecutionPolicy Bypass -Command "$c=Get-Content -LiteralPath '%~f0'; $b=%PSBEGIN%-1; $l=%PSLEN%; $c[$b..($b+$l-1)] | Set-Content -LiteralPath '%PSFILE%' -Encoding UTF8" 

if not exist "%PSFILE%" (
  echo [!] Failed to create temp PowerShell file.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PSFILE%"
set "RC=%ERRORLEVEL%"
del "%PSFILE%" >nul 2>&1

if not "%RC%"=="0" (
  echo.
  echo [!] O-cer failed. Logs: %ProgramData%\Ocer\logs\
  echo.
  pause
  exit /b %RC%
)

echo.
echo [+] Completed.
echo Next:
echo  - Reboot
echo  - Boot via firmware boot menu: \EFI\ocer\BOOTX64.EFI (x64) or \EFI\ocer\BOOTAA64.EFI (ARM64)
echo.
pause
exit /b 0

__OCER_PS_BEGIN__
$ErrorActionPreference = 'Stop'

function Fail([string]$m){ Write-Host ('[!] ' + $m) -ForegroundColor Red; exit 1 }
function Info([string]$m){ Write-Host ('[*] ' + $m) }
function Ok([string]$m){ Write-Host ('[+] ' + $m) -ForegroundColor Green }

function Test-UefiEvidence {
  # 1) Registry PEFirmwareType if present
  try {
    $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction Stop
    if ($p.PEFirmwareType) {
      return ($p.PEFirmwareType -eq 2)
    }
  } catch {}

  # 2) Confirm-SecureBootUEFI exists only on UEFI systems (but may error if Secure Boot off)
  try {
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
      # if this cmdlet exists and doesn't throw "not supported on this platform" we treat as UEFI
      try { $null = Confirm-SecureBootUEFI -ErrorAction Stop; return $true } catch {
        # Secure Boot disabled still indicates UEFI; distinguish from BIOS by message
        if ($_.Exception.Message -match 'not supported on this platform') { return $false }
        return $true
      }
    }
  } catch {}

  # 3) Evidence-based: find an ESP with Windows Boot Manager
  try {
    $espParts = Get-Partition | Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' }
    if (-not $espParts) { return $false }

    $used = (Get-Volume | Where-Object DriveLetter | Select-Object -ExpandProperty DriveLetter) + @('A','B')
    $letters = @('S','T','U','V','W','X','Y','Z') | Where-Object { $used -notcontains $_ }
    if (-not $letters) { return $false }
    $mount = ($letters[0] + ':')

    foreach ($p in $espParts) {
      try {
        $p | Add-PartitionAccessPath -AccessPath $mount | Out-Null
        if (Test-Path -LiteralPath (Join-Path ($mount + '\') 'EFI\Microsoft\Boot\bootmgfw.efi')) { return $true }
      } catch {
      } finally {
        try { $p | Remove-PartitionAccessPath -AccessPath $mount -ErrorAction SilentlyContinue | Out-Null } catch {}
      }
    }
  } catch {}

  return $false
}

Write-Host ''
Write-Host 'ISO input:'
Write-Host '  1) Local ISO path'
Write-Host '  2) Download ISO from URL'
$mode = Read-Host 'Select 1 or 2'

$isoPath = $null
$isoUrl  = $null

if ($mode -eq '2') {
  $isoUrl = Read-Host 'Enter ISO URL (direct .iso link)'
  if (-not $isoUrl) { Fail 'No URL provided.' }
} else {
  $isoPath = Read-Host 'Enter FULL path to ISO'
  if (-not $isoPath) { Fail 'No ISO path provided.' }
}

$expected = (Read-Host 'Paste expected SHA256 checksum (required)').ToLower().Trim()
if (-not $expected) { Fail 'SHA256 is required.' }

$seedDir = Read-Host 'Optional seed folder (blank to skip)'
$tryBcd  = (Read-Host 'Try one-time bootsequence via bcdedit? YES/NO').ToUpper().Trim()
if (-not $tryBcd) { $tryBcd = 'NO' }

Write-Host ''
Write-Host 'About to:'
Write-Host ' - Verify SHA256'
Write-Host ' - Mount ISO'
Write-Host ' - Copy EFI\BOOT to ESP:\EFI\ocer\'
Write-Host ' - Copy ISO to C:\Ocer\images\ubuntu.iso'
if ($seedDir) { Write-Host ' - Copy seed to ESP:\EFI\ocer\autoinstall\' }
if ($tryBcd -eq 'YES') { Write-Host ' - Try bcdedit bootsequence (best-effort)' }
$confirm = Read-Host 'Type YES to continue'
if ($confirm.ToUpper().Trim() -ne 'YES') { Write-Host 'Cancelled.'; exit 0 }

Info 'Checking firmware mode (UEFI required)...'
if (-not (Test-UefiEvidence)) { Fail 'UEFI not detected (or no ESP found). This method requires UEFI + an EFI System Partition.' }
Ok 'UEFI evidence found.'

# --- Detect Windows arch
$arch = $env:PROCESSOR_ARCHITECTURE
$archWow = $env:PROCESSOR_ARCHITEW6432
$isArm = ($arch -match 'ARM' -or $archWow -match 'ARM')
$bootName = if ($isArm) { 'BOOTAA64.EFI' } else { 'BOOTX64.EFI' }
Info ("Detected Windows architecture: " + $(if($isArm){'ARM64'} else {'x64'}) + " (PROCESSOR_ARCHITECTURE=$arch)")

# --- Logging
$base = Join-Path $env:ProgramData 'Ocer'
$logDir = Join-Path $base 'logs'
$dlDir  = Join-Path $base 'downloads'
New-Item -ItemType Directory -Force -Path $logDir, $dlDir | Out-Null
$logFile = Join-Path $logDir ("ocer-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
Start-Transcript -Path $logFile -Force | Out-Null

function Download-Iso([string]$url, [string]$outFile) {
  Info ("Downloading ISO -> $outFile")
  if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force }
  try {
    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
      Info 'Using BITS...'
      Start-BitsTransfer -Source $url -Destination $outFile -DisplayName 'O-cer ISO Download' -Description 'Downloading ISO' -ErrorAction Stop
    } else {
      throw 'BITS not available'
    }
  } catch {
    Info 'BITS failed/unavailable; using Invoke-WebRequest...'
    Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -ErrorAction Stop
  }
  if (-not (Test-Path -LiteralPath $outFile)) { Fail 'Download did not produce an output file.' }
  $len = (Get-Item -LiteralPath $outFile).Length
  if ($len -lt 50MB) { Fail ("Downloaded file too small ($len bytes). Likely not an ISO.") }
  Ok 'Download completed.'
}

try {
  if ($isoUrl) {
    if ($isoUrl -notmatch '^https?://') { Fail 'URL must start with http:// or https://' }
    $dlFile = Join-Path $dlDir 'download.iso'
    Download-Iso -url $isoUrl -outFile $dlFile
    $isoPath = $dlFile
  }

  if (-not (Test-Path -LiteralPath $isoPath)) { Fail "ISO not found: $isoPath" }

  Info 'Verifying ISO SHA256...'
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $isoPath).Hash.ToLower()
  if ($actual -ne $expected) { Fail ("SHA256 mismatch!`nExpected: $expected`nActual:   $actual") }
  Ok 'SHA256 verified.'

  $isoOutDir = 'C:\Ocer\images'
  New-Item -ItemType Directory -Force -Path $isoOutDir | Out-Null
  $isoOnDisk = Join-Path $isoOutDir 'ubuntu.iso'
  Info ("Copying ISO -> $isoOnDisk")
  Copy-Item -LiteralPath $isoPath -Destination $isoOnDisk -Force

  Info 'Mounting ISO...'
  $img = Mount-DiskImage -ImagePath $isoPath -PassThru
  Start-Sleep -Milliseconds 900
  $vol = $img | Get-Volume | Select-Object -First 1
  if (-not $vol -or -not $vol.DriveLetter) { Fail 'Failed to mount ISO or obtain drive letter.' }
  $isoDrive = ($vol.DriveLetter + ':\')
  Info ("ISO mounted at $isoDrive")

  $isoEfiBoot = Join-Path $isoDrive 'EFI\BOOT'
  if (-not (Test-Path $isoEfiBoot)) { Fail 'ISO missing EFI\BOOT directory.' }
  $isoBootEfi = Join-Path $isoEfiBoot $bootName
  if (-not (Test-Path $isoBootEfi)) {
    $found = (Get-ChildItem -Path $isoEfiBoot -Filter '*.EFI' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ', '
    Fail ("ISO not bootable for this architecture. Expected $bootName in EFI\BOOT. Found: $found")
  }

  # Locate ESP + mount
  $espParts = Get-Partition | Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' }
  if (-not $espParts) { Fail 'No ESP found. GPT+UEFI required.' }

  $used = (Get-Volume | Where-Object DriveLetter | Select-Object -ExpandProperty DriveLetter) + @('A','B')
  $letters = @('S','T','U','V','W','X','Y','Z') | Where-Object { $used -notcontains $_ }
  if (-not $letters) { Fail 'No free drive letter available to mount ESP.' }
  $espAccess = ($letters[0] + ':')

  $espPart = $espParts | Select-Object -First 1
  foreach ($p in $espParts) {
    try {
      $p | Add-PartitionAccessPath -AccessPath $espAccess | Out-Null
      if (Test-Path -LiteralPath (Join-Path ($espAccess + '\') 'EFI\Microsoft\Boot\bootmgfw.efi')) { $espPart = $p; break }
    } catch {
    } finally {
      try { $p | Remove-PartitionAccessPath -AccessPath $espAccess -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
  }

  $espPart | Add-PartitionAccessPath -AccessPath $espAccess | Out-Null
  try {
    $dstRoot = Join-Path ($espAccess + '\') 'EFI\ocer'
    $dstLogs = Join-Path $dstRoot 'logs'
    $dstAuto = Join-Path $dstRoot 'autoinstall'
    New-Item -ItemType Directory -Force -Path $dstRoot, $dstLogs | Out-Null

    Info ("Copying ISO EFI\BOOT\* -> $dstRoot")
    Copy-Item -Path (Join-Path $isoEfiBoot '*') -Destination $dstRoot -Recurse -Force

    $isoEfiUbuntu = Join-Path $isoDrive 'EFI\ubuntu'
    if (Test-Path $isoEfiUbuntu) {
      Info 'Copying ISO EFI\ubuntu -> ESP:\EFI\ocer\ubuntu'
      Copy-Item -Path $isoEfiUbuntu -Destination (Join-Path $dstRoot 'ubuntu') -Recurse -Force
    }

    if ($seedDir) {
      if (-not (Test-Path -LiteralPath $seedDir)) { Fail "Seed folder not found: $seedDir" }
      New-Item -ItemType Directory -Force -Path $dstAuto | Out-Null
      Info ("Copying seed -> $dstAuto")
      Copy-Item -Path (Join-Path $seedDir '*') -Destination $dstAuto -Recurse -Force
    }

    Copy-Item -LiteralPath $logFile -Destination $dstLogs -Force

    $dstBootEfi = Join-Path $dstRoot $bootName
    if (-not (Test-Path -LiteralPath $dstBootEfi)) { Fail "Expected staged EFI loader missing: $dstBootEfi" }
    Ok ("Staged EFI loader: $dstBootEfi")

    if ($tryBcd -eq 'YES') {
      Info 'Attempting bcdedit firmware entry (best-effort)...'
      $createOut = & bcdedit /create /d "O-cer Installer" /application BOOTAPP 2>&1
      if ($LASTEXITCODE -ne 0) {
        Info ("bcdedit create failed (non-fatal): `n" + ($createOut | Out-String))
      } else {
        $guid = ($createOut | Select-String -Pattern '{[0-9a-fA-F\-]+}' | Select-Object -First 1).Matches.Value
        if ($guid) {
          & bcdedit /set $guid device partition=$espAccess 2>&1 | Out-Null
          & bcdedit /set $guid path ("\\EFI\\ocer\\" + $bootName) 2>&1 | Out-Null
          $seqOut = & bcdedit /set '{fwbootmgr}' bootsequence $guid 2>&1
          if ($LASTEXITCODE -eq 0) { Ok 'One-time bootsequence set (if firmware honors it).' }
          else { Info ("Setting bootsequence failed (non-fatal): `n" + ($seqOut | Out-String)) }
        }
      }
    }

    Ok 'ESP staging completed.'
    Info ("ESP path: $dstRoot")
    Info ("ISO path: $isoOnDisk")

  } finally {
    try { $espPart | Remove-PartitionAccessPath -AccessPath $espAccess -ErrorAction SilentlyContinue | Out-Null } catch {}
  }

} finally {
  try { Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue | Out-Null } catch {}
  try { Stop-Transcript | Out-Null } catch {}
}
__OCER_PS_END__
