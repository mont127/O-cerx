@echo off
setlocal EnableExtensions

rem ==========================================================
rem  O-cerxz 2.0.2 (single .bat)
rem
rem  Key fix:
rem   - If firmware refuses bootsequence to a custom BOOTAPP GUID ("Element not found"),
rem     we fall back to setting bootsequence to the firmware's built-in "Boot Menu" entry
rem     (on many OEMs this opens the one-time boot menu on next reboot).
rem
rem  Other features:
rem   - ESP mounted to folder: %ProgramData%\Ocer\mnt\esp (no drive-letter collisions)
rem   - Optional keep ISO mounted (debug)
rem   - VMware detection (auto-disables bcdedit override)
rem   - Optional bcdedit firmware bootsequence (best-effort)
rem ==========================================================

title O-cerxz Prep 2.0.2

echo.
echo === O-cerxz 2.0.2 ===
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
echo.
pause
exit /b 0

__OCER_PS_BEGIN__
$ErrorActionPreference = 'Stop'

function Fail([string]$m){ Write-Host ('[!] ' + $m) -ForegroundColor Red; exit 1 }
function Info([string]$m){ Write-Host ('[*] ' + $m) }
function Ok([string]$m){ Write-Host ('[+] ' + $m) -ForegroundColor Green }
function Warn([string]$m){ Write-Host ('[!] ' + $m) -ForegroundColor Yellow }

function Detect-Vmware {
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    return ((($cs.Manufacturer + ' ' + $cs.Model)) -match 'VMware')
  } catch { return $false }
}

function Get-OsDiskNumber {
  $sys = $env:SystemDrive.TrimEnd(':')
  $p = Get-Partition -DriveLetter $sys -ErrorAction Stop
  return $p.DiskNumber
}

function Get-EspPartition {
  $espGuid = '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}'
  $osDisk = Get-OsDiskNumber
  $esp = Get-Partition -DiskNumber $osDisk | Where-Object { $_.GptType -eq $espGuid } | Select-Object -First 1
  if ($esp) { return $esp }
  return (Get-Partition | Where-Object { $_.GptType -eq $espGuid } | Select-Object -First 1)
}

function Mount-PartitionToFolder([Microsoft.Management.Infrastructure.CimInstance]$part, [string]$folder) {
  if (Test-Path -LiteralPath $folder) {
    try { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
  }
  New-Item -ItemType Directory -Force -Path $folder | Out-Null
  try {
    $all = Get-Partition -ErrorAction SilentlyContinue
    foreach ($p in $all) {
      try {
        $paths = $p | Get-PartitionAccessPath -ErrorAction SilentlyContinue
        if ($paths.AccessPath -contains $folder) {
          $p | Remove-PartitionAccessPath -AccessPath $folder -ErrorAction SilentlyContinue | Out-Null
        }
      } catch {}
    }
  } catch {}
  $part | Add-PartitionAccessPath -AccessPath $folder | Out-Null
}

function Unmount-PartitionFromFolder([Microsoft.Management.Infrastructure.CimInstance]$part, [string]$folder) {
  try { $part | Remove-PartitionAccessPath -AccessPath $folder -ErrorAction SilentlyContinue | Out-Null } catch {}
  try { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
}

function Get-FreeLetterAll {
  $used = New-Object System.Collections.Generic.HashSet[string]
  try { foreach ($d in [System.IO.DriveInfo]::GetDrives()) { $null = $used.Add($d.Name.Substring(0,1).ToUpper()) } } catch {}
  try { foreach ($pd in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) { $null = $used.Add($pd.Name.ToUpper()) } } catch {}
  $null = $used.Add('A'); $null = $used.Add('B')
  foreach ($l in @('Z','Y','X','W','V','U','T','S','R','Q','P','O')) { if (-not $used.Contains($l)) { return $l } }
  return $null
}

function Test-UefiEvidence {
  try {
    $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction Stop
    if ($p.PEFirmwareType) { return ($p.PEFirmwareType -eq 2) }
  } catch {}

  try {
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
      try { $null = Confirm-SecureBootUEFI -ErrorAction Stop; return $true } catch {
        if ($_.Exception.Message -match 'not supported on this platform') { return $false }
        return $true
      }
    }
  } catch {}

  try {
    $esp = Get-EspPartition
    if (-not $esp) { return $false }
    $mnt = Join-Path $env:ProgramData 'Ocer\mnt\uefi_probe'
    Mount-PartitionToFolder -part $esp -folder $mnt
    try { return (Test-Path -LiteralPath (Join-Path $mnt 'EFI\Microsoft\Boot\bootmgfw.efi')) }
    finally { Unmount-PartitionFromFolder -part $esp -folder $mnt }
  } catch { return $false }
}

$IsVmware = Detect-Vmware
if ($IsVmware) { Warn 'VMware detected. Auto-switch: firmware bootsequence override disabled.' }

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
$keepIso = (Read-Host 'DEBUG: Keep ISO mounted at end? YES/NO').ToUpper().Trim()
if (-not $keepIso) { $keepIso = 'NO' }

$tryBcd  = (Read-Host 'Try one-time bootsequence via bcdedit? YES/NO').ToUpper().Trim()
if (-not $tryBcd) { $tryBcd = 'NO' }
if ($IsVmware -and $tryBcd -eq 'YES') { Warn 'bcdedit bootsequence disabled on VMware (auto).'; $tryBcd = 'NO' }

Write-Host ''
Write-Host 'About to:'
Write-Host ' - Verify SHA256'
Write-Host ' - Mount ISO'
Write-Host ' - Copy EFI\BOOT to ESP\EFI\ocer\'
Write-Host ' - Copy ISO to C:\Ocer\images\ubuntu.iso'
if ($seedDir) { Write-Host ' - Copy seed to ESP\EFI\ocer\autoinstall\' }
if ($tryBcd -eq 'YES') { Write-Host ' - Try bcdedit firmware bootsequence (best-effort)' }
$confirm = Read-Host 'Type YES to continue'
if ($confirm.ToUpper().Trim() -ne 'YES') { Write-Host 'Cancelled.'; exit 0 }

Info 'Checking firmware mode (UEFI required)...'
if (-not (Test-UefiEvidence)) { Fail 'UEFI not detected (or no ESP found). This method requires UEFI + an EFI System Partition.' }
Ok 'UEFI evidence found.'

$arch = $env:PROCESSOR_ARCHITECTURE
$archWow = $env:PROCESSOR_ARCHITEW6432
$isArm = ($arch -match 'ARM' -or $archWow -match 'ARM')
$bootName = if ($isArm) { 'BOOTAA64.EFI' } else { 'BOOTX64.EFI' }
Info ("Detected Windows architecture: " + $(if($isArm){'ARM64'} else {'x64'}) + " (PROCESSOR_ARCHITECTURE=$arch)")

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
    } else { throw 'BITS not available' }
  } catch {
    Info 'BITS failed/unavailable; using Invoke-WebRequest...'
    Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -ErrorAction Stop
  }
  if (-not (Test-Path -LiteralPath $outFile)) { Fail 'Download did not produce an output file.' }
  $len = (Get-Item -LiteralPath $outFile).Length
  if ($len -lt 50MB) { Fail ("Downloaded file too small ($len bytes). Likely not an ISO.") }
  Ok 'Download completed.'
}

$mountedIsoPath = $null
$espMount = Join-Path $env:ProgramData 'Ocer\mnt\esp'
$espPart = $null

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
  $mountedIsoPath = $isoPath
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

  $espPart = Get-EspPartition
  if (-not $espPart) { Fail 'No ESP found. GPT+UEFI required.' }

  Info ("Mounting ESP to folder: $espMount")
  Mount-PartitionToFolder -part $espPart -folder $espMount

  $dstRoot = Join-Path $espMount 'EFI\ocer'
  $dstLogs = Join-Path $dstRoot 'logs'
  $dstAuto = Join-Path $dstRoot 'autoinstall'
  New-Item -ItemType Directory -Force -Path $dstRoot, $dstLogs | Out-Null

  Info ("Copying ISO EFI\BOOT\* -> $dstRoot")
  Copy-Item -Path (Join-Path $isoEfiBoot '*') -Destination $dstRoot -Recurse -Force

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
    # bcdedit needs a letter, so we temporarily assign one only for the bcdedit commands
    $letter = Get-FreeLetterAll
    if (-not $letter) {
      Warn 'No free drive letter available for bcdedit device=partition. Skipping bootsequence.'
    } else {
      $dl = ($letter + ':')
      Info ("Assigning temporary ESP drive letter for bcdedit: $dl")
      try {
        $espPart | Add-PartitionAccessPath -AccessPath $dl | Out-Null
        Info 'Attempting bcdedit firmware entry (best-effort)...'

        $createOut = & bcdedit /create /d "O-cer Installer" /application BOOTAPP 2>&1
        if ($LASTEXITCODE -ne 0) {
          Warn ("bcdedit create failed (non-fatal):`n" + ($createOut | Out-String))
        } else {
          $guid = ($createOut | Select-String -Pattern '{[0-9a-fA-F\-]+}' | Select-Object -First 1).Matches.Value
          if ($guid) {
            & bcdedit /set $guid device partition=$dl 2>&1 | Out-Null
            & bcdedit /set $guid path ("\\EFI\\ocer\\" + $bootName) 2>&1 | Out-Null

            $seqOut = & bcdedit /set '{fwbootmgr}' bootsequence $guid 2>&1
            if ($LASTEXITCODE -eq 0) {
              Ok 'One-time bootsequence set (if firmware honors it).'
            } else {
              Warn ("Setting bootsequence failed (non-fatal):`n" + ($seqOut | Out-String))

              # Fallback: set BootNext to firmware "Boot Menu" if present
              try {
                $fwTxt = (& bcdedit /enum firmware 2>&1 | Out-String)
                $rx = [regex]'identifier\s+({[0-9a-fA-F\-]+})\s*\r?\n\s*description\s+Boot Menu'
                $m = $rx.Match($fwTxt)
                if ($m.Success) {
                  $bootMenuGuid = $m.Groups[1].Value
                  Info ("Fallback: setting one-time bootsequence to firmware Boot Menu: $bootMenuGuid")
                  $bmOut = & bcdedit /set '{fwbootmgr}' bootsequence $bootMenuGuid 2>&1
                  if ($LASTEXITCODE -eq 0) { Ok 'Fallback set: next boot should open the firmware Boot Menu.' }
                  else { Warn ("Fallback Boot Menu bootsequence failed:`n" + ($bmOut | Out-String)) }
                } else {
                  Warn 'Fallback unavailable: firmware entry with description "Boot Menu" not found.'
                }
              } catch {
                Warn ("Fallback attempt failed: " + $_.Exception.Message)
              }
            }
          }
        }
      } catch {
        Warn ("bcdedit stage failed (non-fatal): " + $_.Exception.Message)
      } finally {
        try { $espPart | Remove-PartitionAccessPath -AccessPath $dl -ErrorAction SilentlyContinue | Out-Null } catch {}
      }
    }
  }

  Ok 'ESP staging completed.'
  Info ("ESP path: $dstRoot")
  Info ("ISO path: $isoOnDisk")

  if ($IsVmware) {
    Warn 'VMware note: Windows-mounting an ISO is NOT the same as attaching it to the VM CD/DVD device.'
    Warn 'If you want to boot the ISO in VMware, set the ISO in VM Settings -> CD/DVD -> Connect at power on.'
  } else {
    Info "Next: reboot and boot \\EFI\\ocer\\$bootName via firmware boot menu (or let firmware bootsequence / Boot Menu fallback work)."
  }

} finally {
  if ($espPart) {
    try { Unmount-PartitionFromFolder -part $espPart -folder $espMount } catch {}
  }
  if ($keepIso -ne 'YES' -and $mountedIsoPath) {
    try { Dismount-DiskImage -ImagePath $mountedIsoPath -ErrorAction SilentlyContinue | Out-Null } catch {}
  } else {
    if ($mountedIsoPath) { Info 'DEBUG: Leaving ISO mounted (as requested).' }
  }
  try { Stop-Transcript | Out-Null } catch {}
}
__OCER_PS_END__
