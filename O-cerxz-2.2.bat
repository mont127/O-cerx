@echo off
setlocal EnableExtensions

rem ==========================================================
rem  O-cerxz 2.2 (single .bat)
rem
rem  Goal: Stage a Linux ISO's UEFI boot files onto the internal ESP and
rem        optionally force the *next* reboot to boot the staged EFI app
rem        automatically (no USB).
rem
rem  What this DOES (Windows-side):
rem   - Verify UEFI (fail-closed)
rem   - Verify ISO SHA256 (required)
rem   - Mount ISO (native)
rem   - Stage EFI\BOOT\* to ESP\EFI\ocer\
rem   - Optional seed copy to ESP\EFI\ocer\autoinstall\
rem   - Optional autoboot strategies (user selects)
rem
rem  Autoboot strategies (best-effort):
rem   1) Firmware BootNext via bcdedit (safe, often blocked on OEM)
rem   2) Copy staged loader to default fallback path ESP\EFI\Boot\BOOT*.EFI (medium)
rem   3) TEMP swap Windows Boot Manager (ESP\EFI\Microsoft\Boot\bootmgfw.efi) (risky)
rem      + NEW in 2.2: also copy companion *.EFI into EFI\Microsoft\Boot
rem        so loaders that expect grub*.efi in that directory can find it.
rem   4) None (manual boot menu)
rem
rem  Restore mode:
rem   - Run: O-cerxz-2.2.bat /restore
rem   - Restores any backups created by strategy (2) or (3)
rem
rem  Notes:
rem   - Some firmwares ignore BootNext and do not provide "Boot from EFI file".
rem     In those cases, only (2) or (3) can be made automatic.
rem   - Strategy (3) requires Secure Boot OFF.
rem ==========================================================

title O-cerxz Prep 2.2

echo.
echo === O-cerxz 2.2 ===
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

powershell -NoProfile -ExecutionPolicy Bypass -File "%PSFILE%" -- %*
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

function Detect-Hypervisor {
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $s = (($cs.Manufacturer + ' ' + $cs.Model)).Trim()
    $u = $s.ToUpperInvariant()
    if ($u -match 'VMWARE') { return 'VMware' }
    if ($u -match 'VIRTUALBOX' -or $u -match 'INNOTEK') { return 'VirtualBox' }
    if ($u -match 'MICROSOFT CORPORATION' -and $u -match 'VIRTUAL') { return 'Hyper-V' }
    if ($u -match 'PARALLELS') { return 'Parallels' }
    if ($u -match 'QEMU' -or $u -match 'KVM') { return 'QEMU/KVM' }
    return $null
  } catch { return $null }
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

  # Detach any existing mount to this folder
  try {
    foreach ($p in (Get-Partition -ErrorAction SilentlyContinue)) {
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
  foreach ($l in @('Z','Y','X','W','V','U','T','S','R','Q','P','O')) {
    if (-not $used.Contains($l)) { return $l }
  }
  return $null
}

function Test-UefiEvidence {
  # 1) PEFirmwareType if present
  try {
    $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction Stop
    if ($p.PEFirmwareType) { return ($p.PEFirmwareType -eq 2) }
  } catch {}

  # 2) SecureBoot cmdlet behavior
  try {
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
      try { $null = Confirm-SecureBootUEFI -ErrorAction Stop; return $true } catch {
        if ($_.Exception.Message -match 'not supported on this platform') { return $false }
        return $true
      }
    }
  } catch {}

  # 3) ESP exists on OS disk and has Windows bootmgfw.efi
  try {
    $esp = Get-EspPartition
    if (-not $esp) { return $false }
    $mnt = Join-Path $env:ProgramData 'Ocer\mnt\uefi_probe'
    Mount-PartitionToFolder -part $esp -folder $mnt
    try {
      return (Test-Path -LiteralPath (Join-Path $mnt 'EFI\Microsoft\Boot\bootmgfw.efi'))
    } finally {
      Unmount-PartitionFromFolder -part $esp -folder $mnt
    }
  } catch { return $false }
}

function Test-SecureBootEnabled {
  try {
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
      return [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    }
  } catch {}
  return $false
}

function Read-Choice([string]$prompt, [string[]]$valid) {
  while ($true) {
    $v = (Read-Host $prompt).Trim()
    if ($valid -contains $v) { return $v }
    Write-Host ('  Valid: ' + ($valid -join ', '))
  }
}

function Mount-IsoAndGetDrive([string]$path) {
  Info 'Mounting ISO...'

  $img = Get-DiskImage -ImagePath $path -ErrorAction SilentlyContinue
  if ($img -and $img.Attached) {
    Info 'ISO already mounted; reusing existing attachment.'
  } else {
    $img = Mount-DiskImage -ImagePath $path -PassThru
  }

  $vol = $null
  for ($i=0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 300
    try { $vol = $img | Get-Volume -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { $vol = $null }
    if ($vol) { break }
  }
  if (-not $vol) { Fail 'Mounted ISO, but Windows did not expose a volume.' }

  if (-not $vol.DriveLetter) {
    $letter = Get-FreeLetterAll
    if (-not $letter) { Fail 'ISO has no drive letter and no free letters are available.' }
    Info ("Assigning drive letter $letter: to ISO volume...")
    try {
      $vol | Set-Volume -NewDriveLetter $letter -ErrorAction Stop | Out-Null
    } catch {
      Fail ('Failed to assign a drive letter to the ISO volume: ' + $_.Exception.Message)
    }
    $vol = $img | Get-Volume | Select-Object -First 1
  }

  $drive = ($vol.DriveLetter + ':\\')
  Info ("ISO mounted at $drive")
  return @{ Image = $img; Volume = $vol; Drive = $drive }
}

# ----------------------- Restore mode -----------------------
$argsList = @($args)
if ($argsList.Count -gt 0 -and $argsList[0].ToLowerInvariant() -eq '/restore') {
  Info 'Restore mode requested.'
  Info 'Checking UEFI + ESP...'
  if (-not (Test-UefiEvidence)) { Fail 'UEFI/ESP not detected. Cannot restore.' }

  $espPart = Get-EspPartition
  if (-not $espPart) { Fail 'ESP not found.' }
  $espMount = Join-Path $env:ProgramData 'Ocer\mnt\esp'
  Mount-PartitionToFolder -part $espPart -folder $espMount
  try {
    # Known fixed targets
    $targets = @(
      @{ Path = 'EFI\Boot\BOOTX64.EFI';   Bak = 'EFI\Boot\BOOTX64.EFI.ocer.bak' },
      @{ Path = 'EFI\Boot\BOOTAA64.EFI';  Bak = 'EFI\Boot\BOOTAA64.EFI.ocer.bak' },
      @{ Path = 'EFI\Microsoft\Boot\bootmgfw.efi'; Bak = 'EFI\Microsoft\Boot\bootmgfw.efi.ocer.bak' }
    )

    foreach ($t in $targets) {
      $p = Join-Path $espMount $t.Path
      $b = Join-Path $espMount $t.Bak
      if (Test-Path -LiteralPath $b) {
        Info ("Restoring $($t.Path) from backup...")
        Copy-Item -LiteralPath $b -Destination $p -Force
        Ok ("Restored: $($t.Path)")
      }
    }

    # Generic: restore any companion EFI backups created by strategy (3)
    $msBoot = Join-Path $espMount 'EFI\Microsoft\Boot'
    if (Test-Path -LiteralPath $msBoot) {
      Get-ChildItem -LiteralPath $msBoot -Filter '*.ocer.bak' -File -ErrorAction SilentlyContinue | ForEach-Object {
        $orig = $_.FullName.Substring(0, $_.FullName.Length - '.ocer.bak'.Length)
        Info ("Restoring companion: $([System.IO.Path]::GetFileName($orig))")
        Copy-Item -LiteralPath $_.FullName -Destination $orig -Force
      }
    }

    Ok 'Restore complete.'
    exit 0
  } finally {
    Unmount-PartitionFromFolder -part $espPart -folder $espMount
  }
}

# ----------------------- Interactive flow -----------------------
$hyper = Detect-Hypervisor
if ($hyper) { Warn ("Hypervisor detected: $hyper") }

Write-Host ''
Write-Host 'ISO input:'
Write-Host '  1) Local ISO path'
Write-Host '  2) Download ISO from URL'
$mode = Read-Choice 'Select 1 or 2' @('1','2')

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

Write-Host ''
Write-Host 'Autoboot strategy:'
Write-Host '  1) Try Firmware BootNext via bcdedit (safe; may be blocked)'
Write-Host '  2) Copy staged loader to ESP\EFI\Boot\BOOT*.EFI fallback (medium)'
Write-Host '  3) TEMP swap Windows Boot Manager (risky; Secure Boot must be OFF)'
Write-Host '  4) None (manual boot menu)'
$auto = Read-Choice 'Select 1/2/3/4' @('1','2','3','4')

if ($auto -eq '3' -and (Test-SecureBootEnabled)) {
  Fail 'Secure Boot appears enabled. Strategy (3) is blocked. Disable Secure Boot or use strategy 1/2/4.'
}

Write-Host ''
Write-Host 'About to:'
Write-Host ' - Verify UEFI + ESP'
Write-Host ' - Verify SHA256'
Write-Host ' - Mount ISO'
Write-Host ' - Stage ISO EFI\BOOT\* -> ESP\EFI\ocer\'
Write-Host ' - Copy ISO -> C:\Ocer\images\payload.iso'
if ($seedDir) { Write-Host ' - Copy seed -> ESP\EFI\ocer\autoinstall\' }
switch ($auto) {
  '1' { Write-Host ' - Autoboot: try bcdedit BootNext (best-effort)' }
  '2' { Write-Host ' - Autoboot: write fallback ESP\EFI\Boot\BOOT*.EFI (with backup)' }
  '3' { Write-Host ' - Autoboot: swap Windows bootmgfw.efi (with backup) [RISKY]'
         Write-Host '   + copy companion *.EFI into EFI\Microsoft\Boot'
         Write-Host '   To recover: run this script with /restore' }
  '4' { Write-Host ' - Autoboot: none' }
}
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
  $isoOnDisk = Join-Path $isoOutDir 'payload.iso'
  Info ("Copying ISO -> $isoOnDisk")
  Copy-Item -LiteralPath $isoPath -Destination $isoOnDisk -Force

  $mountedIsoPath = $isoPath
  $mount = Mount-IsoAndGetDrive -path $isoPath
  $img = $mount.Image
  $vol = $mount.Volume
  $isoDrive = $mount.Drive

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

  # ---------------- Autoboot strategies ----------------
  if ($auto -eq '1') {
    $letter = Get-FreeLetterAll
    if (-not $letter) {
      Warn 'No free drive letter available for bcdedit device=partition. Autoboot skipped.'
    } else {
      $dl = ($letter + ':')
      Info ("Assigning temporary ESP drive letter for bcdedit: $dl")
      try {
        $espPart | Add-PartitionAccessPath -AccessPath $dl | Out-Null
        Info 'Attempting bcdedit firmware entry + BootNext (best-effort)...'

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
              Ok 'BootNext set (if firmware honors it).'
            } else {
              Warn ("Setting BootNext failed (non-fatal):`n" + ($seqOut | Out-String))
              Warn 'If your firmware blocks BootNext, use strategy (2) or (3), or boot manually.'
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

  if ($auto -eq '2') {
    $fallbackDir = Join-Path $espMount 'EFI\Boot'
    New-Item -ItemType Directory -Force -Path $fallbackDir | Out-Null
    $fallback = Join-Path $fallbackDir $bootName
    $bak = $fallback + '.ocer.bak'

    Info ("Autoboot strategy (2): writing fallback " + $fallback)
    if (Test-Path -LiteralPath $fallback) {
      if (-not (Test-Path -LiteralPath $bak)) {
        Info ("Backing up existing fallback -> $bak")
        Copy-Item -LiteralPath $fallback -Destination $bak -Force
      } else {
        Info 'Backup already exists; leaving as-is.'
      }
    }

    Copy-Item -LiteralPath $dstBootEfi -Destination $fallback -Force
    Ok ("Fallback written: EFI\\Boot\\$bootName")
    Warn 'UEFI fallback behavior varies by vendor. If it still boots Windows, your firmware does not use fixed-disk fallback.'
  }

  if ($auto -eq '3') {
    # Swap Windows Boot Manager to force firmware to load our EFI.
    # Many loaders expect companion files (e.g. grubaa64.efi/grubx64.efi) in the SAME directory.
    # So we also copy staged *.EFI into EFI\Microsoft\Boot (without touching BCD/fonts/etc).

    $msBootDir = Join-Path $espMount 'EFI\Microsoft\Boot'
    $winBoot   = Join-Path $msBootDir 'bootmgfw.efi'
    $winBak    = $winBoot + '.ocer.bak'

    Info 'Autoboot strategy (3): TEMP swap Windows Boot Manager (RISKY)'
    if (-not (Test-Path -LiteralPath $winBoot)) { Fail 'Windows bootmgfw.efi not found on ESP. Cannot swap.' }

    if (-not (Test-Path -LiteralPath $winBak)) {
      Info ("Backing up Windows bootmgfw.efi -> $winBak")
      Copy-Item -LiteralPath $winBoot -Destination $winBak -Force
    } else {
      Warn 'Backup already exists (bootmgfw.efi.ocer.bak). Not overwriting it.'
    }

    New-Item -ItemType Directory -Force -Path $msBootDir | Out-Null

    # Copy companion EFI files
    try {
      $efiFiles = Get-ChildItem -LiteralPath $dstRoot -Filter '*.EFI' -File -ErrorAction SilentlyContinue
      foreach ($f in $efiFiles) {
        $dest = Join-Path $msBootDir $f.Name
        if (Test-Path -LiteralPath $dest) {
          $destBak = $dest + '.ocer.bak'
          if (-not (Test-Path -LiteralPath $destBak)) {
            Copy-Item -LiteralPath $dest -Destination $destBak -Force
          }
        }
        Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
      }
      Info 'Companion EFI files copied into EFI\Microsoft\Boot.'
    } catch {
      Warn ('Copying companion EFI files failed (may still boot): ' + $_.Exception.Message)
    }

    # Finally swap bootmgfw.efi itself
    Copy-Item -LiteralPath $dstBootEfi -Destination $winBoot -Force

    Ok 'Windows Boot Manager swapped for next boot.'
    Warn 'To restore: boot back into Windows and run: O-cerxz-2.2.bat /restore'
  }

  Ok 'ESP staging completed.'
  Info ("ESP path: $dstRoot")
  Info ("ISO path: $isoOnDisk")
  Info ("Next boot target: \\EFI\\ocer\\$bootName")

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
