#requires -version 3

# Be sure to keep pid variable named the same as it is now otherwise the script
# will recognize pid as the own PS process, not good
[CmdletBinding()]
param(
  [string]$TargetExe = "infected.exe",

  # Detection
  [int]$PollMs = 2,

  # Freeze / slices
  [int]$DelayBeforeSuspendMs = 0,
  [int]$RunSliceMs = 2,
  [int]$RescanEveryMs = 0,
  [int]$RescanForSeconds = 30,
  [switch]$KeepSuspended,
  [switch]$OnceAfterRescans,

  # Follow children
  [switch]$FollowChildren,
  [int]$MaxChildDepth = 3,

  # PE-sieve config
  # Right now, I do not believe running two modes at the same time will work
  [int[]]$BaselineDumpModes = @(3),
  [int[]]$RescanDumpModes   = @(3),
  [ValidateSet("0","1","2","3","4","5")]
  [string]$PeImpMode = "3",
  [switch]$PeReflection = $true,
  [switch]$PeMiniDump   = $true,
  [string[]]$PeExtraArgs = @(),

  # Paths (relative to current working directory by default)
  [string]$OutRoot     = ".\dumps\pesieve",
  [string]$PeSievePath = ".\pe-sieve64.exe",

  # Logging
  [switch]$DebugMode
)

$ErrorActionPreference = "Stop"
$TargetExe       = [IO.Path]::GetFileName($TargetExe)
$TargetNameNoExt = [IO.Path]::GetFileNameWithoutExtension($TargetExe)

New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$tsFile = Get-Date -Format "yyyyMMdd_HHmmssfff"
$Script:LogPath = Join-Path $OutRoot ("monitor_{0}.log" -f $tsFile)

function LogLine {
  param(
    [string]$Message,
    [ValidateSet("INFO","DEBUG","WARN","ERROR","FATAL")] [string]$Level="INFO"
  )
  if ($Level -eq "DEBUG" -and -not $DebugMode) { return }

  $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
  $line = "{0} - [{1}] {2}" -f $ts,$Level,$Message

  Write-Host $line
  $line | Out-File -FilePath $Script:LogPath -Append -Encoding UTF8
}

# ---- Win32 / NT helpers ----
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Native {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

  [DllImport("ntdll.dll")]
  public static extern int NtSuspendProcess(IntPtr hProcess);

  [DllImport("ntdll.dll")]
  public static extern int NtResumeProcess(IntPtr hProcess);

  [DllImport("winmm.dll")]
  public static extern uint timeBeginPeriod(uint uPeriod);

  [DllImport("winmm.dll")]
  public static extern uint timeEndPeriod(uint uPeriod);
}
"@ -ErrorAction Stop

$PROCESS_ALL_ACCESS = 0x001F0FFF
$STILL_ACTIVE       = 259

function Enable-HighResTimer { try { [Native]::timeBeginPeriod(1) | Out-Null } catch {} }
function Disable-HighResTimer { try { [Native]::timeEndPeriod(1)   | Out-Null } catch {} }

function Open-ProcHandle([int]$TargetPid){
  $h = [Native]::OpenProcess($PROCESS_ALL_ACCESS, $false, $TargetPid)
  if ($h -eq [IntPtr]::Zero) { return [IntPtr]::Zero }
  return $h
}
function Is-AliveHandle([IntPtr]$h){
  if ($h -eq [IntPtr]::Zero) { return $false }
  $code = 0
  if (-not [Native]::GetExitCodeProcess($h, [ref]$code)) { return $false }
  return ($code -eq $STILL_ACTIVE)
}
function Suspend-Handle([IntPtr]$h){
  if ($h -eq [IntPtr]::Zero) { return $false }
  return ([Native]::NtSuspendProcess($h) -eq 0)
}
function Resume-Handle([IntPtr]$h){
  if ($h -eq [IntPtr]::Zero) { return $false }
  return ([Native]::NtResumeProcess($h) -eq 0)
}

function Wait-PreciseMs([int]$ms){
  if ($ms -le 0){ return }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt $ms) {
    [System.Threading.Thread]::Sleep(0)
  }
}

function ModeName([int]$dmode) {
  switch ($dmode) {
    1 { "dmode1_virtual" }
    3 { "dmode3_realigned" }
    2 { "dmode2_unmapped" }
    default { "dmode0_auto" }
  }
}

# --- child-process discovery (recursive, depth-limited) ---
function Get-ChildPids {
  param(
    [int]$RootPid,
    [int]$MaxDepth = 3,
    [int]$CurrentDepth = 0
  )

  if ($CurrentDepth -ge $MaxDepth) {
    return @()
  }

  try {
    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $RootPid" -ErrorAction Stop
  } catch {
    return @()
  }

  $result = @()
  foreach ($c in $children) {
    $cpid = [int]$c.ProcessId
    $result += $cpid
    $result += Get-ChildPids -RootPid $cpid -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
  }
  return $result
}

function RunPeSieve {
  param(
    [int]$TargetPid,
    [string]$OutDir,
    [int]$DumpMode,
    [string]$Tag
  )

  if (-not (Test-Path $PeSievePath)) {
    LogLine ("PE-sieve missing at {0}" -f $PeSievePath) "ERROR"
    return $false
  }

  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

  $args = @("/pid",$TargetPid,"/dir",$OutDir,"/dmode",$DumpMode)
  if ($PeImpMode -and $PeImpMode -ne "0") { $args += @("/imp",$PeImpMode) }
  if ($PeReflection) { $args += "/refl" }
  if ($PeMiniDump)   { $args += "/minidmp" }
  if ($PeExtraArgs -and $PeExtraArgs.Count -gt 0) { $args += $PeExtraArgs }

  $logFile = Join-Path $OutDir ("pe-sieve_{0}_{1}.log" -f $TargetPid,$Tag)
  try {
    $out = & $PeSievePath @args 2>&1 | Out-String
    $out | Set-Content -Path $logFile -Encoding UTF8
    if ($DebugMode) {
      LogLine ("PE-sieve ok pid={0} dmode={1} out={2}" -f $TargetPid,$DumpMode,$OutDir) "DEBUG"
    }
    return $true
  } catch {
    LogLine ("PE-sieve FAILED pid={0} dmode={1}: {2}" -f $TargetPid,$DumpMode,$_.Exception.Message) "WARN"
    return $false
  }
}

function RunPeSieveModes {
  param(
    [int]$TargetPid,
    [string]$ScanDir,
    [string]$TagPrefix,
    [int[]]$DumpModes
  )
  foreach ($m in $DumpModes) {
    $sub = Join-Path $ScanDir (ModeName $m)
    $tag = "{0}_{1}" -f $TagPrefix,(ModeName $m)
    RunPeSieve -TargetPid $TargetPid -OutDir $sub -DumpMode $m -Tag $tag | Out-Null
  }
}

function Capture-OnePid {
  param(
    [int]$TargetPid,
    [string]$ReasonTag
  )

  $stamp   = Get-Date -Format "yyyyMMdd_HHmmssfff"
  $baseDir = Join-Path $OutRoot ("process_{0}_{1}_{2}" -f $TargetPid,$ReasonTag,$stamp)
  New-Item -ItemType Directory -Force -Path $baseDir | Out-Null
  LogLine ("HIT pid={0} reason={1} baseDir={2}" -f $TargetPid,$ReasonTag,$baseDir) "INFO"

  $h = Open-ProcHandle $TargetPid
  if ($h -eq [IntPtr]::Zero) {
    LogLine ("Could not open pid={0} (already exited?)" -f $TargetPid) "WARN"
    return $false
  }

  # Track children we’ve already baseline scanned
  $childSeen = @{}

  try {
    if ($DelayBeforeSuspendMs -gt 0) { Wait-PreciseMs $DelayBeforeSuspendMs }

    if (-not (Suspend-Handle $h)) {
      LogLine ("Suspend failed pid={0}" -f $TargetPid) "WARN"
      return $false
    }

    if (-not (Is-AliveHandle $h)) {
      LogLine ("Capture aborted pid={0}: exited even after suspend attempt" -f $TargetPid) "WARN"
      return $false
    }

    # --- Initial children baseline, if requested ---
    if ($FollowChildren) {
      $initialChildren = Get-ChildPids -RootPid $TargetPid -MaxDepth $MaxChildDepth | Sort-Object -Unique
      foreach ($cpid in $initialChildren) {
        $childSeen[$cpid] = $true
        if (Get-Process -Id $cpid -ErrorAction SilentlyContinue) {
          $childFirst = Join-Path $baseDir ("child_{0}_first_seen" -f $cpid)
          LogLine ("Child first-seen baseline pid={0} dir={1}" -f $cpid,$childFirst) "INFO"
          RunPeSieveModes -TargetPid $cpid -ScanDir $childFirst -TagPrefix ("child_{0}_first_seen" -f $cpid) -DumpModes $RescanDumpModes
        }
      }
    }

    # Baseline scans for parent
    $scan0 = Join-Path $baseDir "scan_00_baseline"
    New-Item -ItemType Directory -Force -Path $scan0 | Out-Null
    RunPeSieveModes -TargetPid $TargetPid -ScanDir $scan0 -TagPrefix "00_baseline" -DumpModes $BaselineDumpModes

    # Rescan loop
    if (-not $KeepSuspended -and $RescanForSeconds -gt 0) {
      $end  = (Get-Date).AddSeconds($RescanForSeconds)
      $iter = 1
      while ((Get-Date) -lt $end) {
        Resume-Handle $h | Out-Null
        Wait-PreciseMs $RunSliceMs

        if (-not (Is-AliveHandle $h)) {
          LogLine ("Rescan loop stopping pid={0}: exited during run slice" -f $TargetPid) "INFO"
          break
        }

        Suspend-Handle $h | Out-Null
        if (-not (Is-AliveHandle $h)) {
          LogLine ("Rescan loop stopping pid={0}: exited right after suspend" -f $TargetPid) "INFO"
          break
        }

        # Parent rescan
        $scanDir = Join-Path $baseDir ("scan_{0:D2}_rescan" -f $iter)
        New-Item -ItemType Directory -Force -Path $scanDir | Out-Null
        RunPeSieveModes -TargetPid $TargetPid -ScanDir $scanDir -TagPrefix ("{0:D2}_rescan" -f $iter) -DumpModes $RescanDumpModes

        # Child rescans
        if ($FollowChildren) {
          $currentChildren = Get-ChildPids -RootPid $TargetPid -MaxDepth $MaxChildDepth | Sort-Object -Unique
          foreach ($cpid in $currentChildren) {
            if (-not (Get-Process -Id $cpid -ErrorAction SilentlyContinue)) {
              if ($childSeen.ContainsKey($cpid)) { $childSeen.Remove($cpid) }
              continue
            }

            # If brand-new child during rescan window, do a one time first_seen baseline
            if (-not $childSeen.ContainsKey($cpid)) {
              $childSeen[$cpid] = $true
              $childFirst = Join-Path $baseDir ("child_{0}_first_seen" -f $cpid)
              LogLine ("Child first-seen baseline pid={0} dir={1}" -f $cpid,$childFirst) "INFO"
              RunPeSieveModes -TargetPid $cpid -ScanDir $childFirst -TagPrefix ("child_{0}_first_seen" -f $cpid) -DumpModes $RescanDumpModes
            }

            $childScanDir = Join-Path $baseDir ("scan_{0:D2}_child_{1}" -f $iter,$cpid)
            RunPeSieveModes -TargetPid $cpid -ScanDir $childScanDir -TagPrefix ("{0:D2}_child_{1}" -f $iter,$cpid) -DumpModes $RescanDumpModes
          }
        }

        if ($RescanEveryMs -gt 0) { Wait-PreciseMs $RescanEveryMs }
        $iter++
      }
    }

    if (-not $KeepSuspended) { Resume-Handle $h | Out-Null }

    # ---- Log the most recently written DLL and its size in bytes ----
    $lastDll = Get-ChildItem -Path $baseDir -Recurse -File -Filter *.dll -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime |
               Select-Object -Last 1

    if ($lastDll) {
      LogLine ("Last DLL dump: Name={0} Size={1} bytes Path={2}" -f `
               $lastDll.Name, $lastDll.Length, $lastDll.FullName) "INFO"
    } else {
      LogLine "No DLL files found in capture directory (no .dll dumps?)" "WARN"
    }
    # ----------------------------------------------------------------------

    return $true
  }
  finally {
    if ($h -ne [IntPtr]::Zero) {
      [Native]::CloseHandle($h) | Out-Null
    }
  }
}


# -------------------- Main --------------------
Enable-HighResTimer
LogLine ("==== Start {0} target={1} ====" -f (Get-Date -Format "MM/dd/yyyy HH:mm:ss"), $TargetExe) "INFO"
LogLine ("OUTROOT={0}" -f $OutRoot) "INFO"
LogLine ("PESIEVE={0}" -f $PeSievePath) "INFO"
LogLine ("BaselineDModes={0} RescanDModes={1} Imp={2} Refl={3} MiniDmp={4}" -f ($BaselineDumpModes -join ","), ($RescanDumpModes -join ","), $PeImpMode, $PeReflection, $PeMiniDump) "INFO"
LogLine ("PollMs={0} RunSliceMs={1} RescanForSeconds={2} RescanEveryMs={3}" -f $PollMs,$RunSliceMs,$RescanForSeconds,$RescanEveryMs) "INFO"
LogLine ("FollowChildren={0} MaxChildDepth={1}" -f $FollowChildren,$MaxChildDepth) "INFO"
LogLine ("Log={0}" -f $Script:LogPath) "INFO"

try {
  while ($true) {
    $p = Get-Process -Name $TargetNameNoExt -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) {
      $targetPid = [int]$p.Id   # NOT $pid !
      $ok = Capture-OnePid -TargetPid $targetPid -ReasonTag "root_poll"
      if ($OnceAfterRescans) {
        LogLine ("OnceAfterRescans=True: stopping. captureOk={0}" -f $ok) "INFO"
        break
      }
    }
    Wait-PreciseMs $PollMs
  }
}
catch {
  LogLine ("FATAL: {0}" -f $_.Exception.Message) "FATAL"
}
finally {
  Disable-HighResTimer
  LogLine "Stopped." "INFO"
}
