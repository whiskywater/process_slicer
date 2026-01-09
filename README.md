# process_slicer
A PowerShell wrapper script for PE-sieve and SysteminternalsSuite to freeze a target process in order to slice execution into time windows,  then runs PE-sieve during these slices to capture evolving in memory payloads.

REQUIREMENTS:

PE-sieve - https://github.com/hasherezade/pe-sieve
SysteminternalsSuite - https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

By default, process_slicer will assume that PE-sieve and SysteminternalsSuite are in the same working directory as itself.

Example usage command:

powershell -NoProfile -ExecutionPolicy Bypass -File .\process_slicer.ps1 `
  -TargetExe "infected.exe" `
  -PollMs 0.2 `
  -RunSliceMs 0.2 `
  -RescanForSeconds 800 `
  -BaselineDumpModes 3 `
  -RescanDumpModes 3 `
  -PeImpMode 3 -PeReflection -PeMiniDump `
  -FollowChildren `
  -OnceAfterRescans `
  -DebugMode

-TargetExe - This is your target you wish to run through process_slicer.

-PollMs - This is how frequent process_slicer checks for the target process to appear, measured in milliseconds.

-RunSliceMs - How long the target process is allowed to run between freezes per slice, measured in milliseconds.

-RescanForSeconds - Total duration of the rescan window, measured in seconds. Keep this value high for total process scan, low for storage capacity restraints.

-BaselineDumpModes & -RescanDumpModes - Maps directly to PE-sieve's /dmode parameter.
1 – dump virtual image (VIRTUAL)
2 – dump unmapped
3 – realigned dump (fixes section alignment, often best for RE)
0 – auto

-PeImpMode - Points to PE-sieve's /imp (import) argument.

-PeReflection - Toggle for PE-sieve's /refl flag.

-PeMiniDump - Toggle for PE-sieve's /minidmp flag.

-FollowChildren - Optional toggle that tells process_slicer to follow any child processes created by the parent process.

-OnceAfterRescans - Toggles the script to stop after the target process exits or dies.

-DebugMode - Verbosity flag. When enabled, the script logs detailed information about each slice, PE-sieve invocation, and child process discovery.
