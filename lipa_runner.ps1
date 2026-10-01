# lipa_runner.ps1
# Interactive GUI launcher for LIPA audit pipeline.
# Requires: PowerShell 5.1+, Windows Forms

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ------------------------------------------------------------------
# Paths — resolved relative to this script file
# ------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PythonExe = Join-Path $ScriptDir '.venv\Scripts\python.exe'
$CliScript  = Join-Path $ScriptDir 'src\lipa\cli.py'
$SrcDir     = Join-Path $ScriptDir 'src'

if (-not (Test-Path $PythonExe)) {
    Write-Host ''
    Write-Host '  [ERROR] .venv not found. Run: python -m venv .venv' -ForegroundColor Red
    Write-Host "  Expected: $PythonExe" -ForegroundColor Yellow
    Write-Host ''
    Read-Host '  Press Enter to exit'
    exit 3
}

# ------------------------------------------------------------------
# Helper
# ------------------------------------------------------------------
function Write-Rule {
    Write-Host ('  ' + ('-' * 60)) -ForegroundColor DarkCyan
}

# ------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------
Clear-Host
Write-Host ''
Write-Host '  +----------------------------------------------------------+' -ForegroundColor Cyan
Write-Host '  |   LIPA  --  Local Ingress Pre-flight Auditor             |' -ForegroundColor Cyan
Write-Host '  |   Zero-Execution AST Safety & Compatibility Gate         |' -ForegroundColor Cyan
Write-Host '  +----------------------------------------------------------+' -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------
# Load Windows Forms
# ------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms | Out-Null

# ------------------------------------------------------------------
# Step 1 -- Select Python file(s) to audit
# ------------------------------------------------------------------
Write-Host '  Step 1/3  Select Python file(s) to Audit' -ForegroundColor Yellow
Write-Host '  (Hold Ctrl to pick multiple files)' -ForegroundColor DarkGray
Write-Host ''

$fileDlg                  = New-Object System.Windows.Forms.OpenFileDialog
$fileDlg.Title            = 'LIPA - Select Python File(s) to Audit'
$fileDlg.Filter           = 'Python Files (*.py)|*.py|All Files (*.*)|*.*'
$fileDlg.Multiselect      = $true
$fileDlg.InitialDirectory = $ScriptDir

$dlgResult = $fileDlg.ShowDialog()
if ($dlgResult -ne [System.Windows.Forms.DialogResult]::OK -or $fileDlg.FileNames.Count -eq 0) {
    Write-Host '  Cancelled -- no file selected.' -ForegroundColor DarkGray
    Read-Host '  Press Enter to exit'
    exit 0
}
$selectedFiles = $fileDlg.FileNames

Write-Host '  Selected file(s):' -ForegroundColor Green
foreach ($f in $selectedFiles) {
    Write-Host "    $f" -ForegroundColor White
}
Write-Host ''

# ------------------------------------------------------------------
# Step 2 -- Select workspace root
# ------------------------------------------------------------------
Write-Host '  Step 2/3  Select Project Workspace Root (folder)' -ForegroundColor Yellow
Write-Host ''

$folderDlg                       = New-Object System.Windows.Forms.FolderBrowserDialog
$folderDlg.Description           = 'LIPA - Select Workspace Root (project root folder)'
$folderDlg.SelectedPath          = $ScriptDir
$folderDlg.ShowNewFolderButton   = $false

$dlgResult = $folderDlg.ShowDialog()
if ($dlgResult -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Host '  Cancelled -- no folder selected.' -ForegroundColor DarkGray
    Read-Host '  Press Enter to exit'
    exit 0
}
$workspaceRoot = $folderDlg.SelectedPath

Write-Host '  Workspace root:' -ForegroundColor Green
Write-Host "    $workspaceRoot" -ForegroundColor White
Write-Host ''

# ------------------------------------------------------------------
# Step 3 -- Optional baseline for contract diffing
# ------------------------------------------------------------------
Write-Host '  Step 3/3  Load Baseline for Contract Diff? [y/N]' -ForegroundColor Yellow
Write-Host '  (Skip with Enter to run without baseline)' -ForegroundColor DarkGray
Write-Host ''

$baselineFile   = $null
$baselineAnswer = Read-Host '  Load baseline'
if ($baselineAnswer -imatch '^y') {
    if ($selectedFiles.Count -gt 1) {
        Write-Host '  [WARN] Baseline applies to the first file only.' -ForegroundColor DarkYellow
    }
    $baseDlg                  = New-Object System.Windows.Forms.OpenFileDialog
    $baseDlg.Title            = 'LIPA - Select Baseline Python File'
    $baseDlg.Filter           = 'Python Files (*.py)|*.py|All Files (*.*)|*.*'
    $baseDlg.Multiselect      = $false
    $baseDlg.InitialDirectory = Split-Path $selectedFiles[0]

    $dlgResult = $baseDlg.ShowDialog()
    if ($dlgResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $baselineFile = $baseDlg.FileName
        Write-Host "  Baseline: $baselineFile" -ForegroundColor Green
    } else {
        Write-Host '  Skipped -- no baseline.' -ForegroundColor DarkGray
    }
}
Write-Host ''

# ------------------------------------------------------------------
# Version targets
# ------------------------------------------------------------------
Write-Rule
Write-Host '  Python version targets (default: 3.11 3.12 3.13 3.14 3.15)' -ForegroundColor DarkGray
Write-Host '  Type versions separated by commas, or press Enter for default:' -ForegroundColor DarkGray
Write-Host ''

$verInput = Read-Host '  Target versions'
$verFlags = [System.Collections.Generic.List[string]]::new()

if ($verInput -and $verInput.Trim() -ne '') {
    foreach ($v in ($verInput -split ',')) {
        $v = $v.Trim()
        if ($v -match '^\d+\.\d+$') {
            $verFlags.Add('--target-version')
            $verFlags.Add($v)
        }
    }
} else {
    foreach ($v in @('3.11','3.12','3.13','3.14','3.15')) {
        $verFlags.Add('--target-version')
        $verFlags.Add($v)
    }
}

Write-Host ''

# ------------------------------------------------------------------
# Build CLI argument list
# Run as: python -m lipa.cli <args>
# This resolves relative imports correctly without pip install.
# ------------------------------------------------------------------
$env:PYTHONPATH = $SrcDir

$cliArgs = [System.Collections.Generic.List[string]]::new()
$cliArgs.Add('-m')
$cliArgs.Add('lipa.cli')
foreach ($f in $selectedFiles) { $cliArgs.Add($f) }
$cliArgs.Add('--workspace')
$cliArgs.Add($workspaceRoot)
foreach ($flag in $verFlags) { $cliArgs.Add($flag) }

if ($baselineFile -and $selectedFiles.Count -eq 1) {
    $cliArgs.Add('--baseline')
    $cliArgs.Add($baselineFile)
}

# ------------------------------------------------------------------
# Run LIPA (human report to console)
# ------------------------------------------------------------------
Write-Rule
Write-Host ''
Write-Host '  Scanning ...' -ForegroundColor Cyan
Write-Host ''
Write-Rule

$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $PythonExe @cliArgs
$exitCode = $LASTEXITCODE
$sw.Stop()
$elapsedMs = [int]$sw.ElapsedMilliseconds

Write-Host ''
Write-Rule
Write-Host ''

# ------------------------------------------------------------------
# Verdict summary
# ------------------------------------------------------------------
switch ($exitCode) {
    0 {
        Write-Host '  [PASS]  All stages cleared -- safe to proceed.' -ForegroundColor Green
    }
    1 {
        Write-Host '  [BLOCKED]  Fatal issues detected -- fix before deploying.' -ForegroundColor Red
    }
    2 {
        Write-Host '  [WARN]  Warnings found -- review recommended.' -ForegroundColor Yellow
    }
    default {
        Write-Host "  [?]  Exit code: $exitCode" -ForegroundColor DarkGray
    }
}

Write-Host "  Time elapsed: ${elapsedMs} ms" -ForegroundColor DarkGray
Write-Host ''
Write-Rule
Write-Host ''

# ------------------------------------------------------------------
# Optional JSON report save
# ------------------------------------------------------------------
$saveAnswer = Read-Host '  Save JSON report? [y/N]'
if ($saveAnswer -imatch '^y') {
    $jsonArgs = [System.Collections.Generic.List[string]]::new($cliArgs.ToArray())
    $jsonArgs.Add('--json')

    $jsonLines  = & $PythonExe @jsonArgs 2>&1
    $jsonOutput = $jsonLines -join "`n"

    $saveDlg                  = New-Object System.Windows.Forms.SaveFileDialog
    $saveDlg.Title            = 'LIPA - Save JSON Report'
    $saveDlg.Filter           = 'JSON Report (*.json)|*.json|All Files (*.*)|*.*'
    $saveDlg.FileName         = ('lipa_report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.json')
    $saveDlg.InitialDirectory = $workspaceRoot

    $dlgResult = $saveDlg.ShowDialog()
    if ($dlgResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $noBomUtf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($saveDlg.FileName, $jsonOutput, $noBomUtf8)
        Write-Host "  Saved: $($saveDlg.FileName)" -ForegroundColor Green
    } else {
        Write-Host '  Skipped -- report not saved.' -ForegroundColor DarkGray
    }
    Write-Host ''
}

# ------------------------------------------------------------------
# Hold window
# ------------------------------------------------------------------
Write-Host '  Press Enter to close ...' -ForegroundColor DarkGray
$null = Read-Host
