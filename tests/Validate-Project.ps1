\
param(
    [string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'PasswordForge.ps1')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    throw "Source file not found: $ScriptPath"
}

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Error $_.Message }
    throw "PowerShell syntax validation failed with $($parseErrors.Count) error(s)."
}

$source = Get-Content -LiteralPath $ScriptPath -Raw
$required = @(
    'function Get-PasswordAnalysis',
    'function New-StrongPassword',
    'function New-Passphrase',
    'function Strengthen-Password',
    '$form.Text = "PasswordForge"',
    'Rate and Improve',
    'Generate 10 strong passwords',
    'Passwords are checked locally only'
)
foreach ($item in $required) {
    if (-not $source.Contains($item)) { throw "Required feature marker missing: $item" }
}

$networkPatterns = 'Invoke-WebRequest|Invoke-RestMethod|System\.Net\.WebClient|System\.Net\.Http\.HttpClient'
if ($source -match $networkPatterns) {
    throw 'Unexpected network-capable code was found in PasswordForge.ps1.'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Write-Host 'PasswordForge validation passed.'
