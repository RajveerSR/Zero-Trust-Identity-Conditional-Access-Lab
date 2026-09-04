[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Path
)

$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $Path),
    [ref] $null,
    [ref] $parseErrors
) | Out-Null

if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output "PowerShell syntax OK: $Path"
