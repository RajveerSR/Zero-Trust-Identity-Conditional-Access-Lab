$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\WorkloadProbe.psm1') -Force

$cases = @(
    @{ Diagnostic = 'Status code: 403. AuthorizationPermissionMismatch. This request is not authorized.'; Expected = 'authorization' },
    @{ Diagnostic = 'ContainerNotFound: The specified container does not exist. Status code: 404.'; Expected = 'missing-resource' },
    @{ Diagnostic = 'AADSTS700016: Application was not found and authentication failed.'; Expected = 'authentication' },
    @{ Diagnostic = 'Could not resolve host: example.blob.core.windows.net'; Expected = 'network' },
    @{ Diagnostic = 'The operation timed out while connecting.'; Expected = 'network' },
    @{ Diagnostic = 'Unexpected CLI failure'; Expected = 'unknown' },
    @{ Diagnostic = ''; Expected = 'unknown' }
)

foreach ($case in $cases) {
    $actual = Get-WorkloadProbeFailureCategory -Diagnostic $case.Diagnostic
    if ($actual -ne $case.Expected) {
        throw "Expected '$($case.Expected)' but got '$actual' for '$($case.Diagnostic)'"
    }
}

Write-Output "Workload diagnostic classification: $($cases.Count) cases passed"
