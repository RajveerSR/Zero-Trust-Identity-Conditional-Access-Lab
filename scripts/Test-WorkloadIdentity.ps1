[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ManagedIdentityClientId,

    [Parameter(Mandatory)]
    [string] $StorageAccountName,

    [Parameter(Mandatory)]
    [string] $EvidencePath
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) is required.'
}

$null = az login --identity --client-id $ManagedIdentityClientId --allow-no-subscriptions --output none
if ($LASTEXITCODE -ne 0) {
    throw 'Managed identity login failed. Run this only on an Azure host with the user-assigned identity attached.'
}

function Invoke-ContainerProbe {
    param([Parameter(Mandatory)][string] $ContainerName)

    $output = az storage blob list `
        --account-name $StorageAccountName `
        --container-name $ContainerName `
        --auth-mode login `
        --only-show-errors `
        --output json 2>&1
    $exitCode = $LASTEXITCODE
    [ordered]@{
        container = $ContainerName
        exitCode = $exitCode
        allowed = ($exitCode -eq 0)
        diagnostic = if ($exitCode -eq 0) { 'Blob list authorized.' } else { ($output | Out-String).Trim() }
    }
}

$allowed = Invoke-ContainerProbe -ContainerName 'allowed'
$denied = Invoke-ContainerProbe -ContainerName 'denied'
$result = [ordered]@{
    evidenceMetadata = [ordered]@{
        type = 'workload-identity-observation'
        capturedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        identityType = 'user-assigned-managed-identity'
        storageAccountName = $StorageAccountName
        expected = 'allowed succeeds; denied receives authorization failure'
        note = 'No token, account key, or credential is written.'
    }
    probes = @($allowed, $denied)
    passed = ($allowed.allowed -and -not $denied.allowed)
}

$parent = Split-Path -Parent $EvidencePath
if ($parent) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $EvidencePath -Encoding utf8

if (-not $result.passed) {
    Write-Error "Probe did not match the expected allow/deny result. Evidence: $EvidencePath"
    exit 1
}

Write-Host "PASS: allowed container was readable and denied container was rejected. Evidence: $EvidencePath"
