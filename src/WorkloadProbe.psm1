function Get-WorkloadProbeFailureCategory {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Diagnostic
    )

    if ([string]::IsNullOrWhiteSpace($Diagnostic)) {
        return 'unknown'
    }

    if ($Diagnostic -match '(?i)ContainerNotFound|ResourceNotFound|specified container does not exist|status(?: code)?\s*[:=]?\s*404|\b404\b') {
        return 'missing-resource'
    }
    if ($Diagnostic -match '(?i)AADSTS|AuthenticationFailed|authentication required|failed to authenticate|credential|acquire.*token|login failed') {
        return 'authentication'
    }
    if ($Diagnostic -match '(?i)timed?\s*out|timeout|name resolution|could not resolve|DNS|connection (?:failed|refused|reset)|network is unreachable') {
        return 'network'
    }
    if ($Diagnostic -match '(?i)AuthorizationPermissionMismatch|AuthorizationFailure|not authorized to perform|request is not authorized|status(?: code)?\s*[:=]?\s*403|\b403\b') {
        return 'authorization'
    }
    return 'unknown'
}

Export-ModuleMember -Function Get-WorkloadProbeFailureCategory
