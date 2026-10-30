function Get-ObjectPropertySafe {
    <#
    .SYNOPSIS
        Safely reads a property from a PSObject, PSCustomObject, or IDictionary (Hashtable) without throwing PropertyNotFoundException under Set-StrictMode -Version Latest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $false)]
        [object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($PropertyName)) {
            return $InputObject[$PropertyName]
        }
        return $DefaultValue
    }

    $PropMatch = $InputObject.PSObject.Properties.Match($PropertyName)
    if ($PropMatch.Count -gt 0) {
        return $PropMatch[0].Value
    }

    return $DefaultValue
}

