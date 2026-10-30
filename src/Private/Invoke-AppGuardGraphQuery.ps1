function Invoke-AppGuardGraphQuery {
    <#
    .SYNOPSIS
        Executes a strict Read-Only GET query against Microsoft Graph using either the Microsoft.Graph SDK or direct REST API.
    .DESCRIPTION
        Supports both Invoke-MgGraphRequest (Graph SDK) and Invoke-RestMethod (REST with Bearer token), automatic pagination (@odata.nextLink),
        and enforces read-only HTTP GET operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'GraphSDK', 'REST')]
        [string]$ConnectionMethod = 'Auto',

        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )

    $FullUri = if ($Uri -match '^https://') {
        $Uri
    }
    else {
        $CleanRelative = $Uri.TrimStart('/')
        "https://graph.microsoft.com/$CleanRelative"
    }

    $Results = [System.Collections.Generic.List[object]]::new()
    $NextLink = $FullUri

    while (-not [string]::IsNullOrWhiteSpace($NextLink)) {
        $Response = $null

        if ($ConnectionMethod -eq 'REST' -or (-not [string]::IsNullOrWhiteSpace($AccessToken))) {
            if ([string]::IsNullOrWhiteSpace($AccessToken)) {
                throw "AccessToken is required when ConnectionMethod is set to 'REST' without an active Graph SDK session."
            }
            $Headers = @{
                'Authorization'    = "Bearer $AccessToken"
                'Content-Type'     = 'application/json'
                'ConsistencyLevel' = 'eventual'
            }
            $Response = Invoke-RestMethod -Method Get -Uri $NextLink -Headers $Headers -ErrorAction Stop
        }
        else {
            # Use Invoke-MgGraphRequest from Microsoft.Graph.Authentication
            $Response = Invoke-MgGraphRequest -Method GET -Uri $NextLink -OutputType PSObject -ErrorAction Stop
        }

        if ($null -ne $Response) {
            $ValArray = Get-ObjectPropertySafe -InputObject $Response -PropertyName 'value'
            if ($null -ne $ValArray -and ($ValArray -is [System.Collections.IEnumerable]) -and ($ValArray -isnot [string])) {
                foreach ($Item in $ValArray) {
                    $Results.Add($Item)
                }
            }
            else {
                $Results.Add($Response)
            }

            $NextVal = Get-ObjectPropertySafe -InputObject $Response -PropertyName '@odata.nextLink'
            if (-not [string]::IsNullOrWhiteSpace([string]$NextVal)) {
                $NextLink = [string]$NextVal
            }
            else {
                $NextLink = $null
            }
        }
        else {
            $NextLink = $null
        }
    }

    return $Results.ToArray()
}

