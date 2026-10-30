function Get-M365TenantAppPolicies {
    <#
    .SYNOPSIS
        Reads global Microsoft Entra ID / M365 tenant application protection and governance policies (Strict Read-Only).
    .DESCRIPTION
        Queries /v1.0/policies/authorizationPolicy, /beta/policies/authorizationPolicy,
        /v1.0/policies/adminConsentRequestPolicy, and /v1.0/policies/defaultAppManagementPolicy
        using either Microsoft.Graph SDK (Invoke-MgGraphRequest) or REST API (Invoke-RestMethod).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Reads multiple distinct Entra ID policy endpoints (Authorization, AdminConsent, AppManagement).')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'GraphSDK', 'REST')]
        [string]$ConnectionMethod = 'Auto',

        [Parameter(Mandatory = $false)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$DemoMode
    )

    if ($DemoMode) {
        $Demo = Get-AppGuardDemoData
        return $Demo.TenantPoliciesRaw
    }

    $TenantId   = 'Unknown-Tenant-Id'
    $TenantName = 'Microsoft Entra ID Tenant'
    $TenantDomain = ''
    try {
        $Org = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/organization' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
        if ($Org.Count -gt 0 -and $null -ne $Org[0]) {
            $OrgId   = [string](Get-ObjectPropertySafe -InputObject $Org[0] -PropertyName 'id')
            $OrgName = [string](Get-ObjectPropertySafe -InputObject $Org[0] -PropertyName 'displayName')
            $VerDoms = Get-ObjectPropertySafe -InputObject $Org[0] -PropertyName 'verifiedDomains'
            if ($null -ne $VerDoms) {
                $DefDom = @($VerDoms | Where-Object { (Get-ObjectPropertySafe -InputObject $_ -PropertyName 'isDefault') -eq $true }) | Select-Object -First 1
                if ($null -ne $DefDom) {
                    $TenantDomain = [string](Get-ObjectPropertySafe -InputObject $DefDom -PropertyName 'name')
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($OrgId))   { $TenantId   = $OrgId }
            if (-not [string]::IsNullOrWhiteSpace($OrgName)) {
                $TenantName = if (-not [string]::IsNullOrWhiteSpace($TenantDomain)) { "$OrgName ($TenantDomain)" } else { $OrgName }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($TenantDomain)) {
                $TenantName = $TenantDomain
            }
        }
    }
    catch {
        Write-Verbose "Could not query /v1.0/organization: $_"
    }

    if ($TenantName -eq 'Microsoft Entra ID Tenant') {
        try {
            $Doms = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/domains' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
            $DefDomObj = @($Doms | Where-Object { (Get-ObjectPropertySafe -InputObject $_ -PropertyName 'isDefault') -eq $true }) | Select-Object -First 1
            if ($null -ne $DefDomObj) {
                $DomId = [string](Get-ObjectPropertySafe -InputObject $DefDomObj -PropertyName 'id')
                if (-not [string]::IsNullOrWhiteSpace($DomId)) {
                    $TenantName = $DomId
                }
            }
        }
        catch {
            Write-Verbose "Could not query /v1.0/domains: $_"
        }
    }

    $Ctx = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -ne $Ctx) {
        if ($TenantId -eq 'Unknown-Tenant-Id' -and -not [string]::IsNullOrWhiteSpace($Ctx.TenantId)) {
            $TenantId = [string]$Ctx.TenantId
        }
        if ($TenantName -eq 'Microsoft Entra ID Tenant' -and -not [string]::IsNullOrWhiteSpace($Ctx.Account) -and $Ctx.Account -match '@(.+)$') {
            $TenantName = $Matches[1]
        }
    }

    # 1. Authorization Policy (query v1.0 primary, enrich with beta for allowUserConsentForRiskyApps)
    $AuthPolicy = $null
    try {
        $AuthResV1 = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/policies/authorizationPolicy' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
        if ($AuthResV1.Count -gt 0) { $AuthPolicy = $AuthResV1[0] }
    }
    catch {
        Write-Verbose "Could not query v1.0 authorizationPolicy: $_"
    }

    try {
        $AuthResBeta = @(Invoke-AppGuardGraphQuery -Uri '/beta/policies/authorizationPolicy' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
        if ($AuthResBeta.Count -gt 0 -and $null -ne $AuthResBeta[0]) {
            if ($null -eq $AuthPolicy) {
                $AuthPolicy = $AuthResBeta[0]
            }
            else {
                $BetaRisky = Get-ObjectPropertySafe -InputObject $AuthResBeta[0] -PropertyName 'allowUserConsentForRiskyApps'
                if ($null -ne $BetaRisky -and $null -eq (Get-ObjectPropertySafe -InputObject $AuthPolicy -PropertyName 'allowUserConsentForRiskyApps')) {
                    if ($AuthPolicy -is [System.Collections.IDictionary]) {
                        $AuthPolicy['allowUserConsentForRiskyApps'] = $BetaRisky
                    }
                    else {
                        $AuthPolicy | Add-Member -NotePropertyName 'allowUserConsentForRiskyApps' -NotePropertyValue $BetaRisky -Force
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not query beta authorizationPolicy: $_"
    }

    # 2. Admin Consent Request Policy
    $AdminConsentPolicy = $null
    try {
        $ConsentRes = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/policies/adminConsentRequestPolicy' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
        if ($ConsentRes.Count -gt 0) { $AdminConsentPolicy = $ConsentRes[0] }
    }
    catch {
        $AdminConsentPolicy = [PSCustomObject]@{
            isEnabled             = $false
            notifyReviewers       = $false
            remindersEnabled      = $false
            requestDurationInDays = 30
            reviewers             = @()
        }
    }

    # 3. Default App Management Policy (Password addition / lifetime restrictions on Apps & Service Principals)
    $AppMgmtPolicy = $null
    try {
        $MgmtRes = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/policies/defaultAppManagementPolicy' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
        if ($MgmtRes.Count -gt 0) { $AppMgmtPolicy = $MgmtRes[0] }
    }
    catch {
        try {
            $MgmtRes = @(Invoke-AppGuardGraphQuery -Uri '/beta/policies/defaultAppManagementPolicy' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
            if ($MgmtRes.Count -gt 0) { $AppMgmtPolicy = $MgmtRes[0] }
        }
        catch {
            $AppMgmtPolicy = [PSCustomObject]@{
                isEnabled                    = $false
                applicationRestrictions      = [PSCustomObject]@{ passwordCredentials = @(); keyCredentials = @() }
                servicePrincipalRestrictions = [PSCustomObject]@{ passwordCredentials = @(); keyCredentials = @() }
            }
        }
    }

    # 4. External Identity / Cross-Tenant Access Default Policy (B2B Collaboration & Inbound App Trust)
    $CrossTenantDefault = $null
    try {
        $CtRes = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/policies/crossTenantAccessPolicy/default' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
        if ($CtRes.Count -gt 0) { $CrossTenantDefault = $CtRes[0] }
    }
    catch {
        Write-Verbose "Could not query crossTenantAccessPolicy/default: $_"
    }

    # 5. Directory Audit Logs for Policy & Application Modifications (Last modified timestamp, UPN & Actor GUID)
    $DirectoryAudits = @()
    try {
        $AuditRes = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/auditLogs/directoryAudits?$top=200' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
        if ($AuditRes.Count -gt 0) { $DirectoryAudits = $AuditRes }
    }
    catch {
        Write-Verbose "Could not query /v1.0/auditLogs/directoryAudits (AuditLog.Read.All optional): $_"
    }

    return [PSCustomObject]@{
        TenantId                   = $TenantId
        TenantName                 = $TenantName
        AuthorizationPolicy        = $AuthPolicy
        AdminConsentRequestPolicy  = $AdminConsentPolicy
        DefaultAppManagementPolicy = $AppMgmtPolicy
        CrossTenantDefaultPolicy   = $CrossTenantDefault
        DirectoryAudits            = $DirectoryAudits
    }
}

