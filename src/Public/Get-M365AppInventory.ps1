function Get-M365AppInventory {
    <#
    .SYNOPSIS
        Reads all Enterprise Applications (Service Principals), App Registrations (Applications), API Permissions, Credentials, and Directory Roles (Strict Read-Only).
    .DESCRIPTION
        Combines Service Principals, App Registrations, OAuth2PermissionGrants, AppRoleAssignments, and Directory Role memberships into a unified object list for risk evaluation.
        Uses strict-mode safe property access and global O(1) appRoleAssignments batching instead of per-app N+1 queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'GraphSDK', 'REST')]
        [string]$ConnectionMethod = 'Auto',

        [Parameter(Mandatory = $false)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$ExcludeMicrosoftFirstParty,

        [Parameter(Mandatory = $false)]
        [switch]$DemoMode
    )

    if ($DemoMode) {
        $Demo = Get-AppGuardDemoData
        return $Demo.AppsRaw
    }

    # 1. Fetch Service Principals (Enterprise Applications)
    $SpSelect = 'id,appId,displayName,servicePrincipalType,signInAudience,accountEnabled,appRoleAssignmentRequired,publisherName,verifiedPublisher,createdDateTime,passwordCredentials,keyCredentials,appRoles,oauth2PermissionScopes,appOwnerOrganizationId'
    $ServicePrincipals = @(Invoke-AppGuardGraphQuery -Uri "/v1.0/servicePrincipals?`$select=$SpSelect&`$top=999" -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)

    # 2. Fetch App Registrations (Local Applications) to merge local credentials & owners
    $AppSelect = 'id,appId,displayName,signInAudience,publisherDomain,verifiedPublisher,createdDateTime,passwordCredentials,keyCredentials'
    $AppRegistrations = @(Invoke-AppGuardGraphQuery -Uri "/v1.0/applications?`$select=$AppSelect&`$top=999" -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
    $AppRegByAppId = @{}
    foreach ($AppReg in $AppRegistrations) {
        $RegAppId = Get-ObjectPropertySafe -InputObject $AppReg -PropertyName 'appId'
        if (-not [string]::IsNullOrWhiteSpace([string]$RegAppId)) {
            $AppRegByAppId[[string]$RegAppId] = $AppReg
        }
    }

    # Build lookup map for Resource ServicePrincipal Id -> AppRole definitions AND collect Resource SPs (like Microsoft Graph, Exchange, SPO)
    $SpById = @{}
    $AppRoleMap = @{}
    $ResourceSpIds = [System.Collections.Generic.List[string]]::new()

    foreach ($Sp in $ServicePrincipals) {
        $SpId   = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'id')
        $SpName = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'displayName')
        if ([string]::IsNullOrWhiteSpace($SpId)) { continue }

        $SpById[$SpId] = $Sp
        $SpAppRoles = Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'appRoles'
        if ($null -ne $SpAppRoles -and @($SpAppRoles).Count -gt 0) {
            $ResourceSpIds.Add($SpId)
            foreach ($Role in $SpAppRoles) {
                $RoleId    = [string](Get-ObjectPropertySafe -InputObject $Role -PropertyName 'id')
                $RoleValue = [string](Get-ObjectPropertySafe -InputObject $Role -PropertyName 'value')
                $RoleDisp  = [string](Get-ObjectPropertySafe -InputObject $Role -PropertyName 'displayName')
                if (-not [string]::IsNullOrWhiteSpace($RoleId)) {
                    $AppRoleMap["${SpId}:${RoleId}"] = [PSCustomObject]@{
                        Permission   = if (-not [string]::IsNullOrWhiteSpace($RoleValue)) { $RoleValue } else { $RoleDisp }
                        DisplayName  = $RoleDisp
                        ResourceName = $SpName
                    }
                }
            }
        }
    }

    # 3. Fetch all OAuth2PermissionGrants (Delegated permissions)
    $AllGrants = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/oauth2PermissionGrants?$top=999' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
    $GrantsByClientSpId = @{}
    foreach ($Grant in $AllGrants) {
        $ClientId    = [string](Get-ObjectPropertySafe -InputObject $Grant -PropertyName 'clientId')
        $GrantId     = [string](Get-ObjectPropertySafe -InputObject $Grant -PropertyName 'id')
        $ConsentType = [string](Get-ObjectPropertySafe -InputObject $Grant -PropertyName 'consentType')
        $ScopeVal    = [string](Get-ObjectPropertySafe -InputObject $Grant -PropertyName 'scope')
        if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
            if (-not $GrantsByClientSpId.ContainsKey($ClientId)) {
                $GrantsByClientSpId[$ClientId] = [System.Collections.Generic.List[object]]::new()
            }
            $GrantsByClientSpId[$ClientId].Add([PSCustomObject]@{
                Id          = $GrantId
                ConsentType = $ConsentType
                Scope       = $ScopeVal
            })
        }
    }

    # 4. Fetch Directory Roles and Memberships to see which Service Principals hold Admin Roles
    $DirectoryRoles = @(Invoke-AppGuardGraphQuery -Uri '/v1.0/directoryRoles?$expand=members' -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
    $RolesByPrincipalId = @{}
    foreach ($DirRole in $DirectoryRoles) {
        $DirRoleId   = [string](Get-ObjectPropertySafe -InputObject $DirRole -PropertyName 'id')
        $DirRoleTmpl = [string](Get-ObjectPropertySafe -InputObject $DirRole -PropertyName 'roleTemplateId')
        $DirRoleName = [string](Get-ObjectPropertySafe -InputObject $DirRole -PropertyName 'displayName')
        $Members     = Get-ObjectPropertySafe -InputObject $DirRole -PropertyName 'members'
        if ($null -ne $Members) {
            foreach ($Member in $Members) {
                $MemId = [string](Get-ObjectPropertySafe -InputObject $Member -PropertyName 'id')
                if (-not [string]::IsNullOrWhiteSpace($MemId)) {
                    if (-not $RolesByPrincipalId.ContainsKey($MemId)) {
                        $RolesByPrincipalId[$MemId] = [System.Collections.Generic.List[object]]::new()
                    }
                    $RolesByPrincipalId[$MemId].Add([PSCustomObject]@{
                        RoleId         = $DirRoleId
                        RoleTemplateId = $DirRoleTmpl
                        DisplayName    = $DirRoleName
                    })
                }
            }
        }
    }

    # 5. Fetch AppRoleAssignedTo on Resource Service Principals (e.g. Microsoft Graph, Exchange, SharePoint)
    #    Instead of querying /appRoleAssignments on all 500+ client apps (N+1), we query appRoleAssignedTo on the few Resource SPs
    #    that actually expose appRoles, mapping them by principalId (Client SP Id)!
    $AppRolesByClientSpId = @{}
    foreach ($ResSpId in $ResourceSpIds) {
        try {
            $AssignedToList = @(Invoke-AppGuardGraphQuery -Uri "/v1.0/servicePrincipals/$ResSpId/appRoleAssignedTo?`$top=999" -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken)
            foreach ($Assignment in $AssignedToList) {
                $PrincipalType = [string](Get-ObjectPropertySafe -InputObject $Assignment -PropertyName 'principalType')
                $PrincipalId   = [string](Get-ObjectPropertySafe -InputObject $Assignment -PropertyName 'principalId')
                $ResourceId    = [string](Get-ObjectPropertySafe -InputObject $Assignment -PropertyName 'resourceId' -DefaultValue $ResSpId)
                $AppRoleId     = [string](Get-ObjectPropertySafe -InputObject $Assignment -PropertyName 'appRoleId')
                $AssignId      = [string](Get-ObjectPropertySafe -InputObject $Assignment -PropertyName 'id')
                $ResDispName   = [string](Get-ObjectPropertySafe -InputObject $Assignment -PropertyName 'resourceDisplayName')

                if ($PrincipalType -eq 'ServicePrincipal' -and -not [string]::IsNullOrWhiteSpace($PrincipalId) -and $AppRoleId -ne '00000000-0000-0000-0000-000000000000') {
                    $LookupKey = "${ResourceId}:${AppRoleId}"
                    $PermValue = if ($AppRoleMap.ContainsKey($LookupKey)) { $AppRoleMap[$LookupKey].Permission } else { $AppRoleId }
                    if (-not [string]::IsNullOrWhiteSpace($PermValue)) {
                        if (-not $AppRolesByClientSpId.ContainsKey($PrincipalId)) {
                            $AppRolesByClientSpId[$PrincipalId] = [System.Collections.Generic.List[object]]::new()
                        }
                        $AppRolesByClientSpId[$PrincipalId].Add([PSCustomObject]@{
                            Id           = $AssignId
                            Permission   = $PermValue
                            ResourceName = $ResDispName
                        })
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve appRoleAssignedTo for resource $ResSpId : $_"
        }
    }

    $MicrosoftTenantIds = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
        '72f988bf-86f1-41af-91ab-2d7cd011db47'
    )

    $UnifiedInventory = [System.Collections.Generic.List[object]]::new()

    foreach ($Sp in $ServicePrincipals) {
        $SpId       = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'id')
        $SpAppId    = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'appId')
        $SpDispName = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'displayName' -DefaultValue 'Unnamed-ServicePrincipal')
        $SpType     = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'servicePrincipalType' -DefaultValue 'Application')
        $SpAudience = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'signInAudience' -DefaultValue 'AzureADMultipleOrgs')
        $SpEnabled  = [bool](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'accountEnabled' -DefaultValue $true)
        $SpAssignReq = [bool](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'appRoleAssignmentRequired' -DefaultValue $false)
        $SpPubName  = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'publisherName')
        $SpOwnerOrg = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'appOwnerOrganizationId')
        $SpCreated  = [string](Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'createdDateTime')

        $MicrosoftTenantIds = @(
            'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
            '72f988bf-86f1-41af-91ab-2d7cd011db47',
            '47df5bb7-e6bc-4256-afb0-dd8c8e3c1ce8'
        )
        $IsMicrosoftOwned = ($SpOwnerOrg -in $MicrosoftTenantIds) -or ($SpAppId -match '^000000') -or ($SpPubName -match '^Microsoft')

        if ($ExcludeMicrosoftFirstParty -and $IsMicrosoftOwned) {
            continue
        }

        $VerPubObj  = Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'verifiedPublisher'
        $VerPubDisp = if ($null -ne $VerPubObj) { [string](Get-ObjectPropertySafe -InputObject $VerPubObj -PropertyName 'displayName') } else { $null }
        $VerifiedPubName = if (-not [string]::IsNullOrWhiteSpace($VerPubDisp)) {
            $VerPubDisp
        }
        elseif ($IsMicrosoftOwned) {
            'Microsoft Corporation (First-Party)'
        }
        else {
            $null
        }
        if ([string]::IsNullOrWhiteSpace($SpPubName) -and $IsMicrosoftOwned) {
            $SpPubName = 'Microsoft Corporation'
        }

        $LinkedAppReg = if (-not [string]::IsNullOrWhiteSpace($SpAppId) -and $AppRegByAppId.ContainsKey($SpAppId)) {
            $AppRegByAppId[$SpAppId]
        }
        else {
            $null
        }
        $LinkedAppRegId = if ($null -ne $LinkedAppReg) { [string](Get-ObjectPropertySafe -InputObject $LinkedAppReg -PropertyName 'id') } else { $null }

        if ([string]::IsNullOrWhiteSpace($SpPubName) -and $null -ne $LinkedAppReg) {
            $SpPubName = [string](Get-ObjectPropertySafe -InputObject $LinkedAppReg -PropertyName 'publisherDomain')
        }

        # Combine PasswordCredentials & KeyCredentials from both ServicePrincipal and local App Registration
        $PwdList = [System.Collections.Generic.List[object]]::new()
        $SpPwdCreds = Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'passwordCredentials'
        if ($null -ne $SpPwdCreds) {
            foreach ($Cred in $SpPwdCreds) {
                $PwdList.Add([PSCustomObject]@{
                    KeyId         = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'keyId')
                    DisplayName   = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'displayName' -DefaultValue 'Unnamed-Secret')
                    StartDateTime = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'startDateTime')
                    EndDateTime   = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'endDateTime')
                    SourceObject  = 'ServicePrincipal'
                })
            }
        }
        if ($null -ne $LinkedAppReg) {
            $AppPwdCreds = Get-ObjectPropertySafe -InputObject $LinkedAppReg -PropertyName 'passwordCredentials'
            if ($null -ne $AppPwdCreds) {
                foreach ($Cred in $AppPwdCreds) {
                    $PwdList.Add([PSCustomObject]@{
                        KeyId         = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'keyId')
                        DisplayName   = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'displayName' -DefaultValue 'Unnamed-Secret')
                        StartDateTime = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'startDateTime')
                        EndDateTime   = [string](Get-ObjectPropertySafe -InputObject $Cred -PropertyName 'endDateTime')
                        SourceObject  = 'Application'
                    })
                }
            }
        }

        $KeyList = [System.Collections.Generic.List[object]]::new()
        $SpKeyCreds = Get-ObjectPropertySafe -InputObject $Sp -PropertyName 'keyCredentials'
        if ($null -ne $SpKeyCreds) {
            foreach ($Key in $SpKeyCreds) {
                $KeyList.Add([PSCustomObject]@{
                    KeyId         = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'keyId')
                    DisplayName   = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'displayName' -DefaultValue 'X509-Certificate')
                    StartDateTime = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'startDateTime')
                    EndDateTime   = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'endDateTime')
                    SourceObject  = 'ServicePrincipal'
                })
            }
        }
        if ($null -ne $LinkedAppReg) {
            $AppKeyCreds = Get-ObjectPropertySafe -InputObject $LinkedAppReg -PropertyName 'keyCredentials'
            if ($null -ne $AppKeyCreds) {
                foreach ($Key in $AppKeyCreds) {
                    $KeyList.Add([PSCustomObject]@{
                        KeyId         = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'keyId')
                        DisplayName   = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'displayName' -DefaultValue 'X509-Certificate')
                        StartDateTime = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'startDateTime')
                        EndDateTime   = [string](Get-ObjectPropertySafe -InputObject $Key -PropertyName 'endDateTime')
                        SourceObject  = 'Application'
                    })
                }
            }
        }

        $UnifiedInventory.Add([PSCustomObject]@{
            ObjectId                  = $SpId
            AppRegistrationObjectId   = $LinkedAppRegId
            AppId                     = $SpAppId
            DisplayName               = $SpDispName
            ServicePrincipalType      = $SpType
            SignInAudience            = $SpAudience
            AccountEnabled            = $SpEnabled
            AppRoleAssignmentRequired = $SpAssignReq
            PublisherName             = $SpPubName
            VerifiedPublisher         = $VerifiedPubName
            CreatedDateTime           = $SpCreated
            LastSignInDateTime        = $null
            Owners                    = @()
            DirectoryRoles            = if ($RolesByPrincipalId.ContainsKey($SpId)) { $RolesByPrincipalId[$SpId].ToArray() } else { @() }
            AppRoleAssignments        = if ($AppRolesByClientSpId.ContainsKey($SpId)) { $AppRolesByClientSpId[$SpId].ToArray() } else { @() }
            DelegatedGrants           = if ($GrantsByClientSpId.ContainsKey($SpId)) { $GrantsByClientSpId[$SpId].ToArray() } else { @() }
            PasswordCredentials       = $PwdList.ToArray()
            KeyCredentials            = $KeyList.ToArray()
        })
    }

    return $UnifiedInventory.ToArray()
}

