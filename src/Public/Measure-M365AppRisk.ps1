function Measure-M365AppRisk {
    <#
    .SYNOPSIS
        Evaluates all 10 Global Tenant App Protection Policies (T-01 to T-10) and every Enterprise Application / App Registration into Red, Orange, or Green risk levels, generating bilingual Lockdown Playbooks per row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$TenantPoliciesRaw,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$AppsRaw
    )

    $ModuleRoot = Split-Path -Path $PSScriptRoot -Parent
    $ProjectRoot = Split-Path -Path $ModuleRoot -Parent
    $ConfigPath  = Join-Path -Path $ProjectRoot -ChildPath 'config'

    $IocConfig  = Get-Content -Path (Join-Path $ConfigPath 'known-compromised-apps.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $PermConfig = Get-Content -Path (Join-Path $ConfigPath 'dangerous-permissions.json') -Raw -Encoding UTF8 | ConvertFrom-Json

    # Build fast lookup dictionaries
    $IocByAppId = @{}
    foreach ($Ioc in $IocConfig.compromisedApps) {
        $IocByAppId[$Ioc.appId.ToLowerInvariant()] = $Ioc
    }

    $EscalationMap = @{}
    foreach ($P in $PermConfig.escalationPermissions) {
        $EscalationMap[$P.value.ToLowerInvariant()] = $P
    }

    $HighDataMap = @{}
    foreach ($P in $PermConfig.highRiskDataPermissions) {
        $HighDataMap[$P.value.ToLowerInvariant()] = $P
    }

    $MedDataMap = @{}
    foreach ($P in $PermConfig.mediumRiskPermissions) {
        $MedDataMap[$P.value.ToLowerInvariant()] = $P
    }

    # =========================================================================
    # PART 1: EVALUATE 14 GLOBAL TENANT APP PROTECTION POLICIES (T-01 .. T-14)
    # =========================================================================
    $RealTenantId   = [string](Get-ObjectPropertySafe -InputObject $TenantPoliciesRaw -PropertyName 'TenantId' -DefaultValue 'Unknown-Tenant-Id')
    $RealTenantName = [string](Get-ObjectPropertySafe -InputObject $TenantPoliciesRaw -PropertyName 'TenantName' -DefaultValue 'Microsoft Entra ID Tenant')
    $AuthPol    = Get-ObjectPropertySafe -InputObject $TenantPoliciesRaw -PropertyName 'AuthorizationPolicy'
    $ConsentPol = Get-ObjectPropertySafe -InputObject $TenantPoliciesRaw -PropertyName 'AdminConsentRequestPolicy'
    $MgmtPol    = Get-ObjectPropertySafe -InputObject $TenantPoliciesRaw -PropertyName 'DefaultAppManagementPolicy'
    $AuditsRaw  = Get-ObjectPropertySafe -InputObject $TenantPoliciesRaw -PropertyName 'DirectoryAudits'
    $AuditList  = if ($null -ne $AuditsRaw) { @($AuditsRaw) } else { @() }

    # Parse Directory Audits to extract LastModifiedDateTime, LastModifiedByUpn, and LastModifiedByGuid per specific Policy ID (T-01..T-14) & Target ObjectId
    $PolicyAuditById    = @{}
    $PolicyAuditByGroup = @{}
    $AppAuditByTargetId = @{}

    foreach ($Aud in $AuditList) {
        $ActDisplay = [string](Get-ObjectPropertySafe -InputObject $Aud -PropertyName 'activityDisplayName')
        $ActTimeRaw = Get-ObjectPropertySafe -InputObject $Aud -PropertyName 'activityDateTime'
        $ActTimeStr = [string]$ActTimeRaw
        if ($ActTimeRaw -is [DateTime]) {
            $ActTimeStr = $ActTimeRaw.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
        }
        else {
            $ParsedAudTime = [DateTime]::MinValue
            if ([DateTime]::TryParse($ActTimeStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$ParsedAudTime)) {
                $ActTimeStr = $ParsedAudTime.ToString('yyyy-MM-dd HH:mm:ss UTC')
            }
        }

        $InitBy  = Get-ObjectPropertySafe -InputObject $Aud -PropertyName 'initiatedBy'
        $UsrObj  = Get-ObjectPropertySafe -InputObject $InitBy -PropertyName 'user'
        $AppActorObj = Get-ObjectPropertySafe -InputObject $InitBy -PropertyName 'app'

        $ActorUpn  = [string](Get-ObjectPropertySafe -InputObject $UsrObj -PropertyName 'userPrincipalName')
        $ActorGuid = [string](Get-ObjectPropertySafe -InputObject $UsrObj -PropertyName 'id')
        if ([string]::IsNullOrWhiteSpace($ActorUpn)) {
            $ActorUpn  = [string](Get-ObjectPropertySafe -InputObject $AppActorObj -PropertyName 'displayName')
            $ActorGuid = [string](Get-ObjectPropertySafe -InputObject $AppActorObj -PropertyName 'servicePrincipalId')
        }
        if ([string]::IsNullOrWhiteSpace($ActorUpn))  { $ActorUpn  = 'System / Admin' }
        if ([string]::IsNullOrWhiteSpace($ActorGuid)) { $ActorGuid = 'N/A' }

        # Inspect targetResources & modifiedProperties to map to the exact T-01..T-14 setting
        $ModPropNames = [System.Collections.Generic.List[string]]::new()
        $Targets = Get-ObjectPropertySafe -InputObject $Aud -PropertyName 'targetResources'
        if ($null -ne $Targets) {
            foreach ($Tgt in @($Targets)) {
                $ModProps = Get-ObjectPropertySafe -InputObject $Tgt -PropertyName 'modifiedProperties'
                if ($null -ne $ModProps) {
                    foreach ($Mp in @($ModProps)) {
                        $MpName = [string](Get-ObjectPropertySafe -InputObject $Mp -PropertyName 'displayName')
                        if (-not [string]::IsNullOrWhiteSpace($MpName)) {
                            $ModPropNames.Add($MpName)
                        }
                    }
                }
            }
        }
        $PropInfo = if ($ModPropNames.Count -gt 0) { " [$($ModPropNames -join ', ')]" } else { '' }

        $AuditRecord = [PSCustomObject]@{
            LastModifiedDateTime = $ActTimeStr
            LastModifiedByUpn    = $ActorUpn
            LastModifiedByGuid   = $ActorGuid
            ActivityName         = $ActDisplay
            BadgeDE              = "Zuletzt geändert am: $ActTimeStr – Von: $ActorUpn (GUID: $ActorGuid)$PropInfo"
            BadgeEN              = "Last modified: $ActTimeStr – By: $ActorUpn (GUID: $ActorGuid)$PropInfo"
        }

        if ($ActDisplay -match 'authorization policy') {
            $JoinedProps = ($ModPropNames -join ' ')
            if ($JoinedProps -match 'PermissionGrantPoliciesAssigned') {
                if (-not $PolicyAuditById.ContainsKey('T-01')) { $PolicyAuditById['T-01'] = $AuditRecord }
                if (-not $PolicyAuditById.ContainsKey('T-02')) { $PolicyAuditById['T-02'] = $AuditRecord }
            }
            if ($JoinedProps -match 'AllowedToCreateApps') {
                if (-not $PolicyAuditById.ContainsKey('T-03')) { $PolicyAuditById['T-03'] = $AuditRecord }
            }
            if ($JoinedProps -match 'AllowedToCreateSecurityGroups') {
                if (-not $PolicyAuditById.ContainsKey('T-04')) { $PolicyAuditById['T-04'] = $AuditRecord }
            }
            if ($JoinedProps -match 'AllowUserConsentForRiskyApps') {
                if (-not $PolicyAuditById.ContainsKey('T-05')) { $PolicyAuditById['T-05'] = $AuditRecord }
            }
            if ($JoinedProps -match 'AllowedToReadOtherUsers') {
                if (-not $PolicyAuditById.ContainsKey('T-11')) { $PolicyAuditById['T-11'] = $AuditRecord }
            }
            if ($JoinedProps -match 'AllowInvitesFrom') {
                if (-not $PolicyAuditById.ContainsKey('T-12')) { $PolicyAuditById['T-12'] = $AuditRecord }
            }
            if ($JoinedProps -match 'GuestUserRoleId') {
                if (-not $PolicyAuditById.ContainsKey('T-13')) { $PolicyAuditById['T-13'] = $AuditRecord }
            }
            if ($ModPropNames.Count -eq 0 -and -not $PolicyAuditByGroup.ContainsKey('AuthPolicy')) {
                $PolicyAuditByGroup['AuthPolicy'] = $AuditRecord
            }
        }
        elseif ($ActDisplay -match 'admin consent' -and -not $PolicyAuditById.ContainsKey('T-05')) {
            $PolicyAuditById['T-05'] = $AuditRecord
        }
        elseif ($ActDisplay -match 'app management' -and -not $PolicyAuditByGroup.ContainsKey('AppMgmtPolicy')) {
            $PolicyAuditByGroup['AppMgmtPolicy'] = $AuditRecord
        }
        elseif ($ActDisplay -match 'cross-tenant|crossTenant' -and -not $PolicyAuditById.ContainsKey('T-14')) {
            $PolicyAuditById['T-14'] = $AuditRecord
        }

        if ($null -ne $Targets) {
            foreach ($Tgt in @($Targets)) {
                $TgtId = [string](Get-ObjectPropertySafe -InputObject $Tgt -PropertyName 'id')
                if (-not [string]::IsNullOrWhiteSpace($TgtId)) {
                    $TgtKey = $TgtId.ToLowerInvariant()
                    if (-not $AppAuditByTargetId.ContainsKey($TgtKey)) {
                        $AppAuditByTargetId[$TgtKey] = $AuditRecord
                    }
                }
            }
        }
    }

    $DefUserRolePerms = Get-ObjectPropertySafe -InputObject $AuthPol -PropertyName 'defaultUserRolePermissions'
    $AssignedPoliciesRaw = Get-ObjectPropertySafe -InputObject $DefUserRolePerms -PropertyName 'permissionGrantPoliciesAssigned'
    $AssignedPolicies = if ($null -ne $AssignedPoliciesRaw) { @($AssignedPoliciesRaw) } else { @() }

    $TenantFindings = [System.Collections.Generic.List[object]]::new()

    # T-01: User Consent for Applications
    $UserConsentGrants = @($AssignedPolicies | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
    $T01Color = 'Green'
    $T01CurrDE = 'Deaktiviert (Kein User Consent erlaubt)'
    $T01CurrEN = 'Disabled (User consent not allowed)'
    if ($UserConsentGrants -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
        $T01Color = 'Red'
        $T01CurrDE = 'OFFEN: Benutzer dürfen ALLEN Apps zustimmen (microsoft-user-default-legacy)'
        $T01CurrEN = 'OPEN: Users can consent to ALL apps (microsoft-user-default-legacy)'
    }
    elseif ($UserConsentGrants.Count -gt 0) {
        $T01Color = 'Orange'
        $T01CurrDE = "Eingeschränkt erlaubt: $($UserConsentGrants -join ', ')"
        $T01CurrEN = "Restricted user consent enabled: $($UserConsentGrants -join ', ')"
    }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-01'
        Color          = $T01Color
        NameDE         = 'Benutzer-Zustimmung für Drittanbieter-Apps (User Consent)'
        NameEN         = 'User Consent for Third-Party Applications'
        CurrentDE      = $T01CurrDE
        CurrentEN      = $T01CurrEN
        RecommendedDE  = 'Benutzer-Zustimmung komplett deaktivieren (Leeres Array - nur Admin Consent)'
        RecommendedEN  = 'Disable user consent completely (Empty array - Admin consent only)'
        Compliance     = 'CIS M365 5.1.5.1 | NIS2 Art. 21(2)d | ISO 27001 A.5.15 | BSI CON.10'
        DetailDE       = 'Wenn Benutzer selbst Apps zustimmen dürfen, können Angreifer per OAuth Consent Phishing ohne Passwort/MFA dauerhaften Zugriff auf Postfächer und OneDrive erlangen.'
        DetailEN       = 'If users can consent to apps on their own, attackers can use OAuth Consent Phishing to gain persistent access to mailboxes and OneDrive without needing passwords or MFA.'
        LockdownSdk    = @(
            '# [T-01 LOCKDOWN] Deaktiviert User Consent für alle Drittanbieter-Apps (Microsoft.Graph SDK)',
            'Update-MgPolicyAuthorizationPolicy -BodyParameter @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-01 LOCKDOWN] Deaktiviert User Consent via Graph REST API',
            '$Body = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } } | ConvertTo-Json -Depth 4',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-02: Group Owner Consent for Applications accessing group data
    $GroupConsentGrants = @($AssignedPolicies | Where-Object { $_ -like 'ManagePermissionGrantsForOwnedResource.*' })
    $T02Color = if ($GroupConsentGrants.Count -gt 0) { 'Red' } else { 'Green' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-02'
        Color          = $T02Color
        NameDE         = 'Gruppenbesitzer-Zustimmung für Apps (Group Owner Consent)'
        NameEN         = 'Group Owner Consent for Apps Accessing Group Data'
        CurrentDE      = if ($T02Color -eq 'Red') { "AKTIV: Gruppenbesitzer dürfen Apps Zugriff auf Teams/SharePoint-Gruppen gewähren ($($GroupConsentGrants -join ', '))" } else { 'Deaktiviert (Kein Group Owner Consent)' }
        CurrentEN      = if ($T02Color -eq 'Red') { "ACTIVE: Group owners can grant apps access to Teams/SharePoint group data ($($GroupConsentGrants -join ', '))" } else { 'Disabled (No Group Owner Consent)' }
        RecommendedDE  = 'Gruppenbesitzer-Zustimmung deaktivieren'
        RecommendedEN  = 'Do not allow group owner consent'
        Compliance     = 'T-Minus 365 Hardening | DORA Art. 9(4) | ISO 27001 A.5.15'
        DetailDE       = 'Verhindert, dass Besitzer einzelner Microsoft 365 Gruppen / Teams eigenmächtig Drittanbieter-Apps Zugriff auf alle Gruppendateien und -Konversationen geben.'
        DetailEN       = 'Prevents owners of Microsoft 365 groups or Teams from autonomously granting third-party apps access to group files and conversations.'
        LockdownSdk    = @(
            '# [T-02 LOCKDOWN] Entfernt Group Owner Consent aus der Authorization Policy',
            '$Remaining = @((Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned | Where-Object { $_ -notlike "ManagePermissionGrantsForOwnedResource.*" })',
            'Update-MgPolicyAuthorizationPolicy -BodyParameter @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = $Remaining } } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-02 LOCKDOWN] Entfernt Group Owner Consent via Graph REST API',
            '$Pol = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"',
            '$Clean = @($Pol.defaultUserRolePermissions.permissionGrantPoliciesAssigned | Where-Object { $_ -notlike "ManagePermissionGrantsForOwnedResource.*" })',
            '$Body = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = $Clean } } | ConvertTo-Json -Depth 4',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-03: Users can register applications (allowedToCreateApps)
    $CanCreateApps = ((Get-ObjectPropertySafe -InputObject $DefUserRolePerms -PropertyName 'allowedToCreateApps') -eq $true)
    $T03Color = if ($CanCreateApps) { 'Red' } else { 'Green' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-03'
        Color          = $T03Color
        NameDE         = 'Standardbenutzer dürfen eigene App-Registrierungen erstellen (allowedToCreateApps)'
        NameEN         = 'Standard Users Can Register Applications (allowedToCreateApps)'
        CurrentDE      = if ($CanCreateApps) { 'ERLAUBT (allowedToCreateApps = true)' } else { 'Blockiert (allowedToCreateApps = false)' }
        CurrentEN      = if ($CanCreateApps) { 'ALLOWED (allowedToCreateApps = true)' } else { 'Blocked (allowedToCreateApps = false)' }
        RecommendedDE  = 'Deaktivieren (allowedToCreateApps = false; nur über Rolle Application Developer)'
        RecommendedEN  = 'Disable (allowedToCreateApps = false; restrict to Application Developer role)'
        Compliance     = 'CIS M365 5.1.2.1 | BSI ORP.4.A2 | ISO 27001 A.8.2'
        DetailDE       = 'Wenn jeder Standardbenutzer eigene App Registrations anlegen darf, kann ein kompromittiertes Benutzerkonto genutzt werden, um persistente App-Identitäten im Tenant zu registrieren.'
        DetailEN       = 'If standard users can register applications, a compromised user account can create persistent application identities and secrets inside the tenant.'
        LockdownSdk    = @(
            '# [T-03 LOCKDOWN] Verbietet Standardbenutzern das Erstellen eigener App Registrations',
            'Update-MgPolicyAuthorizationPolicy -BodyParameter @{ defaultUserRolePermissions = @{ allowedToCreateApps = $false } } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-03 LOCKDOWN] Setzt allowedToCreateApps = false via Graph REST API',
            '$Body = @{ defaultUserRolePermissions = @{ allowedToCreateApps = $false } } | ConvertTo-Json -Depth 4',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-04: Allow user consent for risky apps
    $RiskyConsent = ((Get-ObjectPropertySafe -InputObject $AuthPol -PropertyName 'allowUserConsentForRiskyApps') -eq $true)
    $T04Color = if ($RiskyConsent) { 'Red' } else { 'Green' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-04'
        Color          = $T04Color
        NameDE         = 'Benutzer-Zustimmung bei erkannten Risiko-Apps (allowUserConsentForRiskyApps)'
        NameEN         = 'Allow User Consent for Risky Apps (allowUserConsentForRiskyApps)'
        CurrentDE      = if ($RiskyConsent) { 'ERLAUBT (allowUserConsentForRiskyApps = true)' } else { 'Blockiert (false / geschützt)' }
        CurrentEN      = if ($RiskyConsent) { 'ALLOWED (allowUserConsentForRiskyApps = true)' } else { 'Blocked (false / protected)' }
        RecommendedDE  = 'Blockieren (allowUserConsentForRiskyApps = false)'
        RecommendedEN  = 'Block (allowUserConsentForRiskyApps = false)'
        Compliance     = 'NIS2 Art. 21(2)d | Microsoft Entra ID Protection'
        DetailDE       = 'Stellt sicher, dass Microsofts Risikoerkennung verdächtige OAuth-Consent-Anfragen automatisch blockiert.'
        DetailEN       = 'Ensures Microsoft risk detection automatically blocks suspicious OAuth consent requests.'
        LockdownSdk    = @(
            '# [T-04 LOCKDOWN] Deaktiviert User Consent für Risiko-Apps',
            'Update-MgPolicyAuthorizationPolicy -BodyParameter @{ allowUserConsentForRiskyApps = $false } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-04 LOCKDOWN] Deaktiviert allowUserConsentForRiskyApps via Graph REST API (/beta)',
            '$Body = @{ allowUserConsentForRiskyApps = $false } | ConvertTo-Json',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-05: Admin Consent Workflow (adminConsentRequestPolicy)
    $WorkflowEnabled = ((Get-ObjectPropertySafe -InputObject $ConsentPol -PropertyName 'isEnabled') -eq $true)
    $ReviewersList   = Get-ObjectPropertySafe -InputObject $ConsentPol -PropertyName 'reviewers'
    $NotifyRev       = ((Get-ObjectPropertySafe -InputObject $ConsentPol -PropertyName 'notifyReviewers') -eq $true)
    $HasReviewers    = ($WorkflowEnabled -and $null -ne $ReviewersList -and @($ReviewersList).Count -gt 0)
    $T05Color = if (-not $WorkflowEnabled) { 'Red' } elseif (-not $HasReviewers -or -not $NotifyRev) { 'Orange' } else { 'Green' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-05'
        Color          = $T05Color
        NameDE         = 'Admin Consent Workflow für App-Anfragen (adminConsentRequestPolicy)'
        NameEN         = 'Admin Consent Workflow for App Requests (adminConsentRequestPolicy)'
        CurrentDE      = if ($T05Color -eq 'Red') { 'DEAKTIVIERT (isEnabled = false)' } elseif ($T05Color -eq 'Orange') { 'Aktiviert, aber keine Reviewer / E-Mail-Alarme hinterlegt' } else { 'Aktiviert inkl. Reviewer & Benachrichtigung' }
        CurrentEN      = if ($T05Color -eq 'Red') { 'DISABLED (isEnabled = false)' } elseif ($T05Color -eq 'Orange') { 'Enabled, but missing reviewers or email notifications' } else { 'Enabled with reviewers and notifications' }
        RecommendedDE  = 'Aktivieren (isEnabled = true) mit definierten Security-Reviewern'
        RecommendedEN  = 'Enable (isEnabled = true) with designated security reviewers'
        Compliance     = 'CIS M365 5.1.5.2 | DORA Art. 28 | ISO 27001 A.5.19'
        DetailDE       = 'Erzwingt einen strukturierten Prüfungs- und Freigabeprozess durch das Security-Team, bevor neue Drittanbieter-Apps im Tenant zugelassen werden.'
        DetailEN       = 'Enforces a structured security review and approval workflow before new third-party applications are permitted in the tenant.'
        LockdownSdk    = @(
            '# [T-05 LOCKDOWN] Aktiviert den Admin Consent Workflow im Tenant',
            'Update-MgPolicyAdminConsentRequestPolicy -BodyParameter @{ isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 14 } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-05 LOCKDOWN] Aktiviert den Admin Consent Workflow via Graph REST API',
            '$Body = @{ isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 14 } | ConvertTo-Json',
            'Invoke-MgGraphRequest -Method PUT -Uri "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-06: Default App Management Policy (Global Switch isEnabled)
    $AppMgmtEnabled = ((Get-ObjectPropertySafe -InputObject $MgmtPol -PropertyName 'isEnabled') -eq $true)
    $T06Color = if ($AppMgmtEnabled) { 'Green' } else { 'Red' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-06'
        Color          = $T06Color
        NameDE         = 'Tenant App-Management-Richtlinie aktiv (defaultAppManagementPolicy)'
        NameEN         = 'Tenant App Management Policy Enabled (defaultAppManagementPolicy)'
        CurrentDE      = if ($AppMgmtEnabled) { 'Aktiviert (isEnabled = true)' } else { 'DEAKTIVIERT (isEnabled = false) - Keine Passwort-Sperren für Apps aktiv!' }
        CurrentEN      = if ($AppMgmtEnabled) { 'Enabled (isEnabled = true)' } else { 'DISABLED (isEnabled = false) - No app password restrictions active!' }
        RecommendedDE  = 'Aktivieren (isEnabled = true)'
        RecommendedEN  = 'Enable (isEnabled = true)'
        Compliance     = 'NIS2 Art. 21(2)j | ISO 27001 A.5.17 | CloudCapsule Lockdown Guide'
        DetailDE       = 'Die defaultAppManagementPolicy steuert tenantweit, ob Apps und Service Principals Passwörter (Client Secrets) hinzufügen dürfen und wie lange diese gültig sein dürfen.'
        DetailEN       = 'The defaultAppManagementPolicy controls tenant-wide whether apps and service principals are allowed to add passwords (client secrets) and their maximum lifetimes.'
        LockdownSdk    = @(
            '# [T-06 LOCKDOWN] Aktiviert die globale Tenant App Management Policy',
            'Update-MgPolicyDefaultAppManagementPolicy -BodyParameter @{ isEnabled = $true } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-06 LOCKDOWN] Aktiviert defaultAppManagementPolicy via Graph REST API',
            '$Body = @{ isEnabled = $true } | ConvertTo-Json',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # Helper to inspect passwordCredentials / keyCredentials restrictions
    $AppRestrObj = Get-ObjectPropertySafe -InputObject $MgmtPol -PropertyName 'applicationRestrictions'
    $SpRestrObj  = Get-ObjectPropertySafe -InputObject $MgmtPol -PropertyName 'servicePrincipalRestrictions'
    $AppPwdRaw   = Get-ObjectPropertySafe -InputObject $AppRestrObj -PropertyName 'passwordCredentials'
    $AppKeyRaw   = Get-ObjectPropertySafe -InputObject $AppRestrObj -PropertyName 'keyCredentials'
    $SpPwdRaw    = Get-ObjectPropertySafe -InputObject $SpRestrObj  -PropertyName 'passwordCredentials'

    $AppPwdRestrictions = if ($null -ne $AppPwdRaw) { @($AppPwdRaw) } else { @() }
    $AppKeyRestrictions = if ($null -ne $AppKeyRaw) { @($AppKeyRaw) } else { @() }
    $SpPwdRestrictions  = if ($null -ne $SpPwdRaw)  { @($SpPwdRaw) }  else { @() }

    # T-07: App Registration can add Password (Client Secret) -> passwordAddition restriction
    $AppPwdAddRule = $AppPwdRestrictions | Where-Object { (Get-ObjectPropertySafe -InputObject $_ -PropertyName 'restrictionType') -eq 'passwordAddition' } | Select-Object -First 1
    $AppPwdAddBlocked = ($AppMgmtEnabled -and $null -ne $AppPwdAddRule -and (Get-ObjectPropertySafe -InputObject $AppPwdAddRule -PropertyName 'state') -eq 'enabled')
    $T07Color = if ($AppPwdAddBlocked) { 'Green' } elseif ($AppMgmtEnabled) { 'Orange' } else { 'Red' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-07'
        Color          = $T07Color
        NameDE         = 'App-Registrierung kann Passwort (Client Secret) hinzufügen (passwordAddition)'
        NameEN         = 'App Registration Can Add Password / Client Secret (passwordAddition)'
        CurrentDE      = if ($AppPwdAddBlocked) { 'Blockiert (Nur Zertifikate / Federated Credentials erlaubt)' } else { 'ERLAUBT: Apps können neue Passwörter (Client Secrets) hinzufügen!' }
        CurrentEN      = if ($AppPwdAddBlocked) { 'Blocked (Only Certificates / Federated Credentials allowed)' } else { 'ALLOWED: Apps can add new passwords (client secrets)!' }
        RecommendedDE  = 'Hinzufügen von Passwörtern blockieren (restrictionType: passwordAddition = enabled) -> Zertifikate erzwingen'
        RecommendedEN  = 'Block password addition (restrictionType: passwordAddition = enabled) -> Enforce certificates'
        Compliance     = 'Huntress & CloudCapsule Advisory | ISO 27001 A.5.17 | DORA Art. 9(4)'
        DetailDE       = 'Bei Supply-Chain-Angriffen (wie Storm-0940 / ConnectWise) fügen Angreifer neue Client Secrets (Passwörter) zu bestehenden Apps im Tenant hinzu, um eine dauerhafte Backdoor einzurichten.'
        DetailEN       = 'During supply chain attacks (like Storm-0940 / ConnectWise), threat actors add new client secrets (passwords) to existing apps in the tenant to establish persistent backdoors.'
        LockdownSdk    = @(
            '# [T-07 LOCKDOWN] Verbietet das Hinzufügen neuer Passwörter (Client Secrets) bei App Registrations',
            '$Params = @{',
            '    IsEnabled = $true',
            '    ApplicationRestrictions = @{',
            '        PasswordCredentials = @(@{ RestrictionType = "passwordAddition"; State = "enabled" })',
            '    }',
            '}',
            'Update-MgPolicyDefaultAppManagementPolicy -BodyParameter $Params -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-07 LOCKDOWN] Blockiert passwordAddition für App Registrations via Graph REST API',
            '$Body = @{',
            '    isEnabled = $true',
            '    applicationRestrictions = @{',
            '        passwordCredentials = @(@{ restrictionType = "passwordAddition"; state = "enabled" })',
            '    }',
            '} | ConvertTo-Json -Depth 6',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-08: Enterprise App (Service Principal) can add Local Password (Backdoor Defense!)
    $SpPwdAddRule = $SpPwdRestrictions | Where-Object { (Get-ObjectPropertySafe -InputObject $_ -PropertyName 'restrictionType') -eq 'passwordAddition' } | Select-Object -First 1
    $SpPwdAddBlocked = ($AppMgmtEnabled -and $null -ne $SpPwdAddRule -and (Get-ObjectPropertySafe -InputObject $SpPwdAddRule -PropertyName 'state') -eq 'enabled')
    $T08Color = if ($SpPwdAddBlocked) { 'Green' } else { 'Red' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-08'
        Color          = $T08Color
        NameDE         = 'Enterprise App (Service Principal) kann lokales Passwort hinzufügen (Backdoor-Schutz)'
        NameEN         = 'Enterprise App (Service Principal) Can Add Local Password (Backdoor Defense)'
        CurrentDE      = if ($SpPwdAddBlocked) { 'Blockiert (Service Principals dürfen keine eigenen Passwörter erhalten)' } else { 'KRITISCH: Lokale Passwörter können zu Enterprise Apps (Service Principals) hinzugefügt werden!' }
        CurrentEN      = if ($SpPwdAddBlocked) { 'Blocked (Service principals cannot have local passwords added)' } else { 'CRITICAL: Local passwords can be added directly to Enterprise Apps (Service Principals)!' }
        RecommendedDE  = 'servicePrincipalRestrictions -> passwordAddition = enabled setzen'
        RecommendedEN  = 'Set servicePrincipalRestrictions -> passwordAddition = enabled'
        Compliance     = 'Huntress Storm-0940 Mitigation | NIS2 Art. 21(2)d | BSI ORP.4.A22'
        DetailDE       = 'Multi-Tenant Enterprise Apps authentifizieren sich über den Tenant des Herstellers. Ein lokales Passwort auf einem Service Principal in Ihrem Tenant ist fast immer eine Backdoor oder Fehlkonfiguration!'
        DetailEN       = 'Multi-tenant Enterprise Apps authenticate via the vendor tenant. A local password added directly to a Service Principal in your tenant is almost always a backdoor or misconfiguration!'
        LockdownSdk    = @(
            '# [T-08 LOCKDOWN] Verbietet das Hinzufügen lokaler Passwörter auf allen Enterprise Apps (Service Principals)',
            '$Params = @{',
            '    IsEnabled = $true',
            '    ServicePrincipalRestrictions = @{',
            '        PasswordCredentials = @(@{ RestrictionType = "passwordAddition"; State = "enabled" })',
            '    }',
            '}',
            'Update-MgPolicyDefaultAppManagementPolicy -BodyParameter $Params -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-08 LOCKDOWN] Blockiert passwordAddition auf Service Principals via Graph REST API',
            '$Body = @{',
            '    isEnabled = $true',
            '    servicePrincipalRestrictions = @{',
            '        passwordCredentials = @(@{ restrictionType = "passwordAddition"; state = "enabled" })',
            '    }',
            '} | ConvertTo-Json -Depth 6',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-09: Maximum App Password Lifetime (passwordLifetime)
    $AppLifeRule = $AppPwdRestrictions | Where-Object { (Get-ObjectPropertySafe -InputObject $_ -PropertyName 'restrictionType') -eq 'passwordLifetime' } | Select-Object -First 1
    $LifeEnabled = ($AppMgmtEnabled -and $null -ne $AppLifeRule -and (Get-ObjectPropertySafe -InputObject $AppLifeRule -PropertyName 'state') -eq 'enabled')
    $MaxLifeStr  = [string](Get-ObjectPropertySafe -InputObject $AppLifeRule -PropertyName 'maxLifetime')
    $T09Color = 'Red'
    $T09CurrDE = 'Keine Begrenzung aktiv (Passwörter mit > 2 Jahren Laufzeit möglich)'
    $T09CurrEN = 'No lifetime restriction active (Passwords > 2 years possible)'
    if ($AppPwdAddBlocked) {
        $T09Color = 'Green'
        $T09CurrDE = 'Optimal: Passwörter sind durch T-07 bereits vollständig blockiert'
        $T09CurrEN = 'Optimal: Passwords are completely blocked via T-07'
    }
    elseif ($LifeEnabled) {
        if ($MaxLifeStr -match 'P(\d+)D') {
            $Days = [int]$Matches[1]
            if ($Days -le 180) {
                $T09Color = 'Green'
                $T09CurrDE = "Begrenzt auf max. $Days Tage ($MaxLifeStr)"
                $T09CurrEN = "Restricted to max $Days days ($MaxLifeStr)"
            }
            elseif ($Days -le 365) {
                $T09Color = 'Orange'
                $T09CurrDE = "Begrenzt auf $Days Tage (Empfehlung: <= 180 Tage)"
                $T09CurrEN = "Restricted to $Days days (Recommended: <= 180 days)"
            }
        }
    }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-09'
        Color          = $T09Color
        NameDE         = 'Maximale Laufzeit für App-Passwörter (passwordLifetime)'
        NameEN         = 'Maximum Application Password Lifetime (passwordLifetime)'
        CurrentDE      = $T09CurrDE
        CurrentEN      = $T09CurrEN
        RecommendedDE  = 'Max. 90 bis 180 Tage (P180D) oder Passwörter ganz verbieten'
        RecommendedEN  = 'Max 90 to 180 days (P180D) or block passwords entirely'
        Compliance     = 'ISO 27001 A.5.17 | DORA Art. 9(4) | BSI ORP.4.A8'
        DetailDE       = 'Verhindert langlebige statische API-Secrets, die bei einem Leak über Jahre hinweg unbemerkt missbraucht werden können.'
        DetailEN       = 'Prevents long-lived static API secrets that could be abused unnoticed for years if leaked.'
        LockdownSdk    = @(
            '# [T-09 LOCKDOWN] Begrenzt die maximale Laufzeit von App-Passwörtern auf 180 Tage (P180D)',
            '$Params = @{',
            '    IsEnabled = $true',
            '    ApplicationRestrictions = @{',
            '        PasswordCredentials = @(@{ RestrictionType = "passwordLifetime"; State = "enabled"; MaxLifetime = "P180D" })',
            '    }',
            '}',
            'Update-MgPolicyDefaultAppManagementPolicy -BodyParameter $Params -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-09 LOCKDOWN] Setzt passwordLifetime = P180D via Graph REST API',
            '$Body = @{',
            '    isEnabled = $true',
            '    applicationRestrictions = @{',
            '        passwordCredentials = @(@{ restrictionType = "passwordLifetime"; state = "enabled"; maxLifetime = "P180D" })',
            '    }',
            '} | ConvertTo-Json -Depth 6',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-10: Certificate Lifetime & Custom Password Block (asymmetricKeyLifetime & customPasswordAddition)
    $CertLifeRule = $AppKeyRestrictions | Where-Object { (Get-ObjectPropertySafe -InputObject $_ -PropertyName 'restrictionType') -eq 'asymmetricKeyLifetime' } | Select-Object -First 1
    $CertLifeActive = ($AppMgmtEnabled -and $null -ne $CertLifeRule -and (Get-ObjectPropertySafe -InputObject $CertLifeRule -PropertyName 'state') -eq 'enabled')
    $CertMaxLifeStr = [string](Get-ObjectPropertySafe -InputObject $CertLifeRule -PropertyName 'maxLifetime')
    $T10Color = if ($CertLifeActive) { 'Green' } else { 'Orange' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-10'
        Color          = $T10Color
        NameDE         = 'Zertifikats-Laufzeitbegrenzung & Verbot benutzerdefinierter Passwörter'
        NameEN         = 'Certificate Lifetime Limit & Custom Password Restriction'
        CurrentDE      = if ($CertLifeActive) { "Aktiv ($CertMaxLifeStr)" } else { 'Nicht eingeschränkt (Zertifikate mit beliebiger Laufzeit & Custom Passwords möglich)' }
        CurrentEN      = if ($CertLifeActive) { "Active ($CertMaxLifeStr)" } else { 'Unrestricted (Certificates with arbitrary lifetime & custom passwords allowed)' }
        RecommendedDE  = 'asymmetricKeyLifetime <= P365D & customPasswordAddition = enabled'
        RecommendedEN  = 'asymmetricKeyLifetime <= P365D & customPasswordAddition = enabled'
        Compliance     = 'ISO 27001 A.8.24 | NIST SP 800-57 | BSI CON.1'
        DetailDE       = 'Erzwingt jährliche Zertifikatsrotation (max. 365 Tage) und verbietet schwache, manuell gewählte App-Passwörter.'
        DetailEN       = 'Enforces annual certificate rotation (max 365 days) and prohibits weak, manually chosen application passwords.'
        LockdownSdk    = @(
            '# [T-10 LOCKDOWN] Begrenzt Zertifikatslaufzeit auf 365 Tage und blockiert benutzerdefinierte Passwörter',
            '$Params = @{',
            '    IsEnabled = $true',
            '    ApplicationRestrictions = @{',
            '        PasswordCredentials = @(@{ RestrictionType = "customPasswordAddition"; State = "enabled" })',
            '        KeyCredentials      = @(@{ RestrictionType = "asymmetricKeyLifetime"; State = "enabled"; MaxLifetime = "P365D" })',
            '    }',
            '}',
            'Update-MgPolicyDefaultAppManagementPolicy -BodyParameter $Params -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-10 LOCKDOWN] Härtet asymmetricKeyLifetime & customPasswordAddition via Graph REST API',
            '$Body = @{',
            '    isEnabled = $true',
            '    applicationRestrictions = @{',
            '        passwordCredentials = @(@{ restrictionType = "customPasswordAddition"; state = "enabled" })',
            '        keyCredentials      = @(@{ restrictionType = "asymmetricKeyLifetime"; state = "enabled"; maxLifetime = "P365D" })',
            '    }',
            '} | ConvertTo-Json -Depth 6',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-11: Standard Users Allowed to Read Other Users (Directory Enumeration Protection)
    $CanReadOtherUsers = ((Get-ObjectPropertySafe -InputObject $DefUserRolePerms -PropertyName 'allowedToReadOtherUsers' -DefaultValue $true) -eq $true)
    $T11Color = if ($CanReadOtherUsers) { 'Orange' } else { 'Green' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-11'
        Color          = $T11Color
        NameDE         = 'Verzeichnis-Auslesbarkeit durch Standardbenutzer / Delegated Apps (allowedToReadOtherUsers)'
        NameEN         = 'Directory Enumeration by Standard Users / Delegated Apps (allowedToReadOtherUsers)'
        CurrentDE      = if ($CanReadOtherUsers) { 'Standard (allowedToReadOtherUsers = true; Delegated Apps können alle User/Admins auslesen)' } else { 'Gehärtet (allowedToReadOtherUsers = false)' }
        CurrentEN      = if ($CanReadOtherUsers) { 'Default (allowedToReadOtherUsers = true; Delegated apps can enumerate all users/admins)' } else { 'Hardened (allowedToReadOtherUsers = false)' }
        RecommendedDE  = 'Für Hochsicherheits-Tenants prüfen (Vorsicht: Beeinflusst Teams/Outlook Adressbuch-Suche)'
        RecommendedEN  = 'Evaluate for high-security tenants (Note: Impacts Teams/Outlook address book search)'
        Compliance     = 'NIS2 Art. 21(2)d | ISO 27001 A.5.15 | CloudCapsule Reconnaissance Defense'
        DetailDE       = 'Verhindert bei false, dass kompromittierte Konten oder delegierte OAuth-Apps das komplette Entra-Verzeichnis (inkl. Global Admin Konten) per Graph auslesen können.'
        DetailEN       = 'When set to false, prevents compromised accounts or delegated OAuth apps from enumerating the entire Entra directory via Graph.'
        LockdownSdk    = @(
            '# [T-11 HARDENING] ACHTUNG: Vor Aktivierung Auswirkungen auf Teams/Exchange-Suche prüfen!',
            'Update-MgPolicyAuthorizationPolicy -BodyParameter @{ defaultUserRolePermissions = @{ allowedToReadOtherUsers = $false } } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-11 HARDENING] Setzt allowedToReadOtherUsers = false via Graph REST API',
            '$Body = @{ defaultUserRolePermissions = @{ allowedToReadOtherUsers = $false } } | ConvertTo-Json -Depth 4',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-12: Guest Invite Restrictions (allowInvitesFrom)
    $AllowInvitesFrom = [string](Get-ObjectPropertySafe -InputObject $AuthPol -PropertyName 'allowInvitesFrom' -DefaultValue 'everyone')
    $T12Color = 'Green'
    if ($AllowInvitesFrom -in @('everyone', 'adminsGuestInvitersAndAllMembers')) {
        $T12Color = 'Red'
    }
    elseif ($AllowInvitesFrom -eq 'adminsAndGuestInviters') {
        $T12Color = 'Orange'
    }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-12'
        Color          = $T12Color
        NameDE         = 'Externe Gast-Einladungen & B2B-Lateral-Movement (allowInvitesFrom)'
        NameEN         = 'External Guest Invitations & B2B Lateral Movement (allowInvitesFrom)'
        CurrentDE      = "Aktuelle Richtlinie: $AllowInvitesFrom"
        CurrentEN      = "Current policy: $AllowInvitesFrom"
        RecommendedDE  = 'Nur Administratoren / Guest Inviter Rolle (adminsAndGuestInviters) oder Niemand (none)'
        RecommendedEN  = 'Restrict to Admins / Guest Inviter role (adminsAndGuestInviters) or None (none)'
        Compliance     = 'CIS M365 5.1.6.2 | CloudCapsule Lockdown Guide | ISO 27001 A.5.15'
        DetailDE       = 'Verhindert, dass Standardbenutzer oder Gäste beliebige externe Identitäten in den Tenant einladen und diesen App-Zugriffe ermöglichen.'
        DetailEN       = 'Prevents standard users or guests from inviting arbitrary external identities into the tenant and granting them application access.'
        LockdownSdk    = @(
            '# [T-12 HARDENING] Beschränkt Gast-Einladungen auf explizite Admin-/Guest-Inviter-Rollen',
            'Update-MgPolicyAuthorizationPolicy -BodyParameter @{ allowInvitesFrom = "adminsAndGuestInviters" } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-12 HARDENING] Setzt allowInvitesFrom = adminsAndGuestInviters via Graph REST API',
            '$Body = @{ allowInvitesFrom = "adminsAndGuestInviters" } | ConvertTo-Json',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-13: Guest User Directory Access Level (guestUserRoleId)
    $GuestRoleIdRaw = [string](Get-ObjectPropertySafe -InputObject $AuthPol -PropertyName 'guestUserRoleId' -DefaultValue '10dae51f-b6af-4016-8d66-8c2a99b929b3')
    $GuestRoleId = $GuestRoleIdRaw.Trim().ToLowerInvariant()
    $T13Color = 'Red'
    $T13CurrDE = "Uneingeschränkter Gastzugriff ($GuestRoleId)"
    $T13CurrEN = "Unrestricted Guest Access ($GuestRoleId)"
    if ($GuestRoleId -eq '2af84b1e-32c8-42b7-82bc-daa82404023b') {
        $T13Color = 'Green'
        $T13CurrDE = 'Maximal eingeschränkt (Restricted Guest User: 2af84b1e-...)'
        $T13CurrEN = 'Strictly restricted (Restricted Guest User: 2af84b1e-...)'
    }
    elseif ($GuestRoleId -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') {
        $T13Color = 'Orange'
        $T13CurrDE = 'Standard-Gastzugriff (Gäste können andere Gruppen/Benutzer sehen: 10dae51f-...)'
        $T13CurrEN = 'Standard Guest Access (Guests can view other groups/users: 10dae51f-...)'
    }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-13'
        Color          = $T13Color
        NameDE         = 'Gastbenutzer-Verzeichnisrechte (guestUserRoleId - Least Privilege)'
        NameEN         = 'Guest User Directory Access Restrictions (guestUserRoleId - Least Privilege)'
        CurrentDE      = $T13CurrDE
        CurrentEN      = $T13CurrEN
        RecommendedDE  = 'Restricted Guest User (2af84b1e-32c8-42b7-82bc-daa82404023b) - Zugriff nur auf eigene Profil-Daten'
        RecommendedEN  = 'Restricted Guest User (2af84b1e-32c8-42b7-82bc-daa82404023b) - Access limited to own profile only'
        Compliance     = 'CIS M365 5.1.6.1 | BSI ORP.4.A2 | ISO 27001 A.5.15'
        DetailDE       = 'Verhindert, dass externe Gastkonten (z. B. von Dienstleistern/Vendoren) das interne Entra-Verzeichnis, Gruppenmitgliedschaften oder App-Zuweisungen ausspähen können.'
        DetailEN       = 'Prevents external guest accounts (e.g. from vendors/MSPs) from enumerating the internal Entra directory, group memberships, or app assignments.'
        LockdownSdk    = @(
            '# [T-13 HARDENING] Setzt Gastbenutzer-Rechte auf die restriktivste Stufe (Restricted Guest User)',
            'Update-MgPolicyAuthorizationPolicy -BodyParameter @{ guestUserRoleId = "2af84b1e-32c8-42b7-82bc-daa82404023b" } -WhatIf'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-13 HARDENING] Setzt guestUserRoleId = 2af84b1e-32c8-42b7-82bc-daa82404023b via Graph REST API',
            '$Body = @{ guestUserRoleId = "2af84b1e-32c8-42b7-82bc-daa82404023b" } | ConvertTo-Json',
            'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Body $Body -ContentType "application/json"'
        ) -join "`n"
    })

    # T-14: Cross-Tenant Access Default Policy (Inbound/Outbound B2B App Access)
    $CrossPol   = Get-ObjectPropertySafe -InputObject $TenantPoliciesRaw -PropertyName 'CrossTenantDefaultPolicy'
    $InbObj     = Get-ObjectPropertySafe -InputObject $CrossPol -PropertyName 'b2bCollaborationInbound'
    $InbAppsObj = Get-ObjectPropertySafe -InputObject $InbObj   -PropertyName 'applications'
    $InbAccess  = [string](Get-ObjectPropertySafe -InputObject $InbAppsObj -PropertyName 'accessType' -DefaultValue 'allowed')
    $T14Color   = if ($InbAccess -eq 'blocked') { 'Green' } else { 'Orange' }
    $TenantFindings.Add([PSCustomObject]@{
        Id             = 'T-14'
        Color          = $T14Color
        NameDE         = 'Cross-Tenant Access Standardrichtlinie für externe Mandanten-Apps (crossTenantAccessPolicy)'
        NameEN         = 'Cross-Tenant Access Default Policy for External Tenant Apps (crossTenantAccessPolicy)'
        CurrentDE      = if ($InbAccess -eq 'blocked') { 'Standardmäßig blockiert (Nur explizite Partner-Tenants erlaubt)' } else { "Offener Standard (b2bCollaborationInbound.applications.accessType = $InbAccess)" }
        CurrentEN      = if ($InbAccess -eq 'blocked') { 'Blocked by default (Only explicit partner tenants allowed)' } else { "Open default (b2bCollaborationInbound.applications.accessType = $InbAccess)" }
        RecommendedDE  = 'Standard-Zugriff prüfen und über Partner-Konfigurationen auf verifizierte Partner-Tenants einschränken'
        RecommendedEN  = 'Review default access and restrict via partner configurations to verified partner tenants'
        Compliance     = 'NIS2 Art. 21(2)d | DORA Art. 28 | ISO 27001 A.5.19'
        DetailDE       = 'Steuert, welchen externen Microsoft-365-Mandanten und deren Applikationen standardmäßig im Rahmen von B2B-Zugriffen vertraut wird.'
        DetailEN       = 'Controls which external Microsoft 365 tenants and their applications are trusted by default for B2B collaboration.'
        LockdownSdk    = @(
            '# [T-14 HARDENING] Prüft die aktuelle Cross-Tenant Default Policy im Detail',
            'Get-MgPolicyCrossTenantAccessPolicyDefault | ConvertTo-Json -Depth 6'
        ) -join "`n"
        LockdownRest   = @(
            '# [T-14 HARDENING] Abruf & Prüfung der Cross-Tenant Access Default Policy via Graph REST API',
            'Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default"'
        ) -join "`n"
    })

    # Inject live Tenant Context, Write Scope Check, Execution Status & Audit Info into all 14 Tenant Policy scripts
    foreach ($PolItem in $TenantFindings) {
        $AuditGroupKey = if ($PolItem.Id -in @('T-01','T-02','T-03','T-04','T-11','T-12','T-13')) { 'AuthPolicy' }
                         elseif ($PolItem.Id -eq 'T-05') { 'ConsentPolicy' }
                         elseif ($PolItem.Id -in @('T-06','T-07','T-08','T-09','T-10')) { 'AppMgmtPolicy' }
                         else { 'CrossTenantPolicy' }

        $PolAud = if ($PolicyAuditById.ContainsKey($PolItem.Id)) {
            $PolicyAuditById[$PolItem.Id]
        }
        elseif ($PolicyAuditByGroup.ContainsKey($AuditGroupKey)) {
            $PolicyAuditByGroup[$AuditGroupKey]
        }
        else {
            $null
        }
        $PolLastModDE = if ($null -ne $PolAud) { $PolAud.BadgeDE } else { 'Keine aktuelle Änderung im Audit-Log (letzte 200 Events)' }
        $PolLastModEN = if ($null -ne $PolAud) { $PolAud.BadgeEN } else { 'No recent change in audit log (last 200 events)' }
        $PolItem | Add-Member -NotePropertyName 'LastModifiedDE' -NotePropertyValue $PolLastModDE -Force
        $PolItem | Add-Member -NotePropertyName 'LastModifiedEN' -NotePropertyValue $PolLastModEN -Force

        $IsSimSdk = $PolItem.LockdownSdk -match '-WhatIf'
        $PolHeaderSdk = @(
            "#Requires -Version 7.0",
            "# =============================================================================",
            "# AppSentry for M365 Tenant Policy Hardening: $($PolItem.Id) - $($PolItem.NameDE)",
            "# Target Tenant : $RealTenantName",
            "# Tenant ID     : $RealTenantId",
            "# Recommended   : $($PolItem.RecommendedDE)",
            "# =============================================================================",
            "`$TargetTenantId = `"$RealTenantId`"",
            "`$RequiredScopes = @(`"Policy.ReadWrite.Authorization`", `"Policy.ReadWrite.ApplicationConfiguration`", `"Policy.ReadWrite.CrossTenantAccess`")",
            "`$Ctx = Get-MgContext -ErrorAction SilentlyContinue",
            "`$NeedsConnect = (`$null -eq `$Ctx) -or (`$Ctx.TenantId -ne `$TargetTenantId) -or (`$Ctx.Scopes -notcontains `"Policy.ReadWrite.Authorization`")",
            "if (`$NeedsConnect) {",
            "    Write-Host `"[*] Connecting to Tenant '$RealTenantName' (`$TargetTenantId) with Policy ReadWrite scopes...`" -ForegroundColor Cyan",
            "    Connect-MgGraph -TenantId `$TargetTenantId -Scopes `$RequiredScopes -NoWelcome -ErrorAction Stop",
            "}",
            "Write-Host `"`n[AppSentry for M365] Applying Policy $($PolItem.Id): $($PolItem.NameDE)...`" -ForegroundColor Cyan",
            ""
        ) -join "`n"

        $FooterMsgLine = if ($IsSimSdk) {
            "    Write-Host `"[SIMULATION / -WhatIf] Dry-run completed! Nothing was changed in Entra ID yet. Remove -WhatIf (or uncheck '-WhatIf Schutz aktiv' in the report before downloading) to apply for real.`" -ForegroundColor Yellow"
        }
        else {
            "    Write-Host `"[SUCCESS] Policy $($PolItem.Id) successfully updated!`" -ForegroundColor Green"
        }

        $PolVerifyLines = if ($PolItem.Id -in @('T-01','T-02','T-03','T-04','T-11','T-12','T-13')) {
            @(
                "    `$VerifyAuth = Invoke-MgGraphRequest -Method GET -Uri `"https://graph.microsoft.com/v1.0/policies/authorizationPolicy`" -ErrorAction SilentlyContinue",
                "    if (`$null -ne `$VerifyAuth) {",
                "        `$GrantsStr = @(`$VerifyAuth.defaultUserRolePermissions.permissionGrantPoliciesAssigned) -join ', '",
                "        Write-Host `"[CURRENT LIVE STATE] allowInvitesFrom: `$(`$VerifyAuth.allowInvitesFrom) | guestUserRoleId: `$(`$VerifyAuth.guestUserRoleId) | allowedToCreateApps: `$(`$VerifyAuth.defaultUserRolePermissions.allowedToCreateApps) | allowedToReadOtherUsers: `$(`$VerifyAuth.defaultUserRolePermissions.allowedToReadOtherUsers) | consentGrants: [`$GrantsStr]`" -ForegroundColor Cyan",
                "    }"
            )
        }
        elseif ($PolItem.Id -eq 'T-05') {
            @(
                "    `$VerifyConsent = Invoke-MgGraphRequest -Method GET -Uri `"https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy`" -ErrorAction SilentlyContinue",
                "    if (`$null -ne `$VerifyConsent) {",
                "        Write-Host `"[CURRENT LIVE STATE] adminConsentRequestPolicy.isEnabled: `$(`$VerifyConsent.isEnabled) | requestDurationInDays: `$(`$VerifyConsent.requestDurationInDays)`" -ForegroundColor Cyan",
                "    }"
            )
        }
        elseif ($PolItem.Id -in @('T-06','T-07','T-08','T-09','T-10')) {
            @(
                "    `$VerifyMgmt = Invoke-MgGraphRequest -Method GET -Uri `"https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy`" -ErrorAction SilentlyContinue",
                "    if (`$null -ne `$VerifyMgmt) {",
                "        Write-Host `"[CURRENT LIVE STATE] defaultAppManagementPolicy.isEnabled: `$(`$VerifyMgmt.isEnabled)`" -ForegroundColor Cyan",
                "    }"
            )
        }
        else {
            @()
        }

        $PolFooterSdk = (@(
            "",
            "if (`$?) {",
            $FooterMsgLine
        ) + $PolVerifyLines + @("}")) -join "`n"

        $PolHeaderRest = @(
            "#Requires -Version 7.0",
            "# =============================================================================",
            "# AppSentry for M365 Tenant Policy Hardening (REST): $($PolItem.Id) - $($PolItem.NameDE)",
            "# Target Tenant : $RealTenantName",
            "# Tenant ID     : $RealTenantId",
            "# Recommended   : $($PolItem.RecommendedDE)",
            "# =============================================================================",
            "`$TargetTenantId = `"$RealTenantId`"",
            "`$RequiredScopes = @(`"Policy.ReadWrite.Authorization`", `"Policy.ReadWrite.ApplicationConfiguration`", `"Policy.ReadWrite.CrossTenantAccess`")",
            "`$Ctx = Get-MgContext -ErrorAction SilentlyContinue",
            "`$NeedsConnect = (`$null -eq `$Ctx) -or (`$Ctx.TenantId -ne `$TargetTenantId) -or (`$Ctx.Scopes -notcontains `"Policy.ReadWrite.Authorization`")",
            "if (`$NeedsConnect) {",
            "    Write-Host `"[*] Connecting to Tenant '$RealTenantName' (`$TargetTenantId) with Policy ReadWrite scopes...`" -ForegroundColor Cyan",
            "    Connect-MgGraph -TenantId `$TargetTenantId -Scopes `$RequiredScopes -NoWelcome -ErrorAction Stop",
            "}",
            "Write-Host `"`n[AppSentry for M365] Applying Policy $($PolItem.Id) via REST API...`" -ForegroundColor Cyan",
            ""
        ) -join "`n"

        $PolFooterRest = (@(
            "",
            "if (`$?) {",
            "    Write-Host `"[SUCCESS] Policy $($PolItem.Id) REST operation completed!`" -ForegroundColor Green"
        ) + $PolVerifyLines + @("}")) -join "`n"

        $PolItem.LockdownSdk  = $PolHeaderSdk + $PolItem.LockdownSdk + $PolFooterSdk
        $PolItem.LockdownRest = $PolHeaderRest + $PolItem.LockdownRest + $PolFooterRest
    }

    # =========================================================================
    # PART 2: EVALUATE INDIVIDUAL APPLICATIONS (6 DIMENSIONS + 3-STAGE LOCKDOWN)
    # =========================================================================
    $Now = [DateTime]::UtcNow
    $AppFindings = [System.Collections.Generic.List[object]]::new()

    foreach ($App in $AppsRaw) {
        $AppIdLower = if (-not [string]::IsNullOrWhiteSpace($App.AppId)) { $App.AppId.ToLowerInvariant() } else { '' }
        $ReasonsDE  = [System.Collections.Generic.List[string]]::new()
        $ReasonsEN  = [System.Collections.Generic.List[string]]::new()

        # Stage 1, Stage 2, and Stage 3 collector lists
        $SdkStage1  = [System.Collections.Generic.List[string]]::new()
        $RestStage1 = [System.Collections.Generic.List[string]]::new()
        $SdkStage2Extra  = [System.Collections.Generic.List[string]]::new()
        $RestStage2Extra = [System.Collections.Generic.List[string]]::new()
        $SdkStage3Extra  = [System.Collections.Generic.List[string]]::new()
        $RestStage3Extra = [System.Collections.Generic.List[string]]::new()

        $SdkStage1.Add("#Requires -Version 7.0")
        $SdkStage1.Add("# =============================================================================")
        $SdkStage1.Add("# AppSentry for M365 LOCKDOWN PLAYBOOK (PowerShell Graph SDK)")
        $SdkStage1.Add("# Target Tenant : $RealTenantName")
        $SdkStage1.Add("# Tenant ID     : $RealTenantId")
        $SdkStage1.Add("# Target App    : $($App.DisplayName) (AppId: $($App.AppId))")
        $SdkStage1.Add("# Object ID     : $($App.ObjectId)")
        $SdkStage1.Add("# =============================================================================")
        $SdkStage1.Add("`$TargetTenantId     = `"$RealTenantId`"")
        $SdkStage1.Add("`$ServicePrincipalId = `"$($App.ObjectId)`"")
        $SdkStage1.Add("")
        $SdkStage1.Add("# [0] Session & Write-Scope Verification (Ensures execution in the exact target tenant with Write permissions):")
        $SdkStage1.Add("`$Ctx = Get-MgContext -ErrorAction SilentlyContinue")
        $SdkStage1.Add("`$NeedsConnect = (`$null -eq `$Ctx) -or (`$Ctx.TenantId -ne `$TargetTenantId) -or (`$Ctx.Scopes -notcontains `"Application.ReadWrite.All`")")
        $SdkStage1.Add("if (`$NeedsConnect) {")
        $SdkStage1.Add("    Write-Host `"[*] Connecting to Microsoft Graph for Tenant '$RealTenantName' (`$TargetTenantId) with ReadWrite scopes...`" -ForegroundColor Cyan")
        $SdkStage1.Add("    Connect-MgGraph -TenantId `$TargetTenantId -Scopes `"Application.ReadWrite.All`", `"AppRoleAssignment.ReadWrite.All`", `"RoleManagement.ReadWrite.Directory`" -NoWelcome -ErrorAction Stop")
        $SdkStage1.Add("}")
        $SdkStage1.Add("Write-Host `"`n[AppSentry for M365] Executing Lockdown for '$($App.DisplayName)' (AppId: $($App.AppId))...`" -ForegroundColor Cyan")
        $SdkStage1.Add("")
        $SdkStage1.Add("# [STAGE 1 - RECOMMENDED SOFT LOCKDOWN] ('Disable, Don't Delete'):")
        $SdkStage1.Add("# Immediately blocks sign-in & token issuance while preserving all backup/app permissions and forensic logs!")
        $SdkStage1.Add("Update-MgServicePrincipal -ServicePrincipalId `$ServicePrincipalId -AccountEnabled:`$false -WhatIf")
        if (-not $App.AppRoleAssignmentRequired) {
            $SdkStage1.Add("Update-MgServicePrincipal -ServicePrincipalId `$ServicePrincipalId -AppRoleAssignmentRequired:`$true -WhatIf")
        }
        $SdkStage1.Add("")
        $SdkStage1.Add("# [ROLLBACK INFO] To re-enable this app later after vendor/security clearance without re-configuring permissions:")
        $SdkStage1.Add("# Update-MgServicePrincipal -ServicePrincipalId `$ServicePrincipalId -AccountEnabled:`$true")

        $RestStage1.Add("#Requires -Version 7.0")
        $RestStage1.Add("# =============================================================================")
        $RestStage1.Add("# AppSentry for M365 LOCKDOWN PLAYBOOK (Graph REST API)")
        $RestStage1.Add("# Target Tenant : $RealTenantName")
        $RestStage1.Add("# Tenant ID     : $RealTenantId")
        $RestStage1.Add("# Target App    : $($App.DisplayName) (AppId: $($App.AppId))")
        $RestStage1.Add("# Object ID     : $($App.ObjectId)")
        $RestStage1.Add("# =============================================================================")
        $RestStage1.Add("`$TargetTenantId     = `"$RealTenantId`"")
        $RestStage1.Add("`$ServicePrincipalId = `"$($App.ObjectId)`"")
        $RestStage1.Add("")
        $RestStage1.Add("# [0] Session & Write-Scope Verification:")
        $RestStage1.Add("`$Ctx = Get-MgContext -ErrorAction SilentlyContinue")
        $RestStage1.Add("`$NeedsConnect = (`$null -eq `$Ctx) -or (`$Ctx.TenantId -ne `$TargetTenantId) -or (`$Ctx.Scopes -notcontains `"Application.ReadWrite.All`")")
        $RestStage1.Add("if (`$NeedsConnect) {")
        $RestStage1.Add("    Write-Host `"[*] Connecting to Microsoft Graph for Tenant '$RealTenantName' (`$TargetTenantId) with ReadWrite scopes...`" -ForegroundColor Cyan")
        $RestStage1.Add("    Connect-MgGraph -TenantId `$TargetTenantId -Scopes `"Application.ReadWrite.All`", `"AppRoleAssignment.ReadWrite.All`", `"RoleManagement.ReadWrite.Directory`" -NoWelcome -ErrorAction Stop")
        $RestStage1.Add("}")
        $RestStage1.Add("Write-Host `"`n[AppSentry for M365] Executing REST Lockdown for '$($App.DisplayName)'...`" -ForegroundColor Cyan")
        $RestStage1.Add("")
        $RestStage1.Add("# [STAGE 1 - RECOMMENDED SOFT LOCKDOWN] ('Disable, Don't Delete'):")
        $RestStage1.Add("Invoke-MgGraphRequest -Method PATCH -Uri `"https://graph.microsoft.com/v1.0/servicePrincipals/`$ServicePrincipalId`" -Body (@{ accountEnabled = `$false; appRoleAssignmentRequired = `$true } | ConvertTo-Json) -ContentType `"application/json`"")
        $RestStage1.Add("")
        $RestStage1.Add("# [ROLLBACK INFO] To re-enable later: PATCH accountEnabled = `$true")

        # ---------------------------------------------------------------------
        # Dimension 1: Threat Intel / Known Compromised Vendor App / BEC / Traitorware / LotL
        # ---------------------------------------------------------------------
        $IocColor             = 'Green'
        $IocBadgeDE           = 'Kein IOC-Treffer'
        $IocBadgeEN           = 'No IOC Match'
        $IsThreatIntelMatch   = $false
        $ThreatCategory       = ''
        $ThreatCampaign       = ''
        $ThreatDescriptionDE  = ''
        $ThreatDescriptionEN  = ''
        $RecommendationDE     = ''
        $RecommendationEN     = ''
        $ThreatReferences     = @()

        if ($IocByAppId.ContainsKey($AppIdLower)) {
            $MatchedIoc          = $IocByAppId[$AppIdLower]
            $IsThreatIntelMatch  = $true
            $ThreatCategory      = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'category')
            if ([string]::IsNullOrWhiteSpace($ThreatCategory)) { $ThreatCategory = 'VendorBreach' }
            $ThreatCampaign      = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'campaign')
            $ThreatDescriptionDE = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'descriptionDE')
            $ThreatDescriptionEN = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'descriptionEN')
            $RecommendationDE    = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'recommendationDE')
            $RecommendationEN    = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'recommendationEN')
            $RefsRaw             = Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'references'
            $RefUrlFallback      = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'referenceUrl')
            if ($null -ne $RefsRaw) {
                $ThreatReferences = @($RefsRaw)
            }
            elseif (-not [string]::IsNullOrWhiteSpace($RefUrlFallback)) {
                $ThreatReferences = @([PSCustomObject]@{ title = 'Security Advisory'; url = $RefUrlFallback })
            }

            $TargetSeverity = [string](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'severity')
            if ([string]::IsNullOrWhiteSpace($TargetSeverity)) { $TargetSeverity = 'Red' }
            $OnlyWhenOpen   = [bool](Get-ObjectPropertySafe -InputObject $MatchedIoc -PropertyName 'onlyWhenOpenAssignment')

            if ($App.AccountEnabled) {
                if ($OnlyWhenOpen -and $App.AppRoleAssignmentRequired) {
                    $IocColor   = 'Green'
                    $IocBadgeDE = "LotL-CLI (Gehärtet: Zuweisung Pflicht)"
                    $IocBadgeEN = "LotL-CLI (Hardened: Assignment Req.)"
                }
                elseif ($TargetSeverity -eq 'Orange') {
                    $IocColor   = 'Orange'
                    $CatPrefixDE = if ($ThreatCategory -eq 'LotLAdminTool') { 'LOTL-CLI OFFEN' } else { 'TRAITORWARE / ROGUE-APP' }
                    $CatPrefixEN = if ($ThreatCategory -eq 'LotLAdminTool') { 'LOTL-CLI OPEN' } else { 'TRAITORWARE / ROGUE-APP' }
                    $IocBadgeDE = "${CatPrefixDE}: $ThreatCampaign"
                    $IocBadgeEN = "${CatPrefixEN}: $ThreatCampaign"
                    $ReasonsDE.Add("[THREAT-INTEL WARNUNG ($CatPrefixDE)] $ThreatDescriptionDE")
                    $ReasonsEN.Add("[THREAT-INTEL WARNING ($CatPrefixEN)] $ThreatDescriptionEN")
                }
                else {
                    $IocColor   = 'Red'
                    $IocBadgeDE = "AKTIVER IOC: $ThreatCampaign"
                    $IocBadgeEN = "ACTIVE IOC: $ThreatCampaign"
                    $ReasonsDE.Add("[IOC-TREFFER] $ThreatDescriptionDE")
                    $ReasonsEN.Add("[IOC-MATCH] $ThreatDescriptionEN")
                }
            }
            else {
                $IocColor   = 'Orange'
                $IocBadgeDE = "IOC (Bereits gesperrt): $ThreatCampaign"
                $IocBadgeEN = "IOC (Already Disabled): $ThreatCampaign"
                $ReasonsDE.Add("[IOC-WARNUNG] App steht auf der Vorfallsliste ($ThreatCampaign), ist aber bereits deaktiviert (accountEnabled = false).")
                $ReasonsEN.Add("[IOC-WARNING] App is on the known incident watchlist ($ThreatCampaign), but is currently disabled (accountEnabled = false).")
            }
            $SdkStage1.Add("`n# [FORENSICS] Hunt for sign-in activity of this Threat-Intel flagged app:")
            $SdkStage1.Add("Get-MgAuditLogSignIn -Filter `"appId eq '$($App.AppId)'`" -Top 100")
        }

        # ---------------------------------------------------------------------
        # Dimension 2: Self-Escalation / Can App Add Passwords or Roles?
        # ---------------------------------------------------------------------
        $EscColor   = 'Green'
        $EscPerms   = [System.Collections.Generic.List[string]]::new()
        $AllGrantedPerms = [System.Collections.Generic.List[object]]::new()

        foreach ($Ara in @($App.AppRoleAssignments)) {
            $AllGrantedPerms.Add([PSCustomObject]@{ Type = 'Application'; Value = $Ara.Permission; Id = $Ara.Id })
        }
        foreach ($Dg in @($App.DelegatedGrants)) {
            $Scopes = ($Dg.Scope -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($S in $Scopes) {
                $AllGrantedPerms.Add([PSCustomObject]@{ Type = "Delegated ($($Dg.ConsentType))"; Value = $S; Id = $Dg.Id })
            }
        }

        foreach ($PermObj in $AllGrantedPerms) {
            $Key = $PermObj.Value.ToLowerInvariant()
            if ($EscalationMap.ContainsKey($Key)) {
                $Rule = $EscalationMap[$Key]
                $EscPerms.Add("$($PermObj.Value) [$($PermObj.Type)]")
                if ($Rule.severity -eq 'Red') {
                    $EscColor = 'Red'
                    $ReasonsDE.Add("[ESKALATION / PASSWORT-MANIPULATION] $($PermObj.Value): $($Rule.reasonDE)")
                    $ReasonsEN.Add("[ESCALATION / PASSWORD MANIPULATION] $($PermObj.Value): $($Rule.reasonEN)")
                }
                elseif ($Rule.severity -eq 'Orange' -and $EscColor -ne 'Red') {
                    $EscColor = 'Orange'
                    $ReasonsDE.Add("[WARNUNG] $($PermObj.Value): $($Rule.reasonDE)")
                    $ReasonsEN.Add("[WARNING] $($PermObj.Value): $($Rule.reasonEN)")
                }
            }
        }
        $EscBadgeDE = if ($EscColor -eq 'Red') { "JA (Kritisch: $($EscPerms -join ', '))" } elseif ($EscColor -eq 'Orange') { "Eingeschränkt ($($EscPerms -join ', '))" } else { 'Nein (Keine Eskalationsrechte)' }
        $EscBadgeEN = if ($EscColor -eq 'Red') { "YES (Critical: $($EscPerms -join ', '))" } elseif ($EscColor -eq 'Orange') { "Limited ($($EscPerms -join ', '))" } else { 'No (No escalation rights)' }

        # ---------------------------------------------------------------------
        # Dimension 3: Entra ID Directory Roles (Global Admin, App Admin, etc.)
        # ---------------------------------------------------------------------
        $RoleColor = 'Green'
        $RoleNames = [System.Collections.Generic.List[string]]::new()
        foreach ($Dr in @($App.DirectoryRoles)) {
            $RoleNames.Add($Dr.DisplayName)
            if ($Dr.DisplayName -match 'Reader') {
                if ($RoleColor -ne 'Red') { $RoleColor = 'Orange' }
                $ReasonsDE.Add("[VERZEICHNIS-ROLLE] App ist Mitglied in '$($Dr.DisplayName)'.")
                $ReasonsEN.Add("[DIRECTORY ROLE] App is a member of '$($Dr.DisplayName)'.")
            }
            else {
                $RoleColor = 'Red'
                $ReasonsDE.Add("[KRITISCHE ADMIN-ROLLE] App besitzt aktive Entra Admin-Rolle: '$($Dr.DisplayName)'!")
                $ReasonsEN.Add("[CRITICAL ADMIN ROLE] App holds active Entra admin role: '$($Dr.DisplayName)'!")
            }
            $SdkStage2Extra.Add("`n# [STAGE 2] Remove Service Principal from Entra Directory Role '$($Dr.DisplayName)':")
            $SdkStage2Extra.Add("Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId `"$($Dr.RoleId)`" -DirectoryObjectId `$ServicePrincipalId -WhatIf")
            $RestStage2Extra.Add("`n# [STAGE 2] Remove Service Principal from Entra Directory Role '$($Dr.DisplayName)':")
            $RestStage2Extra.Add("Invoke-MgGraphRequest -Method DELETE -Uri `"https://graph.microsoft.com/v1.0/directoryRoles/$($Dr.RoleId)/members/`$ServicePrincipalId/`$ref`"")
        }
        $RoleBadgeDE = if ($RoleNames.Count -gt 0) { $RoleNames -join ', ' } else { 'Keine Directory Roles' }
        $RoleBadgeEN = if ($RoleNames.Count -gt 0) { $RoleNames -join ', ' } else { 'No Directory Roles' }

        # ---------------------------------------------------------------------
        # Dimension 4: Data Permissions (Graph / Exchange / SharePoint Scopes)
        # ---------------------------------------------------------------------
        $PermColor = 'Green'
        $PermSummary = [System.Collections.Generic.List[string]]::new()
        $AraIdEntries = [System.Collections.Generic.List[string]]::new()
        foreach ($Ara in @($App.AppRoleAssignments)) {
            $PVal = $Ara.Permission
            $PLow = $PVal.ToLowerInvariant()
            $PermSummary.Add("$PVal (App)")
            if ($EscalationMap.ContainsKey($PLow) -or $HighDataMap.ContainsKey($PLow)) {
                $PermColor = 'Red'
                if ($HighDataMap.ContainsKey($PLow)) {
                    $ReasonsDE.Add("[VOLLZUGRIFF-APP-RECHT] ${PVal}: $($HighDataMap[$PLow].reasonDE)")
                    $ReasonsEN.Add("[HIGH-RISK APP PERMISSION] ${PVal}: $($HighDataMap[$PLow].reasonEN)")
                }
            }
            elseif ($MedDataMap.ContainsKey($PLow) -and $PermColor -ne 'Red') {
                $PermColor = 'Orange'
                $ReasonsDE.Add("[BREITES LESERECHT] ${PVal}: $($MedDataMap[$PLow].reasonDE)")
                $ReasonsEN.Add("[BROAD READ PERMISSION] ${PVal}: $($MedDataMap[$PLow].reasonEN)")
            }
            $AraIdEntries.Add("    `"$($Ara.Id)`" # $PVal")
        }
        if ($AraIdEntries.Count -gt 0) {
            $SdkStage3Extra.Add("`n# [STAGE 3 - DESTRUCTIVE] Revoke all $($AraIdEntries.Count) Application Permissions (AppRoleAssignments):")
            $SdkStage3Extra.Add("`$AppRoleAssignmentIds = @(")
            foreach ($Entry in $AraIdEntries) { $SdkStage3Extra.Add($Entry) }
            $SdkStage3Extra.Add(")")
            $SdkStage3Extra.Add("foreach (`$AssignmentId in `$AppRoleAssignmentIds) {")
            $SdkStage3Extra.Add("    Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId `$ServicePrincipalId -AppRoleAssignmentId `$AssignmentId -WhatIf")
            $SdkStage3Extra.Add("}")

            $RestStage3Extra.Add("`n# [STAGE 3 - DESTRUCTIVE] Revoke all $($AraIdEntries.Count) Application Permissions (AppRoleAssignments):")
            $RestStage3Extra.Add("`$AppRoleAssignmentIds = @(")
            foreach ($Entry in $AraIdEntries) { $RestStage3Extra.Add($Entry) }
            $RestStage3Extra.Add(")")
            $RestStage3Extra.Add("foreach (`$AssignmentId in `$AppRoleAssignmentIds) {")
            $RestStage3Extra.Add("    Invoke-MgGraphRequest -Method DELETE -Uri `"https://graph.microsoft.com/v1.0/servicePrincipals/`$ServicePrincipalId/appRoleAssignments/`$AssignmentId`"")
            $RestStage3Extra.Add("}")
        }

        $DgIdEntries = [System.Collections.Generic.List[string]]::new()
        foreach ($Dg in @($App.DelegatedGrants)) {
            $Scopes = ($Dg.Scope -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($S in $Scopes) {
                $SLow = $S.ToLowerInvariant()
                $PermSummary.Add("$S ($($Dg.ConsentType))")
                if ($HighDataMap.ContainsKey($SLow) -or $EscalationMap.ContainsKey($SLow)) {
                    if ($Dg.ConsentType -eq 'AllPrincipals') {
                        $PermColor = 'Red'
                        $ReasonsDE.Add("[TENANT-WEITER ADMIN-CONSENT] Kritischer Scope '$S' für alle Benutzer gewährt.")
                        $ReasonsEN.Add("[TENANT-WIDE ADMIN CONSENT] Critical scope '$S' granted for all users.")
                    }
                    elseif ($PermColor -ne 'Red') {
                        $PermColor = 'Orange'
                        $ReasonsDE.Add("[DELEGATED PERMISSION] Sensibler Scope '$S' per Einzelbenutzer-Consent gewährt.")
                        $ReasonsEN.Add("[DELEGATED PERMISSION] Sensitive scope '$S' granted via user consent.")
                    }
                }
                elseif ($MedDataMap.ContainsKey($SLow) -and $PermColor -ne 'Red') {
                    $PermColor = 'Orange'
                }
            }
            $DgIdEntries.Add("    `"$($Dg.Id)`" # $($Dg.Scope)")
        }
        if ($DgIdEntries.Count -gt 0) {
            $SdkStage3Extra.Add("`n# [STAGE 3 - DESTRUCTIVE] Revoke all $($DgIdEntries.Count) Delegated OAuth2PermissionGrants:")
            $SdkStage3Extra.Add("`$DelegatedGrantIds = @(")
            foreach ($Entry in $DgIdEntries) { $SdkStage3Extra.Add($Entry) }
            $SdkStage3Extra.Add(")")
            $SdkStage3Extra.Add("foreach (`$GrantId in `$DelegatedGrantIds) {")
            $SdkStage3Extra.Add("    Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId `$GrantId -WhatIf")
            $SdkStage3Extra.Add("}")

            $RestStage3Extra.Add("`n# [STAGE 3 - DESTRUCTIVE] Revoke all $($DgIdEntries.Count) Delegated OAuth2PermissionGrants:")
            $RestStage3Extra.Add("`$DelegatedGrantIds = @(")
            foreach ($Entry in $DgIdEntries) { $RestStage3Extra.Add($Entry) }
            $RestStage3Extra.Add(")")
            $RestStage3Extra.Add("foreach (`$GrantId in `$DelegatedGrantIds) {")
            $RestStage3Extra.Add("    Invoke-MgGraphRequest -Method DELETE -Uri `"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/`$GrantId`"")
            $RestStage3Extra.Add("}")
        }

        $PermBadgeDE = if ($PermSummary.Count -gt 0) { ($PermSummary | Select-Object -First 4) -join ', ' } else { 'Keine API-Grants' }
        $PermBadgeEN = if ($PermSummary.Count -gt 0) { ($PermSummary | Select-Object -First 4) -join ', ' } else { 'No API Grants' }
        if ($PermSummary.Count -gt 4) {
            $PermBadgeDE += " (+$($PermSummary.Count - 4) weitere)"
            $PermBadgeEN += " (+$($PermSummary.Count - 4) more)"
        }

        # ---------------------------------------------------------------------
        # Dimension 5: Credentials (Passwords / Client Secrets & Certificates)
        # ---------------------------------------------------------------------
        $CredColor = 'Green'
        $PwdCount  = @($App.PasswordCredentials).Count
        $CertCount = @($App.KeyCredentials).Count
        $CredNotesDE = [System.Collections.Generic.List[string]]::new()
        $CredNotesEN = [System.Collections.Generic.List[string]]::new()

        if ($PwdCount -eq 0 -and $CertCount -eq 0) {
            $CredNotesDE.Add('Keine lokalen Secrets (OAuth/Federated)')
            $CredNotesEN.Add('No local secrets (OAuth/Federated)')
        }
        else {
            if ($PwdCount -gt 1) {
                $CredColor = 'Red'
                $ReasonsDE.Add("[MEHRERE PASSWÖRTER] App hat $PwdCount gleichzeitige Client Secrets aktiv.")
                $ReasonsEN.Add("[MULTIPLE PASSWORDS] App has $PwdCount active client secrets simultaneously.")
            }
            foreach ($PwdCred in @($App.PasswordCredentials)) {
                $Start = $Now.AddDays(-30)
                if ($PwdCred.StartDateTime) {
                    if ($PwdCred.StartDateTime -is [DateTime]) {
                        $Start = $PwdCred.StartDateTime.ToUniversalTime()
                    }
                    else {
                        $ParsedStart = [DateTime]::MinValue
                        if ([DateTime]::TryParse([string]$PwdCred.StartDateTime, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$ParsedStart)) {
                            $Start = $ParsedStart
                        }
                        elseif ([DateTime]::TryParse([string]$PwdCred.StartDateTime, [System.Globalization.CultureInfo]::CurrentCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$ParsedStart)) {
                            $Start = $ParsedStart
                        }
                    }
                }
                $End = $Now.AddDays(365)
                if ($PwdCred.EndDateTime) {
                    if ($PwdCred.EndDateTime -is [DateTime]) {
                        $End = $PwdCred.EndDateTime.ToUniversalTime()
                    }
                    else {
                        $ParsedEnd = [DateTime]::MinValue
                        if ([DateTime]::TryParse([string]$PwdCred.EndDateTime, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$ParsedEnd)) {
                            $End = $ParsedEnd
                        }
                        elseif ([DateTime]::TryParse([string]$PwdCred.EndDateTime, [System.Globalization.CultureInfo]::CurrentCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$ParsedEnd)) {
                            $End = $ParsedEnd
                        }
                    }
                }
                $AgeDays      = [math]::Round(($Now - $Start).TotalDays, 0)
                $TotalDays    = [math]::Round(($End - $Start).TotalDays, 0)
                $RemainingDays = [math]::Round(($End - $Now).TotalDays, 0)

                if ($PwdCred.SourceObject -eq 'ServicePrincipal' -and $App.SignInAudience -eq 'AzureADMultipleOrgs') {
                    $CredColor = 'Red'
                    $ReasonsDE.Add("[BACKDOOR-ALARM] Lokales Passwort '$($PwdCred.DisplayName)' auf Multi-Tenant Service Principal gefunden (KeyId: $($PwdCred.KeyId))!")
                    $ReasonsEN.Add("[BACKDOOR ALERT] Local password '$($PwdCred.DisplayName)' found directly on Multi-Tenant Service Principal (KeyId: $($PwdCred.KeyId))!")
                }
                if ($AgeDays -le 14) {
                    $CredColor = 'Red'
                    $ReasonsDE.Add("[FRISCHES PASSWORT] Secret '$($PwdCred.DisplayName)' wurde erst vor $AgeDays Tagen hinzugefügt (Prüfung auf Persistence-Backdoor erforderlich!).")
                    $ReasonsEN.Add("[RECENT PASSWORD] Secret '$($PwdCred.DisplayName)' was added only $AgeDays days ago (Verify against persistence backdoor!).")
                }
                if ($TotalDays -gt 730) {
                    $CredColor = 'Red'
                    $ReasonsDE.Add("[ÜBERLANGE LAUFZEIT] Passwort '$($PwdCred.DisplayName)' hat eine Gültigkeit von $TotalDays Tagen (> 2 Jahre).")
                    $ReasonsEN.Add("[EXCESSIVE LIFETIME] Password '$($PwdCred.DisplayName)' has a validity of $TotalDays days (> 2 years).")
                }
                elseif ($TotalDays -gt 365 -and $CredColor -ne 'Red') {
                    $CredColor = 'Orange'
                    $ReasonsDE.Add("[LAUFZEIT-WARNUNG] Passwort '$($PwdCred.DisplayName)' ist länger als 1 Jahr gültig ($TotalDays Tage).")
                    $ReasonsEN.Add("[LIFETIME WARNING] Password '$($PwdCred.DisplayName)' is valid for more than 1 year ($TotalDays days).")
                }
                if ($RemainingDays -le 0 -and $CredColor -ne 'Red') {
                    $CredColor = 'Orange'
                    $ReasonsDE.Add("[ABGELAUFENES PASSWORT] Secret '$($PwdCred.DisplayName)' ist abgelaufen und sollte entfernt werden.")
                    $ReasonsEN.Add("[EXPIRED PASSWORD] Secret '$($PwdCred.DisplayName)' is expired and should be removed.")
                }

                $CredNotesDE.Add("Secret: $($PwdCred.DisplayName) ($($PwdCred.SourceObject), $TotalDays Tage)")
                $CredNotesEN.Add("Secret: $($PwdCred.DisplayName) ($($PwdCred.SourceObject), $TotalDays days)")

                if ($PwdCred.SourceObject -eq 'ServicePrincipal') {
                    $SdkStage2Extra.Add("`n# [STAGE 2] Remove suspicious Password Credential '$($PwdCred.DisplayName)' from Service Principal:")
                    $SdkStage2Extra.Add("Remove-MgServicePrincipalPassword -ServicePrincipalId `$ServicePrincipalId -KeyId `"$($PwdCred.KeyId)`" -WhatIf")
                    $RestStage2Extra.Add("`n# [STAGE 2] Remove Password Credential '$($PwdCred.DisplayName)' from Service Principal via REST:")
                    $RestStage2Extra.Add("Invoke-MgGraphRequest -Method POST -Uri `"https://graph.microsoft.com/v1.0/servicePrincipals/`$ServicePrincipalId/removePassword`" -Body (@{ keyId = `"$($PwdCred.KeyId)`" } | ConvertTo-Json) -ContentType `"application/json`"")
                }
                elseif (-not [string]::IsNullOrWhiteSpace($App.AppRegistrationObjectId)) {
                    $SdkStage2Extra.Add("`n# [STAGE 2] Remove Password Credential '$($PwdCred.DisplayName)' from App Registration:")
                    $SdkStage2Extra.Add("Remove-MgApplicationPassword -ApplicationId `"$($App.AppRegistrationObjectId)`" -KeyId `"$($PwdCred.KeyId)`" -WhatIf")
                    $RestStage2Extra.Add("`n# [STAGE 2] Remove Password Credential '$($PwdCred.DisplayName)' from App Registration via REST:")
                    $RestStage2Extra.Add("Invoke-MgGraphRequest -Method POST -Uri `"https://graph.microsoft.com/v1.0/applications/$($App.AppRegistrationObjectId)/removePassword`" -Body (@{ keyId = `"$($PwdCred.KeyId)`" } | ConvertTo-Json) -ContentType `"application/json`"")
                }
            }
            foreach ($Cert in @($App.KeyCredentials)) {
                $CredNotesDE.Add("Zertifikat: $($Cert.DisplayName)")
                $CredNotesEN.Add("Certificate: $($Cert.DisplayName)")
            }
        }
        $CredBadgeDE = $CredNotesDE -join ' | '
        $CredBadgeEN = $CredNotesEN -join ' | '

        # ---------------------------------------------------------------------
        # Dimension 6: Publisher Verification & User Assignment Governance
        # ---------------------------------------------------------------------
        $GovColor = 'Green'
        $IsVerified = -not [string]::IsNullOrWhiteSpace($App.VerifiedPublisher)
        $PubLabelDE = if ($IsVerified) { "✔ Verifiziert ($($App.VerifiedPublisher))" } else { '⚠ Unverifiziert' }
        $PubLabelEN = if ($IsVerified) { "✔ Verified ($($App.VerifiedPublisher))" } else { '⚠ Unverified' }

        if (-not $IsVerified) {
            if ($PermColor -eq 'Red' -or $EscColor -eq 'Red' -or $RoleColor -eq 'Red') {
                $GovColor = 'Red'
                $ReasonsDE.Add("[UNVERIFIZIERTER HERAUSGEBER] App hat keinen verifizierten Publisher, besitzt aber kritische Berechtigungen!")
                $ReasonsEN.Add("[UNVERIFIED PUBLISHER] App has no verified publisher while holding critical permissions!")
            }
            else {
                $GovColor = 'Orange'
                $ReasonsDE.Add("[UNVERIFIZIERTER HERAUSGEBER] Publisher '$($App.PublisherName)' ist nicht in Entra ID verifiziert.")
                $ReasonsEN.Add("[UNVERIFIED PUBLISHER] Publisher '$($App.PublisherName)' is not verified in Entra ID.")
            }
        }
        if (-not $App.AppRoleAssignmentRequired -and $GovColor -eq 'Green' -and ($PermColor -ne 'Green' -or $EscColor -ne 'Green')) {
            $GovColor = 'Orange'
            $ReasonsDE.Add("[OFFENE BENUTZERZUWEISUNG] appRoleAssignmentRequired = false (Jeder Benutzer im Tenant kann sich an der App anmelden).")
            $ReasonsEN.Add("[OPEN USER ASSIGNMENT] appRoleAssignmentRequired = false (Any user in the tenant can sign into this app).")
        }

        if ($SdkStage2Extra.Count -eq 0) {
            $SdkStage2Extra.Add("`n# [STAGE 2] No active Entra Directory Roles or local Password Credentials found on this app.")
            $RestStage2Extra.Add("`n# [STAGE 2] No active Entra Directory Roles or local Password Credentials found on this app.")
        }
        if ($SdkStage3Extra.Count -eq 0) {
            $SdkStage3Extra.Add("`n# [STAGE 3] No Application Permissions or Delegated OAuth2 Grants found on this app.")
            $RestStage3Extra.Add("`n# [STAGE 3] No Application Permissions or Delegated OAuth2 Grants found on this app.")
        }

        $StateTxtDE  = if ($App.AccountEnabled) { 'Aktiv' } else { 'Deaktiviert' }
        $StateTxtEN  = if ($App.AccountEnabled) { 'Enabled' } else { 'Disabled' }
        $AssignTxtDE = if ($App.AppRoleAssignmentRequired) { 'Zuweisung Pflicht' } else { 'Offen für User' }
        $AssignTxtEN = if ($App.AppRoleAssignmentRequired) { 'Assignment Req.' } else { 'Open to Users' }

        $GovBadgeDE = "$PubLabelDE | $StateTxtDE | $AssignTxtDE"
        $GovBadgeEN = "$PubLabelEN | $StateTxtEN | $AssignTxtEN"

        # ---------------------------------------------------------------------
        # Overall App Traffic-Light Color (Highest severity wins, unless disabled)
        # ---------------------------------------------------------------------
        $AllDimColors = @($IocColor, $EscColor, $RoleColor, $PermColor, $CredColor, $GovColor)
        $OverallColor = 'Green'
        if ($AllDimColors -contains 'Red') {
            $OverallColor = 'Red'
        }
        elseif ($AllDimColors -contains 'Orange') {
            $OverallColor = 'Orange'
        }

        # If the app is already disabled (accountEnabled = false) and had no active secrets/roles, cap at Orange so admins see containment worked
        if (-not $App.AccountEnabled -and $OverallColor -eq 'Red' -and $RoleColor -ne 'Red' -and $CredColor -ne 'Red') {
            $OverallColor = 'Orange'
        }

        if ($ReasonsDE.Count -eq 0) {
            $ReasonsDE.Add('Alle Sicherheitsprüfungen bestanden (Least Privilege, Zertifikats-Auth, Verifizierter Herausgeber & Benutzerzuweisung aktiv).')
            $ReasonsEN.Add('All security checks passed (Least Privilege, Certificate Auth, Verified Publisher & User Assignment enforced).')
        }

        $FullAppRolesList = [System.Collections.Generic.List[object]]::new()
        foreach ($Ara in @($App.AppRoleAssignments)) {
            $PVal = $Ara.Permission
            $PLow = $PVal.ToLowerInvariant()
            $PSev = 'Green'
            $PReasonDE = 'Standard Application Permission'
            $PReasonEN = 'Standard Application Permission'
            if ($EscalationMap.ContainsKey($PLow)) {
                $PSev = $EscalationMap[$PLow].severity
                $PReasonDE = $EscalationMap[$PLow].reasonDE
                $PReasonEN = $EscalationMap[$PLow].reasonEN
            }
            elseif ($HighDataMap.ContainsKey($PLow)) {
                $PSev = 'Red'
                $PReasonDE = $HighDataMap[$PLow].reasonDE
                $PReasonEN = $HighDataMap[$PLow].reasonEN
            }
            elseif ($MedDataMap.ContainsKey($PLow)) {
                $PSev = 'Orange'
                $PReasonDE = $MedDataMap[$PLow].reasonDE
                $PReasonEN = $MedDataMap[$PLow].reasonEN
            }
            $FullAppRolesList.Add([PSCustomObject]@{
                Id           = $Ara.Id
                Permission   = $PVal
                ResourceName = if ($Ara.ResourceName) { $Ara.ResourceName } else { 'Microsoft Graph / API' }
                Severity     = $PSev
                ReasonDE     = $PReasonDE
                ReasonEN     = $PReasonEN
            })
        }

        $FullDelegatedList = [System.Collections.Generic.List[object]]::new()
        foreach ($Dg in @($App.DelegatedGrants)) {
            $Scopes = ($Dg.Scope -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($S in $Scopes) {
                $SLow = $S.ToLowerInvariant()
                $SSev = 'Green'
                if ($EscalationMap.ContainsKey($SLow) -or $HighDataMap.ContainsKey($SLow)) {
                    $SSev = if ($Dg.ConsentType -eq 'AllPrincipals') { 'Red' } else { 'Orange' }
                }
                elseif ($MedDataMap.ContainsKey($SLow)) {
                    $SSev = 'Orange'
                }
                $FullDelegatedList.Add([PSCustomObject]@{
                    GrantId     = $Dg.Id
                    Scope       = $S
                    ConsentType = $Dg.ConsentType
                    Severity    = $SSev
                })
            }
        }

        $AppFooterSdk = @(
            "",
            "if (`$?) {",
            "    Write-Host `"[SIMULATION / -WhatIf] Dry-run completed! Nothing was changed in Entra ID yet. Uncheck '-WhatIf Schutz aktiv' in the report before copying/downloading to apply for real.`" -ForegroundColor Yellow",
            "    `$VerifyUri = `"https://graph.microsoft.com/v1.0/servicePrincipals/`$(`$ServicePrincipalId)?```$select=displayName,accountEnabled,appRoleAssignmentRequired`"",
            "    `$VerifySp = Invoke-MgGraphRequest -Method GET -Uri `$VerifyUri -ErrorAction SilentlyContinue",
            "    if (`$null -ne `$VerifySp) {",
            "        Write-Host `"[CURRENT LIVE STATE] App: `$(`$VerifySp.displayName) | accountEnabled: `$(`$VerifySp.accountEnabled) | appRoleAssignmentRequired: `$(`$VerifySp.appRoleAssignmentRequired)`" -ForegroundColor Cyan",
            "    }",
            "}"
        )
        $AppFooterRest = @(
            "",
            "Write-Host `"[SUCCESS] REST Lockdown operation completed! Verifying current live state in Entra ID:`" -ForegroundColor Green",
            "`$VerifyUri = `"https://graph.microsoft.com/v1.0/servicePrincipals/`$(`$ServicePrincipalId)?```$select=displayName,accountEnabled,appRoleAssignmentRequired`"",
            "`$VerifySp = Invoke-MgGraphRequest -Method GET -Uri `$VerifyUri -ErrorAction SilentlyContinue",
            "if (`$null -ne `$VerifySp) {",
            "    Write-Host `"[CURRENT LIVE STATE] App: `$(`$VerifySp.displayName) | accountEnabled: `$(`$VerifySp.accountEnabled) | appRoleAssignmentRequired: `$(`$VerifySp.appRoleAssignmentRequired)`" -ForegroundColor Cyan",
            "}"
        )

        $SdkStage1Str  = (($SdkStage1 + $AppFooterSdk) -join "`n")
        $SdkStage2Str  = (($SdkStage1 + $SdkStage2Extra + $AppFooterSdk) -join "`n")
        $SdkStage3Str  = (($SdkStage1 + $SdkStage2Extra + $SdkStage3Extra + $AppFooterSdk) -join "`n")
        $RestStage1Str = (($RestStage1 + $AppFooterRest) -join "`n")
        $RestStage2Str = (($RestStage1 + $RestStage2Extra + $AppFooterRest) -join "`n")
        $RestStage3Str = (($RestStage1 + $RestStage2Extra + $RestStage3Extra + $AppFooterRest) -join "`n")

        $SpObjKey  = if (-not [string]::IsNullOrWhiteSpace($App.ObjectId)) { ([string]$App.ObjectId).ToLowerInvariant() } else { '' }
        $AppRegKey = if (-not [string]::IsNullOrWhiteSpace($App.AppRegistrationObjectId)) { ([string]$App.AppRegistrationObjectId).ToLowerInvariant() } else { '' }
        $AppAud = $null
        if ($SpObjKey -and $AppAuditByTargetId.ContainsKey($SpObjKey)) {
            $AppAud = $AppAuditByTargetId[$SpObjKey]
        }
        elseif ($AppRegKey -and $AppAuditByTargetId.ContainsKey($AppRegKey)) {
            $AppAud = $AppAuditByTargetId[$AppRegKey]
        }
        elseif ($AppIdLower -and $AppAuditByTargetId.ContainsKey($AppIdLower)) {
            $AppAud = $AppAuditByTargetId[$AppIdLower]
        }
        $AppLastModDE = if ($null -ne $AppAud) { $AppAud.BadgeDE } elseif ($App.CreatedDateTime) { "Erstellt am: $($App.CreatedDateTime) (Keine jüngste Audit-Änderung)" } else { 'Keine jüngste Audit-Änderung' }
        $AppLastModEN = if ($null -ne $AppAud) { $AppAud.BadgeEN } elseif ($App.CreatedDateTime) { "Created: $($App.CreatedDateTime) (No recent audit change)" } else { 'No recent audit change' }

        $AppFindings.Add([PSCustomObject]@{
            ObjectId                  = $App.ObjectId
            AppRegistrationObjectId   = $App.AppRegistrationObjectId
            AppId                     = $App.AppId
            DisplayName               = $App.DisplayName
            ServicePrincipalType      = $App.ServicePrincipalType
            CreatedDateTime           = $App.CreatedDateTime
            LastModifiedDE            = $AppLastModDE
            LastModifiedEN            = $AppLastModEN
            AppRoleAssignmentRequired = $App.AppRoleAssignmentRequired
            PublisherName             = if ($App.VerifiedPublisher) { "✔ $($App.VerifiedPublisher)" } elseif ($App.PublisherName) { "⚠ $($App.PublisherName) (Unverified)" } else { '⚠ Unverified / Custom' }
            SignInAudience            = $App.SignInAudience
            AccountEnabled            = $App.AccountEnabled
            OverallColor              = $OverallColor
            IocColor                  = $IocColor
            IocBadgeDE                = $IocBadgeDE
            IocBadgeEN                = $IocBadgeEN
            IsThreatIntelMatch        = $IsThreatIntelMatch
            ThreatCategory            = $ThreatCategory
            ThreatCampaign            = $ThreatCampaign
            ThreatDescriptionDE       = $ThreatDescriptionDE
            ThreatDescriptionEN       = $ThreatDescriptionEN
            RecommendationDE          = $RecommendationDE
            RecommendationEN          = $RecommendationEN
            ThreatReferences          = $ThreatReferences
            EscColor                  = $EscColor
            EscBadgeDE                = $EscBadgeDE
            EscBadgeEN                = $EscBadgeEN
            RoleColor                 = $RoleColor
            RoleBadgeDE               = $RoleBadgeDE
            RoleBadgeEN               = $RoleBadgeEN
            PermColor                 = $PermColor
            PermBadgeDE               = $PermBadgeDE
            PermBadgeEN               = $PermBadgeEN
            CredColor                 = $CredColor
            CredBadgeDE               = $CredBadgeDE
            CredBadgeEN               = $CredBadgeEN
            GovColor                  = $GovColor
            GovBadgeDE                = $GovBadgeDE
            GovBadgeEN                = $GovBadgeEN
            ReasonsDE                 = $ReasonsDE.ToArray()
            ReasonsEN                 = $ReasonsEN.ToArray()
            FullDirectoryRoles        = @($App.DirectoryRoles)
            FullAppRoleAssignments    = $FullAppRolesList.ToArray()
            FullDelegatedScopes       = $FullDelegatedList.ToArray()
            FullPasswordCredentials   = @($App.PasswordCredentials)
            FullKeyCredentials        = @($App.KeyCredentials)
            Compliance                = 'NIS2 Art. 21(2)d | DORA Art. 9 & 28 | ISO 27001 A.5.15/A.5.19 | CIS M365 5.1'
            LockdownSdk               = $SdkStage1Str
            LockdownSdkStage1         = $SdkStage1Str
            LockdownSdkStage2         = $SdkStage2Str
            LockdownSdkStage3         = $SdkStage3Str
            LockdownRest              = $RestStage1Str
            LockdownRestStage1        = $RestStage1Str
            LockdownRestStage2        = $RestStage2Str
            LockdownRestStage3        = $RestStage3Str
        })
    }

    # Build full 24-Month Threat Intelligence Watchlist status (Found vs. Not Found in Tenant)
    $AppFindingIdxByAppId = @{}
    for ($i = 0; $i -lt $AppFindings.Count; $i++) {
        $AidKey = ([string]$AppFindings[$i].AppId).ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($AidKey) -and -not $AppFindingIdxByAppId.ContainsKey($AidKey)) {
            $AppFindingIdxByAppId[$AidKey] = $i
        }
    }

    $ThreatWatchlistFindings = [System.Collections.Generic.List[object]]::new()
    foreach ($Ioc in $IocConfig.compromisedApps) {
        $Key = ([string]$Ioc.appId).ToLowerInvariant()
        $Refs = @(if ($null -ne $Ioc.references) { $Ioc.references } else { @() })
        if ($AppFindingIdxByAppId.ContainsKey($Key)) {
            $Idx = $AppFindingIdxByAppId[$Key]
            $MatchedApp = $AppFindings[$Idx]
            $StatusColor = if ($MatchedApp.IocColor -eq 'Red' -or $MatchedApp.OverallColor -eq 'Red') { 'Red' } elseif ($MatchedApp.IocColor -eq 'Orange' -or $MatchedApp.OverallColor -eq 'Orange') { 'Orange' } else { 'Green' }
            $StateBadgeDE = if (-not $MatchedApp.AccountEnabled) { 'IM TENANT (Deaktiviert)' } elseif ($StatusColor -eq 'Green') { 'IM TENANT (Gehärtet)' } else { 'IM TENANT GEFUNDEN!' }
            $StateBadgeEN = if (-not $MatchedApp.AccountEnabled) { 'IN TENANT (Disabled)' } elseif ($StatusColor -eq 'Green') { 'IN TENANT (Hardened)' } else { 'FOUND IN TENANT!' }
            $ThreatWatchlistFindings.Add([PSCustomObject]@{
                FoundInTenant       = $true
                AppIndex            = $Idx
                StatusColor         = $StatusColor
                StateBadgeDE        = $StateBadgeDE
                StateBadgeEN        = $StateBadgeEN
                AppId               = $MatchedApp.AppId
                DisplayName         = $MatchedApp.DisplayName
                Vendor              = $MatchedApp.PublisherName
                LastModifiedDE      = $MatchedApp.LastModifiedDE
                LastModifiedEN      = $MatchedApp.LastModifiedEN
                ThreatCategory      = [string]$Ioc.category
                ThreatCampaign      = [string]$Ioc.campaign
                ThreatDescriptionDE = [string]$Ioc.descriptionDE
                ThreatDescriptionEN = [string]$Ioc.descriptionEN
                RecommendationDE    = [string]$Ioc.recommendationDE
                RecommendationEN    = [string]$Ioc.recommendationEN
                ThreatReferences    = $Refs
                OverallColor        = $MatchedApp.OverallColor
            })
        }
        else {
            $ThreatWatchlistFindings.Add([PSCustomObject]@{
                FoundInTenant       = $false
                AppIndex            = -1
                StatusColor         = 'Green'
                StateBadgeDE        = 'NICHT IM TENANT'
                StateBadgeEN        = 'NOT IN TENANT'
                AppId               = [string]$Ioc.appId
                DisplayName         = [string]$Ioc.name
                Vendor              = [string]$Ioc.vendor
                ThreatCategory      = [string]$Ioc.category
                ThreatCampaign      = [string]$Ioc.campaign
                ThreatDescriptionDE = [string]$Ioc.descriptionDE
                ThreatDescriptionEN = [string]$Ioc.descriptionEN
                RecommendationDE    = 'Kein Handlungsbedarf: Diese bekannte Risiko-App ist in Ihrem Entra ID Tenant nicht registriert.'
                RecommendationEN    = 'No action required: This known risk app is not registered in your Entra ID tenant.'
                ThreatReferences    = $Refs
                OverallColor        = 'Green'
            })
        }
    }

    # Summary KPI calculation
    $Summary = [PSCustomObject]@{
        TenantId            = $RealTenantId
        TenantName          = $RealTenantName
        ScanTimestampUtc    = $Now.ToString('yyyy-MM-dd HH:mm:ss UTC')
        TenantPoliciesRed   = @($TenantFindings | Where-Object { $_.Color -eq 'Red' }).Count
        TenantPoliciesOrange = @($TenantFindings | Where-Object { $_.Color -eq 'Orange' }).Count
        TenantPoliciesGreen = @($TenantFindings | Where-Object { $_.Color -eq 'Green' }).Count
        AppsTotal           = $AppFindings.Count
        AppsRed             = @($AppFindings | Where-Object { $_.OverallColor -eq 'Red' }).Count
        AppsOrange          = @($AppFindings | Where-Object { $_.OverallColor -eq 'Orange' }).Count
        AppsGreen           = @($AppFindings | Where-Object { $_.OverallColor -eq 'Green' }).Count
        ActiveIocMatches    = @($AppFindings | Where-Object { $_.IocColor -eq 'Red' }).Count
        AppsCanAddPasswords = @($AppFindings | Where-Object { $_.EscColor -in @('Red', 'Orange') }).Count
        WatchlistTotal      = $ThreatWatchlistFindings.Count
        WatchlistFound      = @($ThreatWatchlistFindings | Where-Object { $_.FoundInTenant }).Count
    }

    return [PSCustomObject]@{
        Summary         = $Summary
        TenantPolicies  = $TenantFindings.ToArray()
        ThreatWatchlist = $ThreatWatchlistFindings.ToArray()
        Applications    = $AppFindings.ToArray()
    }
}


