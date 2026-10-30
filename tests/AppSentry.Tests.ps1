#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\AppSentry.psd1'
    Import-Module -Name $ModulePath -Force
}

Describe 'AppSentry for M365 Security & Risk Engine (Pester v5)' {

    Context '1. Global Tenant App Protection Policies (T-01 to T-14)' {
        BeforeAll {
            $Script:RunResult = Invoke-AppSentry -DemoMode -Language DE -Quiet
            $Script:Policies  = $Script:RunResult.Assessment.TenantPolicies
        }

        It 'Evaluates all 14 Global Tenant App Protection Settings (T-01 through T-14)' {
            $Script:Policies.Count | Should -Be 14
            ($Script:Policies.Id -join ',') | Should -Be 'T-01,T-02,T-03,T-04,T-05,T-06,T-07,T-08,T-09,T-10,T-11,T-12,T-13,T-14'
        }

        It 'Flags open User Consent (T-01) and Group Owner Consent (T-02) as Red' {
            ($Script:Policies | Where-Object Id -EQ 'T-01').Color | Should -Be 'Red'
            ($Script:Policies | Where-Object Id -EQ 'T-02').Color | Should -Be 'Red'
        }

        It 'Flags allowedToCreateApps = true (T-03) as Red' {
            ($Script:Policies | Where-Object Id -EQ 'T-03').Color | Should -Be 'Red'
        }

        It 'Checks whether Apps (T-07) and Service Principals (T-08) can add passwords (defaultAppManagementPolicy)' {
            $T07 = $Script:Policies | Where-Object Id -EQ 'T-07'
            $T08 = $Script:Policies | Where-Object Id -EQ 'T-08'
            $T07.Color | Should -Be 'Red'
            $T08.Color | Should -Be 'Red'
            $T07.LockdownSdk  | Should -Match 'passwordAddition'
            $T08.LockdownRest | Should -Match 'servicePrincipalRestrictions'
        }

        It 'Generates both Graph SDK and REST API Lockdown Playbooks and Audit Metadata (LastModifiedDE) for every Tenant Policy row' {
            foreach ($Pol in $Script:Policies) {
                $Pol.LockdownSdk    | Should -Not -BeNullOrEmpty
                $Pol.LockdownRest   | Should -Not -BeNullOrEmpty
                $Pol.LastModifiedDE | Should -Not -BeNullOrEmpty
                if ($Pol.Id -ne 'T-14') {
                    $Pol.LockdownSdk  | Should -Match '-BodyParameter'
                    $Pol.LockdownSdk  | Should -Match '-WhatIf'
                    $Pol.LockdownSdk  | Should -Match '\[CURRENT LIVE STATE\]'
                    $Pol.LockdownRest | Should -Match '\[CURRENT LIVE STATE\]'
                }
            }
            $T13 = $Script:Policies | Where-Object Id -EQ 'T-13'
            $T13.LastModifiedDE | Should -Match 'Zuletzt geändert am:.*Von: secadmin@contoso\.de \(GUID: a1b2c3d4-'
        }
    }

    Context '2. Application Risk Scoring (Red / Orange / Green) & IOC Detection' {
        BeforeAll {
            $Script:Apps = $Script:RunResult.Assessment.Applications
        }

        It 'Detects active ConnectWise Cloud Backup (SkyKick) IOC (506e08f9-6e9a-4da4-942b-a099a03644ae) as Red' {
            $CwBackup = $Script:Apps | Where-Object AppId -EQ '506e08f9-6e9a-4da4-942b-a099a03644ae'
            $CwBackup | Should -Not -BeNullOrEmpty
            $CwBackup.OverallColor | Should -Be 'Red'
            $CwBackup.IocColor     | Should -Be 'Red'
            $CwBackup.CredColor    | Should -Be 'Red'
        }

        It 'Detects apps capable of adding passwords to other apps or self-granting roles (Application.ReadWrite.All / RoleManagement.ReadWrite.Directory) as Red' {
            $CwTeams = $Script:Apps | Where-Object AppId -EQ '24205314-2b89-4e07-a2a4-579e898a5640'
            $CwTeams.EscColor  | Should -Be 'Red'
            $CwTeams.RoleColor | Should -Be 'Red'
            $CwTeams.EscBadgeDE | Should -Match 'Application\.ReadWrite\.All'
        }

        It 'Classifies already disabled IOC apps without active secrets/roles as Orange (Contained)' {
            $CwContained = $Script:Apps | Where-Object AppId -EQ '2399d300-6fca-4e6a-a686-399fefe75b83'
            $CwContained.AccountEnabled | Should -BeFalse
            $CwContained.IocColor       | Should -Be 'Orange'
            $CwContained.OverallColor   | Should -Be 'Orange'
        }

        It 'Populates Threat Intelligence Watchlist metadata (IsThreatIntelMatch, RecommendationDE, ThreatReferences) including LotL Admin CLIs and full 23-App Watchlist Audit (Found vs Not Found)' {
            $CwBackup = $Script:Apps | Where-Object AppId -EQ '506e08f9-6e9a-4da4-942b-a099a03644ae'
            $CwBackup.IsThreatIntelMatch | Should -BeTrue
            $CwBackup.ThreatCategory     | Should -Be 'VendorBreach'
            $CwBackup.RecommendationDE   | Should -Not -BeNullOrEmpty
            $CwBackup.ThreatReferences.Count | Should -BeGreaterOrEqual 1

            $GraphCli = $Script:Apps | Where-Object AppId -EQ '14d82eec-204b-4c2f-b7e8-296a70dab67e'
            $GraphCli | Should -Not -BeNullOrEmpty
            $GraphCli.IsThreatIntelMatch | Should -BeTrue
            $GraphCli.ThreatCategory     | Should -Be 'LotLAdminTool'
            $GraphCli.IocColor           | Should -Be 'Orange'
            $GraphCli.RecommendationDE   | Should -Match 'appRoleAssignmentRequired'
            $GraphCli.ThreatReferences.Count | Should -BeGreaterOrEqual 1

            # Verify full 23-entry ThreatWatchlist contains both FoundInTenant = true and FoundInTenant = false (Green negative proof)
            $Watchlist = $Script:RunResult.Assessment.ThreatWatchlist
            $Watchlist.Count | Should -Be 23
            @($Watchlist | Where-Object { $_.FoundInTenant }).Count | Should -Be 4
            $NotFound = @($Watchlist | Where-Object { -not $_.FoundInTenant })
            $NotFound.Count | Should -Be 19
            $NotFound[0].StatusColor | Should -Be 'Green'
            $NotFound[0].StateBadgeDE | Should -Be 'NICHT IM TENANT'
            $NotFound[0].ThreatReferences.Count | Should -BeGreaterOrEqual 1
        }

        It 'Classifies least-privilege, certificate-based apps with verified publisher and user assignment as Green' {
            $GreenApp = $Script:Apps | Where-Object AppId -EQ '11223344-5566-4777-8899-aabbccddeeff'
            $GreenApp.OverallColor | Should -Be 'Green'
            $GreenApp.IocColor     | Should -Be 'Green'
            $GreenApp.EscColor     | Should -Be 'Green'
            $GreenApp.CredColor    | Should -Be 'Green'
            $GreenApp.GovColor     | Should -Be 'Green'
        }

        It 'Generates 3-Stage Escalation Lockdown Playbooks with Tenant Session Verification for every application' {
            foreach ($App in $Script:Apps) {
                $App.LockdownSdkStage1  | Should -Match 'Update-MgServicePrincipal'
                $App.LockdownSdkStage1  | Should -Match '\$TargetTenantId'
                $App.LockdownSdkStage1  | Should -Match 'Connect-MgGraph -TenantId \$TargetTenantId'
                $App.LockdownSdkStage1  | Should -Match '\$\(\$ServicePrincipalId\)\?`\$select='
                $App.LockdownSdkStage1  | Should -Not -Match 'Remove-MgServicePrincipalAppRoleAssignment'
                $App.LockdownRestStage1 | Should -Match 'Invoke-MgGraphRequest'
            }
            $CwTeams = $Script:Apps | Where-Object AppId -EQ '24205314-2b89-4e07-a2a4-579e898a5640'
            # Stage 1 preserves permissions & roles
            $CwTeams.LockdownSdkStage1 | Should -Not -Match 'Remove-MgDirectoryRoleMemberByRef'
            # Stage 2 removes directory roles & passwords, still preserves app permissions
            $CwTeams.LockdownSdkStage2 | Should -Match 'Remove-MgDirectoryRoleMemberByRef'
            $CwTeams.LockdownSdkStage2 | Should -Not -Match 'Remove-MgServicePrincipalAppRoleAssignment'
            # Stage 3 removes all permissions via compact array foreach loop
            $CwTeams.LockdownSdkStage3 | Should -Match 'foreach \(\$AssignmentId in \$AppRoleAssignmentIds\)'
            $CwTeams.LockdownSdkStage3 | Should -Match 'Remove-MgServicePrincipalAppRoleAssignment'
        }
    }

    Context '3. Bilingual HTML Dashboard & Report Exports (DE / EN)' {
        It 'Generates the interactive HTML report, JSON export, and CSV export' {
            $Exports = $Script:RunResult.Exports
            Test-Path -Path $Exports.HtmlReportPath | Should -BeTrue
            Test-Path -Path $Exports.JsonReportPath | Should -BeTrue
            Test-Path -Path $Exports.CsvReportPath  | Should -BeTrue

            $HtmlRaw = Get-Content -Path $Exports.HtmlReportPath -Raw -Encoding UTF8
            $HtmlRaw | Should -Match 'AppSentry for M365'
            $HtmlRaw | Should -Match '506e08f9-6e9a-4da4-942b-a099a03644ae'
            $HtmlRaw | Should -Match 'threat-focus-container'
            $HtmlRaw | Should -Match 'DossierSecThreatIntel'
            $HtmlRaw | Should -Match 'openPolicyModal'
            $HtmlRaw | Should -Match 'openAppModal'
            $HtmlRaw | Should -Match 'openPrintPreviewTab'
        }
    }

    Context '4. Live Graph API Sparse / Omitted Property Resilience (StrictMode Safety)' {
        It 'Does not throw PropertyNotFoundException or DateTime FormatException on US-formatted Graph dates (MM/dd/yyyy)' {
            Mock -ModuleName AppSentry -CommandName Invoke-AppGuardGraphQuery -MockWith {
                param($Uri)
                if ($Uri -like '*servicePrincipals*select*') {
                    return @(
                        # Managed Identity / Sparse Service Principal WITHOUT publisherName, plus US-formatted StartDateTime/EndDateTime
                        [PSCustomObject]@{
                            id                        = 'sp-sparse-1'
                            appId                     = '506e08f9-6e9a-4da4-942b-a099a03644ae'
                            displayName               = 'Sparse-ServicePrincipal-Without-PublisherName'
                            servicePrincipalType      = 'ManagedIdentity'
                            accountEnabled            = $true
                            appRoleAssignmentRequired = $false
                            passwordCredentials       = @(
                                [PSCustomObject]@{
                                    keyId         = 'key-us-date-1'
                                    displayName   = 'US-Date-Secret'
                                    startDateTime = '09/25/2026 13:11:07'
                                    endDateTime   = '09/25/2027 13:11:07'
                                }
                            )
                        }
                    )
                }
                return @()
            }

            { Get-M365AppInventory -ConnectionMethod GraphSDK } | Should -Not -Throw
            $Inv = @(Get-M365AppInventory -ConnectionMethod GraphSDK)
            $Inv.Count | Should -Be 1
            $Inv[0].DisplayName | Should -Be 'Sparse-ServicePrincipal-Without-PublisherName'
            $Inv[0].PublisherName | Should -BeNullOrEmpty

            # Also verify Get-M365TenantAppPolicies and Measure-M365AppRisk with sparse Graph objects
            $PolRaw = Get-M365TenantAppPolicies -ConnectionMethod GraphSDK
            $Risk = Measure-M365AppRisk -TenantPoliciesRaw $PolRaw -AppsRaw $Inv
            $Risk.Applications.Count | Should -Be 1
            $Risk.Applications[0].OverallColor | Should -Be 'Red'
        }
    }
}
