@{
    RootModule        = 'AppSentry.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'a4f8b921-6c4e-4d8a-9b12-8e73c1f509a2'
    Author            = 'AppSentry for M365 Open Source Contributors'
    CompanyName       = 'Security & Compliance Pro (https://www.security-and-compliance.pro)'
    Copyright         = '(c) 2026 AppSentry for M365 Contributors. MIT License.'
    Description       = 'AppSentry for M365: Bilingual (DE/EN) read-only security scanner for Microsoft Entra ID / M365 Enterprise Applications, App Registrations, 24-Month Threat Intelligence Watchlist, and Tenant App Protection Policies (T-01..T-14) with 3-Stage Lockdown Playbooks.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Invoke-AppSentry',
        'Get-M365TenantAppPolicies',
        'Get-M365AppInventory',
        'Measure-M365AppRisk',
        'Export-AppSentryReport'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @(
        'Invoke-M365AppGuard',
        'Export-M365AppGuardReport'
    )
    PrivateData       = @{
        PSData = @{
            Tags       = @('AppSentry', 'Microsoft365', 'EntraID', 'Security', 'OAuth', 'SupplyChain', 'Lockdown', 'GraphAPI', 'Compliance', 'NIS2', 'DORA')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/MKN1411/AppSentry-for-M365'
        }
    }
}

