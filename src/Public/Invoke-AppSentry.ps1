function Invoke-AppSentry {
    <#
    .SYNOPSIS
        Runs the complete AppSentry for M365 Read-Only Security Assessment for Tenant App Policies (T-01..T-14) and Enterprise Applications / App Registrations.
    .DESCRIPTION
        Displays color-coded results (Red, Orange, Green) in the PowerShell console (bilingual DE/EN) and generates the interactive HTML dashboard with a per-row Lockdown button.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Intentional interactive ANSI color-coded traffic light console report.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('DE', 'EN')]
        [string]$Language = 'DE',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'GraphSDK', 'REST')]
        [string]$ConnectionMethod = 'Auto',

        [Parameter(Mandatory = $false)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$ExcludeMicrosoftFirstParty,

        [Parameter(Mandatory = $false)]
        [switch]$DemoMode,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'output'),

        [Parameter(Mandatory = $false)]
        [switch]$NoOpenReport,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    if (-not $DemoMode -and $ConnectionMethod -ne 'REST' -and [string]::IsNullOrWhiteSpace($AccessToken)) {
        $Ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -eq $Ctx) {
            Connect-MgGraph -Scopes @(
                'Application.Read.All',
                'Policy.Read.All',
                'Directory.Read.All',
                'RoleManagement.Read.Directory',
                'AuditLog.Read.All'
            ) -NoWelcome -ErrorAction Stop
        }
    }

    $TenantRaw = Get-M365TenantAppPolicies -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken -DemoMode:$DemoMode
    $AppsRaw   = @(Get-M365AppInventory -ConnectionMethod $ConnectionMethod -AccessToken $AccessToken -ExcludeMicrosoftFirstParty:$ExcludeMicrosoftFirstParty -DemoMode:$DemoMode)
    $Result    = Measure-M365AppRisk -TenantPoliciesRaw $TenantRaw -AppsRaw $AppsRaw
    $Exports   = Export-AppSentryReport -AssessmentResult $Result -Language $Language -OutputPath $OutputPath

    if (-not $Quiet) {
        $Esc = [char]27
        $ClrRed    = "$Esc[91m"
        $ClrOrange = "$Esc[93m"
        $ClrGreen  = "$Esc[92m"
        $ClrCyan   = "$Esc[96m"
        $ClrReset  = "$Esc[0m"

        Write-Host ""
        Write-Host "$ClrCyan====================================================================================================$ClrReset"
        if ($Language -eq 'DE') {
            Write-Host "$ClrCyan 🛡️  AppSentry für M365 | Entra ID App & Supply-Chain Sicherheitsanalyse (100% Read-Only)$ClrReset"
            Write-Host "    Tenant: $($Result.Summary.TenantName) ($($Result.Summary.TenantId))"
        }
        else {
            Write-Host "$ClrCyan 🛡️  AppSentry for M365 | Entra ID App & Supply-Chain Security Scanner (100% Read-Only)$ClrReset"
            Write-Host "    Tenant: $($Result.Summary.TenantName) ($($Result.Summary.TenantId))"
        }
        Write-Host "$ClrCyan====================================================================================================$ClrReset"
        Write-Host ""

        if ($Language -eq 'DE') {
            Write-Host "--- [1] GLOBALE TENANT APP-SCHUTZEINSTELLUNGEN (T-01 bis T-14) ---"
        }
        else {
            Write-Host "--- [1] GLOBAL TENANT APP PROTECTION SETTINGS (T-01 to T-14) ---"
        }

        foreach ($Pol in $Result.TenantPolicies) {
            $C = switch ($Pol.Color) {
                'Red'    { $ClrRed }
                'Orange' { $ClrOrange }
                default  { $ClrGreen }
            }
            $Tag = switch ($Pol.Color) {
                'Red'    { '[🔴 ROT   ]' }
                'Orange' { '[🟠 ORANGE]' }
                default  { '[🟢 GRÜN  ]' }
            }
            if ($Language -eq 'EN') {
                $Tag = switch ($Pol.Color) {
                    'Red'    { '[🔴 RED   ]' }
                    'Orange' { '[🟠 ORANGE]' }
                    default  { '[🟢 GREEN ]' }
                }
            }
            $Name = if ($Language -eq 'DE') { $Pol.NameDE } else { $Pol.NameEN }
            $Curr = if ($Language -eq 'DE') { $Pol.CurrentDE } else { $Pol.CurrentEN }
            $Mod  = if ($Language -eq 'DE') { $Pol.LastModifiedDE } else { $Pol.LastModifiedEN }
            $BtnHint = if ($Pol.Color -eq 'Green') { '[✅ Konform]' } else { '[⚙️ Soll-Wert setzen]' }
            if ($Language -eq 'EN') {
                $BtnHint = if ($Pol.Color -eq 'Green') { '[✅ Compliant]' } else { '[⚙️ Apply Recommended]' }
            }
            Write-Host "$C$Tag $($Pol.Id) - $Name : $Curr $ClrReset $BtnHint"
            if (-not [string]::IsNullOrWhiteSpace($Mod) -and $Mod -notmatch 'Keine aktuelle|No recent') {
                Write-Host "            🕒 $Mod"
            }
        }

        Write-Host ""
        if ($Language -eq 'DE') {
            Write-Host "--- [2] 🚨 AKTIVER ANGRIFFSFOKUS & BEKANNTE RISIKO-APPS (24-MONATS-WATCHLIST: GEFUNDEN & NEGATIVNACHWEIS) ---"
        }
        else {
            Write-Host "--- [2] 🚨 ACTIVE ATTACK FOCUS & KNOWN RISK APPS (24-MONTH WATCHLIST: FOUND & NEGATIVE AUDIT PROOF) ---"
        }

        foreach ($WItem in @($Result.ThreatWatchlist)) {
            if ($WItem.FoundInTenant) {
                $TC = if ($WItem.StatusColor -eq 'Red') { $ClrRed } elseif ($WItem.StatusColor -eq 'Orange') { $ClrOrange } else { $ClrGreen }
                $TTag = if ($WItem.StatusColor -eq 'Red') {
                    if ($Language -eq 'DE') { '[🔴 IM TENANT]' } else { '[🔴 IN TENANT]' }
                }
                else {
                    if ($Language -eq 'DE') { '[🟠 IM TENANT]' } else { '[🟠 IN TENANT]' }
                }
                $TRec = if ($Language -eq 'DE') { $WItem.RecommendationDE } else { $WItem.RecommendationEN }
                $TRefUrls = @(if ($null -ne $WItem.ThreatReferences) { $WItem.ThreatReferences | ForEach-Object { $_.url } }) -join ' | '
                Write-Host "$TC$TTag [$($WItem.ThreatCategory)] $($WItem.DisplayName) (AppId: $($WItem.AppId)) - $($WItem.ThreatCampaign)$ClrReset"
                Write-Host "            💡 Empfehlung: $TRec"
                if (-not [string]::IsNullOrWhiteSpace($TRefUrls)) {
                    Write-Host "            🔗 Quellen   : $TRefUrls"
                }
            }
            else {
                $NTag = if ($Language -eq 'DE') { '[🟢 NICHT IM TENANT]' } else { '[🟢 NOT IN TENANT ]' }
                $NRefUrls = @(if ($null -ne $WItem.ThreatReferences) { $WItem.ThreatReferences | ForEach-Object { $_.url } }) -join ' | '
                Write-Host "$ClrGreen$NTag [$($WItem.ThreatCategory)] $($WItem.DisplayName) (AppId: $($WItem.AppId)) - $($WItem.ThreatCampaign)$ClrReset"
                if (-not [string]::IsNullOrWhiteSpace($NRefUrls)) {
                    Write-Host "                  🔗 Quellen: $NRefUrls"
                }
            }
        }

        Write-Host ""
        if ($Language -eq 'DE') {
            Write-Host "--- [3] VOLLSTÄNDIGES APP-INVENTAR & ALLGEMEINE GEFAHRENANALYSE (ALLE APPS INKL. BLOCK 2) ---"
        }
        else {
            Write-Host "--- [3] FULL APP INVENTORY & GENERAL RISK ASSESSMENT (ALL APPS INCL. BLOCK 2) ---"
        }

        foreach ($App in $Result.Applications) {
            $C = switch ($App.OverallColor) {
                'Red'    { $ClrRed }
                'Orange' { $ClrOrange }
                default  { $ClrGreen }
            }
            $Tag = switch ($App.OverallColor) {
                'Red'    { '[🔴 ROT   ]' }
                'Orange' { '[🟠 ORANGE]' }
                default  { '[🟢 GRÜN  ]' }
            }
            if ($Language -eq 'EN') {
                $Tag = switch ($App.OverallColor) {
                    'Red'    { '[🔴 RED   ]' }
                    'Orange' { '[🟠 ORANGE]' }
                    default  { '[🟢 GREEN ]' }
                }
            }
            $EscTxt  = if ($Language -eq 'DE') { $App.EscBadgeDE } else { $App.EscBadgeEN }
            $CredTxt = if ($Language -eq 'DE') { $App.CredBadgeDE } else { $App.CredBadgeEN }
            Write-Host "$C$Tag $($App.DisplayName) (AppId: $($App.AppId))$ClrReset [🔒 Lockdown Ready]"
            Write-Host "            IOC: [$($App.IocColor)] | Passwort/Rollen-Macht: [$($App.EscColor)] $EscTxt | Secrets: [$($App.CredColor)] $CredTxt"
        }

        Write-Host ""
        Write-Host "$ClrCyan----------------------------------------------------------------------------------------------------$ClrReset"
        Write-Host " 📊 HTML Dashboard (DE/EN + [🔒 Lockdown] Button): $($Exports.HtmlReportPath)"
        Write-Host " 📄 JSON Export                                  : $($Exports.JsonReportPath)"
        Write-Host " 📑 CSV Export                                   : $($Exports.CsvReportPath)"
        Write-Host "$ClrCyan----------------------------------------------------------------------------------------------------$ClrReset"

        if (-not $NoOpenReport -and (Test-Path -Path $Exports.HtmlReportPath)) {
            try {
                Invoke-Item -Path $Exports.HtmlReportPath -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose "Could not auto-open HTML report: $_"
            }
        }
    }

    return [PSCustomObject]@{
        Assessment = $Result
        Exports    = $Exports
    }
}

Set-Alias -Name Invoke-M365AppGuard -Value Invoke-AppSentry

