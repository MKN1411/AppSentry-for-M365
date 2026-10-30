function Export-AppSentryReport {
    <#
    .SYNOPSIS
        Exports the AppSentry for M365 risk assessment results into an interactive bilingual HTML dashboard, JSON file, and CSV summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$AssessmentResult,

        [Parameter(Mandatory = $false)]
        [ValidateSet('DE', 'EN')]
        [string]$Language = 'DE',

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'output')
    )

    if (-not (Test-Path -Path $OutputPath)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force
    }

    $ModuleRoot  = Split-Path -Path $PSScriptRoot -Parent
    $ProjectRoot = Split-Path -Path $ModuleRoot -Parent
    $TemplateFile = Join-Path -Path $ProjectRoot -ChildPath 'templates\report-template.html'
    $I18nFile     = Join-Path -Path $ProjectRoot -ChildPath 'config\i18n.json'

    $TemplateContent = Get-Content -Path $TemplateFile -Raw -Encoding UTF8
    $I18nContent     = Get-Content -Path $I18nFile -Raw -Encoding UTF8
    $ReportJson      = $AssessmentResult | ConvertTo-Json -Depth 10

    $HtmlCompiled = $TemplateContent.Replace('__REPORT_JSON_PLACEHOLDER__', $ReportJson)
    $HtmlCompiled = $HtmlCompiled.Replace('__I18N_JSON_PLACEHOLDER__', $I18nContent)
    $HtmlCompiled = $HtmlCompiled.Replace('__DEFAULT_LANG_PLACEHOLDER__', $Language)

    $RunStamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')
    $HtmlOutPath       = Join-Path -Path $OutputPath -ChildPath "AppSentry-Report-$RunStamp.html"
    $JsonOutPath       = Join-Path -Path $OutputPath -ChildPath "AppSentry-Results-$RunStamp.json"
    $CsvOutPath        = Join-Path -Path $OutputPath -ChildPath "AppSentry-Apps-$RunStamp.csv"
    $HtmlLatestOutPath = Join-Path -Path $OutputPath -ChildPath 'AppSentry-Report.html'
    $JsonLatestOutPath = Join-Path -Path $OutputPath -ChildPath 'AppSentry-Results.json'
    $CsvLatestOutPath  = Join-Path -Path $OutputPath -ChildPath 'AppSentry-Apps.csv'

    Set-Content -Path $HtmlOutPath -Value $HtmlCompiled -Encoding UTF8
    Set-Content -Path $JsonOutPath -Value $ReportJson -Encoding UTF8
    Set-Content -Path $HtmlLatestOutPath -Value $HtmlCompiled -Encoding UTF8
    Set-Content -Path $JsonLatestOutPath -Value $ReportJson -Encoding UTF8

    $CsvRows = foreach ($App in $AssessmentResult.Applications) {
        [PSCustomObject]@{
            OverallRisk         = $App.OverallColor
            DisplayName         = $App.DisplayName
            AppId               = $App.AppId
            ObjectId            = $App.ObjectId
            Publisher           = $App.PublisherName
            AccountEnabled      = $App.AccountEnabled
            IocRisk             = $App.IocColor
            IocStatus           = if ($Language -eq 'DE') { $App.IocBadgeDE } else { $App.IocBadgeEN }
            CanAddPasswordsRisk = $App.EscColor
            CanAddPasswords     = if ($Language -eq 'DE') { $App.EscBadgeDE } else { $App.EscBadgeEN }
            DirectoryRolesRisk  = $App.RoleColor
            DirectoryRoles      = if ($Language -eq 'DE') { $App.RoleBadgeDE } else { $App.RoleBadgeEN }
            PermissionsRisk     = $App.PermColor
            Permissions         = if ($Language -eq 'DE') { $App.PermBadgeDE } else { $App.PermBadgeEN }
            CredentialsRisk     = $App.CredColor
            Credentials         = if ($Language -eq 'DE') { $App.CredBadgeDE } else { $App.CredBadgeEN }
            GovernanceRisk      = $App.GovColor
            Governance          = if ($Language -eq 'DE') { $App.GovBadgeDE } else { $App.GovBadgeEN }
        }
    }
    $CsvRows | Export-Csv -Path $CsvOutPath -NoTypeInformation -Encoding UTF8
    $CsvRows | Export-Csv -Path $CsvLatestOutPath -NoTypeInformation -Encoding UTF8

    return [PSCustomObject]@{
        HtmlReportPath       = $HtmlOutPath
        JsonReportPath       = $JsonOutPath
        CsvReportPath        = $CsvOutPath
        HtmlLatestReportPath = $HtmlLatestOutPath
    }
}

Set-Alias -Name Export-M365AppGuardReport -Value Export-AppSentryReport

