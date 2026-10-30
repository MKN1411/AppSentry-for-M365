#Requires -Version 7.0
Set-StrictMode -Version Latest

$PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
$PublicPath  = Join-Path -Path $PSScriptRoot -ChildPath 'Public'

if (Test-Path -Path $PrivatePath) {
    $PrivateFiles = Get-ChildItem -Path $PrivatePath -Filter '*.ps1' -File -ErrorAction SilentlyContinue
    foreach ($File in $PrivateFiles) {
        . $File.FullName
    }
}

if (Test-Path -Path $PublicPath) {
    $PublicFiles = Get-ChildItem -Path $PublicPath -Filter '*.ps1' -File -ErrorAction SilentlyContinue
    foreach ($File in $PublicFiles) {
        . $File.FullName
    }
}

Export-ModuleMember -Function @(
    'Invoke-AppSentry',
    'Get-M365TenantAppPolicies',
    'Get-M365AppInventory',
    'Measure-M365AppRisk',
    'Export-AppSentryReport'
) -Alias @(
    'Invoke-M365AppGuard',
    'Export-M365AppGuardReport'
)

