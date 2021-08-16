#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$pathToPSD1File #Expected module dir/leaf format: ModuleName/ModuleName.psd1
)

Function Build-RequiredModuleFiles {

    # Get .psd1 data
    $Data = Import-PowerShellDataFile "$pathToPSD1File"

    # Get the RequiredModules
    [array]$RequiredModules = $data.RequiredModules

    foreach ($module in $RequiredModules ) {
        $targetModule = $($module.ModuleName)
        Write-Host "Installing $targetModule"
        Install-Module -Force -AllowClobber $targetModule
        Write-Host "----COMPLETED installation of $targetModule----"
    }

}

$moduleParentFolder = (Get-Item "$pathToPSD1File").Directory.FullName
Build-RequiredModuleFiles

Write-Output "---- START: Register repository----"
$feedParameters = @{
        Name = "AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
}
Register-PSRepository @feedParameters
Write-Output "---- FINISH: Register repository----"

Write-Output "---- START: List Available PSRepositories----"
Get-PSRepository
Write-Output "---- FINISH: List Available PSRepositories----"

Write-Output "---- START: Publish Module----"
Write-Output "modulePath: $moduleParentFolder"
Write-Output "Publishing to $($feedParameters.Name)"

# Path includes release pipeline variables. NugetApiKey is a secret pipeline variable.
Publish-Module -Path "$moduleParentFolder" -Repository ($feedParameters).Name -NuGetApiKey $(Microsoft-AVS-Management-OfficialFeed-And-ReleasesPAT)
Write-Output "---- FINISH: Publish Module----"