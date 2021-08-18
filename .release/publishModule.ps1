#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$pathToPSD1File, #Expected module dir/leaf format: ModuleName/ModuleName.psd1
    [Parameter(Mandatory=$true)][string]$apiKey,
    [switch]$ForPSGallery = $false

)

Function Build-RequiredModuleFiles {

    # Get .psd1 data
    $data = Import-PowerShellDataFile "$pathToPSD1File"

    # Get the RequiredModules
    [array]$RequiredModules = $data.RequiredModules

    foreach ($module in $RequiredModules ) {
        $targetModule = $($module.ModuleName)
        Write-Host "Installing $targetModule"
        Install-Module -Force -AllowClobber $targetModule
        Write-Host "----COMPLETED installation of $targetModule----"
    }

}

Build-RequiredModuleFiles

$script:adoUnofficialFeedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
}
# $script:adoOfficialFeedParameters = @{
#         Name = "AVS-Automation-AdminTools"
#         SourceLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
#         PublishLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
#         InstallationPolicy = 'Trusted'
# }

Write-Output "---- START: Publish Module----"
$moduleParentFolder = (Get-Item "$pathToPSD1File").Directory.FullName
Write-Output "modulePath: $moduleParentFolder"
if($ForPSGallery){
    Write-Host "Publishing to PSGallery"
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    Publish-Module -Path "$moduleParentFolder" -Repository "PSGallery" -NuGetApiKey "$apiKey"

}else{
    Write-Host "Publishing to  $($adoUnofficialFeedParameters.Name)"
    # Register-PSRepository @adoOfficialFeedParameters
    Register-PSRepository @adoUnofficialFeedParameters
    # Publish-Module -Path "$moduleParentFolder" -Repository ($adoOfficialFeedParameters).Name -NuGetApiKey "$apiKey"
    Publish-Module -Path "$moduleParentFolder" -Repository ($adoUnofficialFeedParameters).Name -NuGetApiKey "$apiKey"
}

Write-Output "---- FINISH: Publish Module----"