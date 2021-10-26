#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$pathToPSD1File, #Expected module dir/leaf format: ModuleName/ModuleName.psd1
    [Parameter(Mandatory=$true)][string]$apiKey,
    [switch]$ForPSGallery = $false

)

$script:adoUnofficialFeedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
}

Function Install-RequiredModules {
    param (
        [Parameter(Mandatory=$true)]$sourceFeedParams
    )

    # Get .psd1 data
    $data = Import-PowerShellDataFile "$pathToPSD1File"

    # Get the RequiredModules
    [array]$RequiredModules = $data.RequiredModules

    foreach ($module in $RequiredModules ) {
        $targetModule = $($module.ModuleName)
        Write-Host "Installing $targetModule"
        Install-Module $targetModule -Repository ($sourceFeedParams).Name -Force -AllowClobber
        Write-Host "----COMPLETED installation of $targetModule----"
    }

}

try {
    Write-Host "Attempting to register Powershell repository '$($adoUnofficialFeedParameters.Name)'."
    Register-PSRepository @adoUnofficialFeedParameters -ErrorAction Stop
}
catch {
    Write-Host "The Powershell repository '$($adoUnofficialFeedParameters.Name)' is already registered?"
}

#Install required modules on agent. Necessary for PS publishing.
Install-RequiredModules($adoUnofficialFeedParameters)

Write-Output "---- START: Publish Module----"
$moduleParentFolder = (Get-Item "$pathToPSD1File").Directory.FullName
Write-Output "modulePath: $moduleParentFolder"
if($ForPSGallery){
    Write-Host "Publishing to PSGallery"
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    Publish-Module -Path "$moduleParentFolder" -Repository "PSGallery" -NuGetApiKey "$apiKey"

}else{
    Write-Host "Publishing to  $($adoUnofficialFeedParameters.Name)"
    Publish-Module -Path "$moduleParentFolder" -Repository ($adoUnofficialFeedParameters).Name -NuGetApiKey "$apiKey"
}

Write-Output "---- FINISH: Publish Module----"