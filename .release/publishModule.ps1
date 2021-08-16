#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$moduleParentFolder
)

Write-Output "---- START: List all env variables----"
dir env:
Write-Output "---- FINISH: List all env variables----"

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
Write-Output "modulePath: $(System.DefaultWorkingDirectory)/$(Release.PrimaryArtifactSourceAlias)/$env:moduleParentFolder"

# Path includes release pipeline variables. NugetApiKey is a secret pipeline variable.
Publish-Module -Path $(System.DefaultWorkingDirectory)/$(Release.PrimaryArtifactSourceAlias)/$(moduleParentFolder) -Repository ($feedParameters).Name -NuGetApiKey $(Microsoft-AVS-Management-OfficialFeed-And-ReleasesPAT)
Write-Output "---- FINISH: Publish Module----"