#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest
)

function upload-package ([string]$name, [string]$version, [string]$feed, [string]$key) {
    Write-Output "upload package $name@$version"
    # Install-Module -Name $name -RequiredVersion $version -Repository PSGallery
    Import-Module -Name $name -RequiredVersion $version
    $m = Get-Module -Name $name 
    if($null -eq $m) { throw "Was not able to find the dependency $name" }
    foreach($d in $m.RequiredModules) { 
        upload-package $d.Name $d.Version $feed $key
    }
    $existing = Find-Package -Source $feed -Name $m.Name -AllowPrerelease -RequiredVersion $version -ErrorAction SilentlyContinue
    if($null -eq $existing) { 
        # Save-Package -Name $m.Name -RequiredVersion $version -Source PSGallery -Provider NuGet -Path . -ErrorAction Stop
        Publish-Module -Name $m.Name -RequiredVersion $version -NuGetApiKey $key -Repository $feed
        if($? -eq $false) { throw "Unable to publish the package." } 
        else { Write-Output "Successfully published the dependency of $name@$version" }
    } else { Write-Output "$name@$version already in the feed"}


Write-Output "----START: findAndPublishDependencies-----"
$requiredModules = (Test-ModuleManifest "$absolutePathToManifest" -ErrorAction SilentlyContinue).RequiredModules

if (!$?) {
    Write-Error -Message "FAILED: Could not extract the required dependency module"
    Throw "Dependencies must be loaded in order for the push to succeed"
    
} else {
    Write-Output "---- SUCCEEDED: Was able to parse the dependencies ----"
    foreach($d in $requiredModules) { 
        Write-Output "Required module: $d"
    }
}

$feedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
}

Write-Output "----Registering PSRepository ----"
Unregister-PSRepository -Name $feedParameters.Name -ErrorAction SilentlyContinue
Register-PSRepository @feedParameters
if (!$?) {
    Write-Error -Message "----ERROR: Unable to register repository----"
    Throw "Must be able to register feed before publishing to it"
} else {
    Write-Output "----SUCCEEDED: $($feedParameters.Name) repository registered ----"
}

foreach($d in $requiredModules) {
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    upload-package $d.Name $d.Version $feedParameters.Name "$env:UNOFFICIAL_FEED_NUGET_APIKEY"
}