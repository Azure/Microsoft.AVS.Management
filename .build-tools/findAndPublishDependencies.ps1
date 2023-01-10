#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest
)

function upload-package ([string]$name, [string]$version, [string]$feed, [string]$key) {
    # We do not need to do the install before Import because it is done in the restore dependencies task.
    Import-Module -Name $name -RequiredVersion $version
    $m = Get-Module -Name $name 
    if($null -eq $m) { throw "Was not able to find the dependency $name" }
    foreach($d in $m.RequiredModules) { 
        upload-package $d.Name $d.Version $feed $key
    }
    $existing = Find-Package -Source $feed -Name $m.Name -AllowPrerelease -RequiredVersion $version -ErrorAction SilentlyContinue
    if($null -eq $existing) { 
        Write-Output "Pushing dependency $m.Name@$version to $feed"
        Save-Package -Name $m.Name -RequiredVersion $version -Source $m.RepositorySourceLocation -Provider NuGet -Path . -ErrorAction Stop
        $r = & dotnet @('nuget', 'push', ("{0}.{1}.nupkg" -f $m.Name,$version), '-s', $feed, '-k', $key)
        if($? -eq $false) { throw ("Unable to publish the package $($m.Name)@$version, {0}" -f [System.Linq.Enumerable]::First($r.Split('\n'), [Func[object,bool]]{ param($l) $l.Contains("error") })) }
        else { Write-Output "Successfully published the dependency of $name@$version" }
    } else { Write-Output "$name@$version already in the feed"}
}


Write-Output "----START: findAndPublishDependencies-----"
$requiredModules = (Test-ModuleManifest "$absolutePathToManifest" -ErrorAction SilentlyContinue).RequiredModules

if (!$?) {
    Write-Error -Message "FAILED: Could not extract the required dependency module"
    Throw "Dependencies must be loaded in order for the push to succeed"
} else {
    Write-Output "---- SUCCEEDED: Was able to parse the dependencies ----"
    $requiredModules | Select-Object Name, Version
}

$feedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
}

Write-Output "----Registering AVS Nuget Feed ----"
Unregister-PSRepository -Name $feedParameters.Name -ErrorAction SilentlyContinue
Register-PSRepository @feedParameters
if (!$?) {
    Write-Error -Message "----ERROR: Unable to register repository----"
    Throw "Must be able to register feed before publishing to it"
} else {
    Write-Output "----SUCCEEDED: $($feedParameters.Name) repository registered ----"
}

Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
foreach($d in $requiredModules) {
    upload-package $d.Name $d.Version $feedParameters.PublishLocation "$env:UNOFFICIAL_FEED_NUGET_APIKEY"
}