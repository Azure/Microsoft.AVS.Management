#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$buildNumber,
    [Parameter(Mandatory=$true)][string]$feedLocation,
    [string]$prereleaseString = ""
)
function update-module-version {
    Get-Content $absolutePathToManifest

    $manifestVersionAsArray = (Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion -split "\."
    $updatedModuleVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1],  $buildNumber ) | Join-String -Separator '.'
    $targetModuleParams = @{ModuleVersion = $updatedModuleVersion; Prerelease = $prereleaseString; Path = $absolutePathToManifest}
    
    Update-ModuleManifest @targetModuleParams
    
    if (!$?) {
        throw "Could not update module version. Module version must be updated before proceeding with build."
    }else {
        Write-Host "##vso[task.setvariable variable=moduleVersion]$updatedModuleVersion"
        Write-Output "---- SUCCEED: updated the module version to $((Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion)----"
        Get-Content $absolutePathToManifest
    }    
}

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
        Write-Output "Pushing dependency $m@$version to $feed"
        Save-Package -Name $m.Name -RequiredVersion $version -Source $m.RepositorySourceLocation -Provider NuGet -Path . -ErrorAction Stop
        $r = & dotnet @('nuget', 'push', ("{0}.{1}.nupkg" -f $m,$version), '-s', $feed, '-k', $key)
        if($? -eq $false) { throw ("Unable to publish the package: $m@$version, {0}" -f [System.Linq.Enumerable]::First($r.Split('\n'), [Func[object,bool]]{ param($l) $l.Contains("error") })) }
        else { Write-Output "Successfully published: $m@$version" }
    } else { Write-Output "$name@$version already in the feed"}
}

Write-Output "----START: publish -----"

update-module-version
$requiredModules = (Test-ModuleManifest "$absolutePathToManifest" -ErrorAction SilentlyContinue).RequiredModules

if (!$?) {
    throw "Could not extract the required dependency module. Dependencies must be loaded in order for the push to succeed"
} else {
    Write-Output "Required dependencies:"
    $requiredModules | Select-Object Name, Version
}

Write-Output "----Registering AVS Nuget Feed ----"
[Uri]$uri = $null
if( [Uri]::TryCreate($feedLocation, [UriKind]::Absolute, [ref]$uri) -eq $false) {
    throw "Invalid feed URI: $feedLocation"
}
if($uri.IsFile) { mkdir -p $feedLocation }

$feedParameters = @{ Name = "Dst"; SourceLocation = $feedLocation; PublishLocation = $feedLocation; InstallationPolicy = 'Trusted' }
Unregister-PSRepository -Name $feedParameters.Name -ErrorAction SilentlyContinue
Register-PSRepository @feedParameters
if (!$?) {
    throw "Unable to register repository: Must be able to register feed before publishing to it"
} else {
    Write-Output "----SUCCEEDED: $($feedParameters.Name) repository registered ----"
}

Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
foreach($d in $requiredModules) {
    upload-package $d.Name $d.Version $feedParameters.PublishLocation "key"
}
Publish-Module -Path ([IO.Path]::GetDirectoryName($absolutePathToManifest)) -Repository ($feedParameters).Name -NuGetApiKey "key" -ErrorAction Stop