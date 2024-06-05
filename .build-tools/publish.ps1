#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$buildNumber,
    [string]$prereleaseString,
    $feedParameters
)
function update-module-version {
    Get-Content $manifestAbsolutePath

    $manifestVersionAsArray = (Import-PowerShellDataFile $manifestAbsolutePath).ModuleVersion -split "\."
    $updatedModuleVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1],  $buildNumber ) | Join-String -Separator '.'
    $targetModuleParams = @{ModuleVersion = $updatedModuleVersion; Prerelease = $prereleaseString; Path = $absolutePathToManifest}
    
    Update-ModuleManifest @targetModuleParams
    
    if (!$?) {
        Write-Error -Message "FAILED: Could not update module version"
        Throw "Module version must be updated before proceeding with build."
        
    }else {
        Write-Host "##vso[task.setvariable variable=moduleVersion]$updatedModuleVersion"
        Write-Output "---- SUCCEED: updated the module version to $((Import-PowerShellDataFile $manifestAbsolutePath).ModuleVersion)----"
        Get-Content $manifestAbsolutePath
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
        Write-Output "Pushing dependency $m.Name@$version to $feed"
        Save-Package -Name $m.Name -RequiredVersion $version -Source $m.RepositorySourceLocation -Provider NuGet -Path . -ErrorAction Stop
        $r = & dotnet @('nuget', 'push', ("{0}.{1}.nupkg" -f $m.Name,$version), '-s', $feed, '-k', $key)
        if($? -eq $false) { throw ("Unable to publish the package $($m.Name)@$version, {0}" -f [System.Linq.Enumerable]::First($r.Split('\n'), [Func[object,bool]]{ param($l) $l.Contains("error") })) }
        else { Write-Output "Successfully published the dependency of $name@$version" }
    } else { Write-Output "$name@$version already in the feed"}
}

Write-Output "----START: publish -----"

update-module-version
$requiredModules = (Test-ModuleManifest "$absolutePathToManifest" -ErrorAction SilentlyContinue).RequiredModules

if (!$?) {
    Write-Error -Message "FAILED: Could not extract the required dependency module"
    Throw "Dependencies must be loaded in order for the push to succeed"
} else {
    Write-Output "---- SUCCEEDED: Was able to parse the dependencies ----"
    $requiredModules | Select-Object Name, Version
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
    upload-package $d.Name $d.Version $feedParameters.PublishLocation ""
}

Publish-Module -Path "$absolutePathToManifestFolder" -Repository ($feedParameters).Name -NuGetApiKey "" -ErrorAction Stop