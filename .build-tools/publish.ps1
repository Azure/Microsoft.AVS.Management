#!/usr/bin/pwsh
param (
    [string]$accessToken,
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$buildNumber,
    [Parameter(Mandatory=$true)][string]$previewFeed,
    [string]$prereleaseString = ""
)
function update-moduleversion {
    $manifestVersionAsArray = (Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion -split "\."
    $updatedModuleVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1],  $buildNumber ) | Join-String -Separator '.'
    $targetModuleParams = @{ModuleVersion = $updatedModuleVersion; Prerelease = $prereleaseString; Path = $absolutePathToManifest}
    
    Update-ModuleManifest @targetModuleParams -ErrorAction Stop
    
    Write-Host "##vso[task.setvariable variable=moduleVersion]$updatedModuleVersion"

    Get-Content $absolutePathToManifest
}

function upload-package ([string]$name, [string]$version, [string]$feed, [PSCredential]$credential) {
    # We do not need to do the install before Import because it is done in the restore dependencies task.
    Import-Module -Name $name -RequiredVersion $version -ErrorAction Stop
    $m = Get-Module -Name $name -ErrorAction Stop
    foreach($d in $m.RequiredModules) { 
        upload-package $d.Name $d.Version $feed $credential
    }
    $existing = Find-Package -Source $feed -Name $m.Name -AllowPrerelease -RequiredVersion $version -ErrorAction SilentlyContinue
    if($null -eq $existing) { 
        Write-Output "Pushing dependency $m@$version to $feed"
        Save-PSResource -Name $m.Name -Version $version -Repository Consumption -AsNupkg -Path . -ErrorAction Stop -Credential $credential -SkipDependencyCheck
        $r = & dotnet @('nuget', 'push', ("{0}.{1}.nupkg" -f $m,$version), '-s', $feed, '-k', 'ado')
        if($? -eq $false) { throw ("Unable to publish the package: $m@$version, {0}" -f [System.Linq.Enumerable]::First($r.Split('\n'), [Func[object,bool]]{ param($l) $l.Contains("error") })) }
    } else { Write-Output "$name@$version already in the feed"}
    Write-Host ""
}

Write-Output "Updating module version in $absolutePathToManifest to $buildNumber"
update-moduleversion

Write-Output "Uploading dependencies to $previewFeed"
$requiredModules = (Test-ModuleManifest "$absolutePathToManifest" -ErrorAction Stop).RequiredModules

$c =  [PSCredential]::new("ONEBRANCH_TOKEN", ($accessToken | ConvertTo-SecureString -AsPlainText -Force))
foreach($d in $requiredModules) {
    upload-package $d.Name $d.Version $previewFeed $c
}
Publish-PSResource -Path ([IO.Path]::GetDirectoryName($absolutePathToManifest)) -Repository PreviewV3 -ApiKey "key" -ErrorAction Stop -Credential $c