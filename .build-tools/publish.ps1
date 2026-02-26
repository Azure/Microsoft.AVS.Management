#!/usr/bin/pwsh
param (
    [string]$accessToken,
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$buildNumber,
    [Parameter(Mandatory=$true)][string]$previewFeed,
    [string]$prereleaseString = ""
)
$ErrorActionPreference = "Stop"
# Import the CDR module for conservative dependency resolution
Import-Module "$PSScriptRoot/../Microsoft.AVS.CDR/Microsoft.AVS.CDR.psd1" -Force 

function update-moduleversion {
    $manifestVersionAsArray = (Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion -split "\."
    $updatedModuleVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1],  $buildNumber ) | Join-String -Separator '.'
    $targetModuleParams = @{ModuleVersion = $updatedModuleVersion; Path = $absolutePathToManifest}
    
    # Only add Prerelease parameter if prereleaseString is not null or empty
    if (-not [String]::IsNullOrWhiteSpace($prereleaseString)) {
        $targetModuleParams.Prerelease = $prereleaseString
    }
    
    Update-PSModuleManifest @targetModuleParams 
    
    Write-Host "##vso[task.setvariable variable=moduleVersion]$updatedModuleVersion"

    Get-Content $absolutePathToManifest
}

function replicate-package ([string]$name, [string]$version, [string]$packagePath, [PSCredential]$credential) {
    $existing = Find-PSResource -Repository PreviewV3 -Name $name -Version $version -Prerelease -ErrorAction SilentlyContinue -Credential $credential
    
    if ($null -ne $existing) {
        Write-Output "$name@$version already in the feed, skipping"
        return
    }
    
    Write-Output "Saving $name@$version..."
    Save-PSResource -Name $name -Version $version -Path $packagePath -Repository ConsumptionV3 -Credential $credential -TrustRepository -SkipDependencyCheck -AsNupkg
    
    $expectedFileName = "$name.$version.nupkg"
    $pkg = Get-ChildItem -Path $packagePath -Filter $expectedFileName | Select-Object -First 1
    
    if ($pkg) {
        Write-Output "Publishing $($pkg.Name) to preview feed..."
        Publish-PSResource -NupkgPath $pkg.FullName -Repository PreviewV3 -ApiKey "key"  -Credential $credential
    }
}

Write-Output "Updating module version in $absolutePathToManifest to $buildNumber"
update-moduleversion

Write-Output "Uploading dependencies to $previewFeed"
$manifest = Import-PowerShellDataFile "$absolutePathToManifest"
$moduleName = [System.IO.Path]::GetFileNameWithoutExtension($absolutePathToManifest)

$c = [PSCredential]::new("ONEBRANCH_TOKEN", ($accessToken | ConvertTo-SecureString -AsPlainText -Force))

# Create a temporary directory for packages
$packagePath = Join-Path ([System.IO.Path]::GetTempPath()) "$moduleName-$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $packagePath -Force | Out-Null

try {
    # Use CDR to find and resolve all required modules with conservative dependency resolution
    $allPackages = Find-PSResourceDependencies -ManifestPath $absolutePathToManifest -Repository ConsumptionV3 -Credential $c
    
    Write-Output "Found $($allPackages.Count) total packages (including transitive dependencies)"
    
    foreach ($pkg in $allPackages) {
        replicate-package -name $pkg.Name -version $pkg.Version -packagePath $packagePath -credential $c
    }
    
    # Publish the main module
    Publish-PSResource -Path $moduleName -Repository PreviewV3 -ApiKey "key"  -Credential $c
    
    $version = if ([String]::IsNullOrWhiteSpace($manifest.PrivateData.PSData.Prerelease)) {
        $manifest.ModuleVersion.ToString()
    } else {
        "$($manifest.ModuleVersion)-$($manifest.PrivateData.PSData.Prerelease)" 
    }
    
    $isRemoteFeed = $previewFeed -match '^https?://'
    if ($isRemoteFeed) {
        Write-Output "Verifying installation of $moduleName@$version..."
        Install-PSResourcePinned -Name $moduleName -RequiredVersion $version -Prerelease -Repository PreviewV3 -Credential $c
    } else {
        Write-Output "Verifying installation of $moduleName@$version (local folder, skipping dependencies)..."
        Install-PSResource -Name $moduleName -Version $version -Repository PreviewV3 -SkipDependencyCheck -TrustRepository
    }
}
finally {
    # Cleanup temporary package directory
    if (Test-Path $packagePath) {
        Remove-Item -Path $packagePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}