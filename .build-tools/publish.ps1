#!/usr/bin/pwsh
param (
    [string]$accessToken,
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$buildNumber,
    [Parameter(Mandatory=$true)][string]$previewFeed,
    [string]$prereleaseString = ""
)

# Import the CDR module for conservative dependency resolution
Import-Module "$PSScriptRoot/../Microsoft.AVS.CDR/Microsoft.AVS.CDR.psd1" -Force -ErrorAction Stop

function update-moduleversion {
    $manifestVersionAsArray = (Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion -split "\."
    $updatedModuleVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1],  $buildNumber ) | Join-String -Separator '.'
    $targetModuleParams = @{ModuleVersion = $updatedModuleVersion; Path = $absolutePathToManifest}
    
    # Only add Prerelease parameter if prereleaseString is not null or empty
    if (-not [String]::IsNullOrWhiteSpace($prereleaseString)) {
        $targetModuleParams.Prerelease = $prereleaseString
    }
    
    Update-PSModuleManifest @targetModuleParams -ErrorAction Stop
    
    Write-Host "##vso[task.setvariable variable=moduleVersion]$updatedModuleVersion"

    Get-Content $absolutePathToManifest
}

function replicate-packages ([string]$name, [string]$version, [string]$packagePath, [PSCredential]$credential) {
    # Use CDR to save the module and all its dependencies with conservative resolution
    Write-Output "Saving $name@$version and dependencies using CDR..."
    Save-PSResourcePinned -Name $name -RequiredVersion $version -Path $packagePath -Repository ConsumptionV3 -Credential $credential
    
    # Publish all saved packages to the preview feed
    $packages = Get-ChildItem -Path $packagePath -Filter "*.nupkg"
    foreach ($pkg in $packages) {
        $pkgName = $pkg.BaseName -replace '\.\d+\.\d+\.\d+.*$', ''
        $existing = Find-PSResource -Repository PreviewV3 -Name $pkgName -Prerelease -ErrorAction SilentlyContinue -Credential $credential | 
            Where-Object { $pkg.Name -like "$($_.Name).$($_.Version)*" }
        
        if ($null -eq $existing) {
            Write-Output "Publishing $($pkg.Name) to preview feed..."
            Publish-PSResource -NupkgPath $pkg.FullName -Repository PreviewV3 -ApiKey "key" -ErrorAction Stop -Credential $credential
        } else {
            Write-Output "$($pkg.Name) already in the feed"
        }
    }
}

Write-Output "Updating module version in $absolutePathToManifest to $buildNumber"
update-moduleversion

Write-Output "Uploading dependencies to $previewFeed"
$manifest = Test-ModuleManifest "$absolutePathToManifest" -ErrorAction Stop

$c = [PSCredential]::new("ONEBRANCH_TOKEN", ($accessToken | ConvertTo-SecureString -AsPlainText -Force))

# Create a temporary directory for packages
$packagePath = Join-Path ([System.IO.Path]::GetTempPath()) "avs-packages-$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $packagePath -Force | Out-Null

try {
    # Use CDR to replicate each required module and its dependencies
    foreach ($d in $manifest.RequiredModules) {
        replicate-packages -name $d.Name -version $d.Version -packagePath $packagePath -credential $c
    }
    
    # Publish the main module
    Publish-PSResource -Path $manifest.Name -Repository PreviewV3 -ApiKey "key" -ErrorAction Stop -Credential $c
    
    # Verify installation using CDR's pinned install
    $version = if ([String]::IsNullOrWhiteSpace($manifest.PrivateData.PSData.Prerelease)) {
        $manifest.Version.ToString()
    } else {
        "$($manifest.Version)-$($manifest.PrivateData.PSData.Prerelease)" 
    }
    
    Write-Output "Verifying installation of $($manifest.Name)@$version..."
    Install-PSResourcePinned -Name $manifest.Name -RequiredVersion $version -Repository PreviewV3 -Credential $c
}
finally {
    # Cleanup temporary package directory
    if (Test-Path $packagePath) {
        Remove-Item -Path $packagePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}