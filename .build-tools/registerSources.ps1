#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$consumptionFeed,
    [Parameter(Mandatory=$true)][string]$previewFeed
)
Unregister-PSRepository -Name PSGallery
Register-PackageSource -Name Consumption -Trusted -ProviderName PowerShellGet -Location $consumptionFeed

# if preview feed is a temp folder
[Uri]$uri = $null
if( [Uri]::TryCreate($previewFeed, [UriKind]::Absolute, [ref]$uri) -eq $false) {
    throw "Invalid feed URI: $previewFeed"
}
if($uri.IsFile) { mkdir -p $previewFeed }

Register-PackageSource -Name Preview -ProviderName PowerShellGet -Location $previewFeed
