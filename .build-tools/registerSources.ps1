#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$consumptionFeed,
    [Parameter(Mandatory=$true)][string]$previewFeed
)
Unregister-PSRepository -Name PSGallery
Unregister-PSResourceRepository -Name PSGallery

Register-PackageSource -Name Consumption -Trusted -ProviderName PowerShellGet -Location "$consumptionFeed/nuget/v2"
Register-PSResourceRepository -Name Consumption -Trusted -Uri "$consumptionFeed/nuget/v2"
Register-PSResourceRepository -Name ConsumptionV3 -Trusted -Uri "$consumptionFeed/nuget/v3/index.json"

# if preview feed is a temp folder
[Uri]$uri = $null
if( [Uri]::TryCreate($previewFeed, [UriKind]::Absolute, [ref]$uri) -eq $false) {
    throw "Invalid feed URI: $previewFeed"
}
if($uri.IsFile) {
    mkdir -p $previewFeed
    Register-PackageSource -Name Preview -ProviderName PowerShellGet -Location $previewFeed -PublishLocation $previewFeed
    Register-PSResourceRepository -Name PreviewV3 -Trusted -Uri $previewFeed
}
else {
    Register-PackageSource -Name Preview -ProviderName PowerShellGet -Location "$previewFeed/nuget/v2" -PublishLocation "$previewFeed/nuget/v2"
    Register-PSResourceRepository -Name PreviewV3 -Trusted -Uri "$previewFeed/nuget/v3/index.json"
}

