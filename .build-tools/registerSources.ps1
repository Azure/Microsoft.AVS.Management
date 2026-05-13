#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$consumptionFeed,
    [Parameter(Mandatory=$true)][string]$previewFeed
)
Unregister-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue

Register-PSResourceRepository -Name Consumption -Trusted -Uri "$consumptionFeed"

# if preview feed is a temp folder
[Uri]$uri = $null
if( [Uri]::TryCreate($previewFeed, [UriKind]::Absolute, [ref]$uri) -eq $false) {
    throw "Invalid feed URI: $previewFeed"
}

if ($uri.IsFile) {
    New-Item -ItemType Directory -Force -Path $previewFeed -ErrorAction SilentlyContinue
    Register-PSResourceRepository -Name Preview -Trusted -Uri $previewFeed -ErrorAction SilentlyContinue
} else {
    Register-PSResourceRepository -Name Preview -Trusted -Uri "$previewFeed" -ErrorAction SilentlyContinue
}

Write-Host "Registered repositories:"
Get-PSResourceRepository | Format-Table Name,Uri,Trusted
