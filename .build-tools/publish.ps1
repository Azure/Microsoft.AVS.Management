#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$accessToken,
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$buildNumber,
    [Parameter(Mandatory=$true)][string]$previewFeed,
    [string]$prereleaseString = ""
)
$ErrorActionPreference = "Stop"
# Import the CDR module for conservative dependency resolution
Import-Module "$PSScriptRoot/../Microsoft.AVS.CDR/Microsoft.AVS.CDR.psd1" -Force 

function New-PublishingSecureString {
    <#
    .SYNOPSIS
    Adapts a pipeline access token to the SecureString required by PSCredential.
    .DESCRIPTION
    Isolates the conversion of a token already supplied as text by Azure Pipelines.
    .PARAMETER Text
    The pipeline-provided access token. Its value is never logged by this helper.
    .EXAMPLE
    New-PublishingSecureString -Text $accessToken
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Azure Pipelines supplies the short-lived token as text; package cmdlets require a PSCredential with a SecureString password.')]
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    return $Text | ConvertTo-SecureString -AsPlainText -Force
}

function update-moduleversion {
    $manifestVersionAsArray = (Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion -split "\."
    $updatedModuleVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1],  $buildNumber ) | Join-String -Separator '.'
    $manifestText = Get-Content -LiteralPath $absolutePathToManifest -Raw
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $manifestText, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) {
        throw 'Cannot update an invalid module manifest.'
    }
    $table = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.HashtableAst]
    }, $true)
    $edits = [System.Collections.Generic.List[object]]::new()
    $newline = if ($manifestText.Contains("`r`n")) { "`r`n" } else { "`n" }

    function Get-ManifestEntryAst($TableAst, $Name) {
        $TableAst.KeyValuePairs |
            Where-Object { $_.Item1.SafeGetValue() -eq $Name } |
            Select-Object -First 1
    }

    function Get-ManifestTableAst($Entry) {
        if ($null -ne $Entry) {
            $Entry.Item2.Find({
                param($node)
                $node -is [System.Management.Automation.Language.HashtableAst]
            }, $true)
        }
    }

    function Add-ManifestEntryEdit($TableAst, $EntryText) {
        $offset = $TableAst.Extent.EndOffset - 1
        $lineStart = $manifestText.LastIndexOf("`n", $offset) + 1
        $indent = $manifestText.Substring($lineStart, $offset - $lineStart)
        if ($indent -notmatch '^[ \t]*$') { $indent = '' }
        $edits.Add(@{
            Offset = $offset
            Length = 0
            Text = "$newline$indent    $EntryText$newline$indent"
        })
    }

    # Replace only the field expressions; manifest regeneration discards custom PSData.
    $versionEntry = Get-ManifestEntryAst $table 'ModuleVersion'
    $version = ([version]$updatedModuleVersion).ToString()
    $edits.Add(@{
        Offset = $versionEntry.Item2.Extent.StartOffset
        Length = $versionEntry.Item2.Extent.EndOffset - $versionEntry.Item2.Extent.StartOffset
        Text = "'$version'"
    })

    if (-not [String]::IsNullOrWhiteSpace($prereleaseString)) {
        $value = "'$($prereleaseString.Replace("'", "''"))'"
        $privateDataEntry = Get-ManifestEntryAst $table 'PrivateData'
        $privateData = Get-ManifestTableAst $privateDataEntry
        if ($privateDataEntry -and -not $privateData) {
            throw 'Manifest PrivateData must be a hashtable to set a prerelease.'
        }
        $psDataEntry = if ($privateData) { Get-ManifestEntryAst $privateData 'PSData' }
        $psData = Get-ManifestTableAst $psDataEntry
        if ($psDataEntry -and -not $psData) {
            throw 'Manifest PSData must be a hashtable to set a prerelease.'
        }
        if ($psData) {
            $prerelease = Get-ManifestEntryAst $psData 'Prerelease'
            if ($prerelease) {
                $edits.Add(@{
                    Offset = $prerelease.Item2.Extent.StartOffset
                    Length = $prerelease.Item2.Extent.EndOffset - $prerelease.Item2.Extent.StartOffset
                    Text = $value
                })
            } else {
                Add-ManifestEntryEdit $psData "Prerelease = $value"
            }
        } elseif ($privateData) {
            Add-ManifestEntryEdit $privateData "PSData = @{ Prerelease = $value }"
        } else {
            Add-ManifestEntryEdit $table "PrivateData = @{ PSData = @{ Prerelease = $value } }"
        }
    }

    foreach ($edit in $edits | Sort-Object Offset -Descending) {
        $manifestText = $manifestText.Remove($edit.Offset, $edit.Length).Insert($edit.Offset, $edit.Text)
    }
    Set-Content -LiteralPath $absolutePathToManifest -Value $manifestText -NoNewline -ErrorAction Stop
    
    Write-Host "##vso[task.setvariable variable=moduleVersion]$updatedModuleVersion"

    Get-Content $absolutePathToManifest
}

function replicate-package ([string]$name, [string]$version, [string]$packagePath, [PSCredential]$credential) {
    $existing = Find-PSResource -Repository Preview -Name $name -Version $version -Prerelease -ErrorAction SilentlyContinue -Credential $credential
    
    if ($null -ne $existing) {
        Write-Output "$name@$version already in the feed, skipping"
        return
    }
    
    Write-Output "Saving $name@$version..."
    Save-PSResource -Name $name -Version $version -Path $packagePath -Repository Consumption -Credential $credential -TrustRepository -SkipDependencyCheck -AsNupkg
    
    $expectedFileName = "$name.$version.nupkg"
    $pkg = Get-ChildItem -Path $packagePath -Filter $expectedFileName | Select-Object -First 1
    
    if ($pkg) {
        Write-Output "Publishing $($pkg.Name) to preview feed..."
        Publish-PSResource -NupkgPath $pkg.FullName -Repository Preview -ApiKey "key"  -Credential $credential
    }
}

Write-Output "Updating module version in $absolutePathToManifest to $buildNumber"
update-moduleversion

Write-Output "Uploading dependencies to $previewFeed"
$manifest = Import-PowerShellDataFile "$absolutePathToManifest"
$moduleName = [System.IO.Path]::GetFileNameWithoutExtension($absolutePathToManifest)

$c = [PSCredential]::new("ONEBRANCH_TOKEN", (New-PublishingSecureString -Text $accessToken))

# Create a temporary directory for packages
$packagePath = Join-Path ([System.IO.Path]::GetTempPath()) "$moduleName-$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $packagePath -Force | Out-Null

try {
    # Use CDR to find and resolve all required modules with conservative dependency resolution
    $allPackages = Find-PSResourceDependencies -ManifestPath $absolutePathToManifest -Repository Consumption -Credential $c
    
    Write-Output "Found $($allPackages.Count) total packages (including transitive dependencies)"
    
    foreach ($pkg in $allPackages) {
        replicate-package -name $pkg.Name -version $pkg.Version -packagePath $packagePath -credential $c
    }
    
    # Publish the main module
    Publish-PSResource -Path $moduleName -Repository Preview -ApiKey "key"  -Credential $c
    
    $version = if ([String]::IsNullOrWhiteSpace($manifest.PrivateData.PSData.Prerelease)) {
        $manifest.ModuleVersion.ToString()
    } else {
        "$($manifest.ModuleVersion)-$($manifest.PrivateData.PSData.Prerelease)" 
    }
    
    $isRemoteFeed = $previewFeed -match '^https?://'
    if ($isRemoteFeed) {
        Write-Output "Verifying installation of $moduleName@$version..."
        Install-PSResourcePinned -Name $moduleName -RequiredVersion $version -Prerelease -Force -Repository Preview -Credential $c
    } else {
        Write-Output "Verifying installation of $moduleName@$version (local folder, skipping dependencies)..."
        Install-PSResource -Name $moduleName -Version $version -Repository Preview -SkipDependencyCheck -TrustRepository
    }
}
finally {
    # Cleanup temporary package directory
    if (Test-Path $packagePath) {
        Remove-Item -Path $packagePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}