<#PSScriptInfo
    .VERSION 1.0

    .GUID 8c9ad063-f8fe-4300-87af-264c9bbce0ea

    .AUTHOR Microsoft

    .COMPANYNAME Microsoft

    .COPYRIGHT (c) Microsoft. All rights reserved.

    .DESCRIPTION Private staging and promotion helpers for Microsoft.AVS.CDR.
#>

function Split-CdrResourceVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $match = [System.Text.RegularExpressions.Regex]::Match(
        $Version,
        '^(?<base>\d+(?:\.\d+){0,3})(?:-(?<pre>[0-9A-Za-z][0-9A-Za-z\.-]*))?(?:\+[0-9A-Za-z\.-]+)?$')
    if (-not $match.Success) {
        throw "Version '$Version' is not a supported exact semantic version."
    }

    [pscustomobject]@{
        FullVersion = $Version
        BaseVersion = $match.Groups['base'].Value
        Prerelease = if ($match.Groups['pre'].Success) { $match.Groups['pre'].Value } else { $null }
    }
}

function Get-CdrLinuxModuleRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [string]$Scope
    )

    $root = switch ($Scope) {
        'CurrentUser' { Join-Path $HOME '.local/share/powershell/Modules' }
        'AllUsers' { '/usr/local/share/powershell/Modules' }
    }

    if (Test-Path -LiteralPath $root) {
        $item = Get-Item -LiteralPath $root -ErrorAction Stop
        if (-not $item.PSIsContainer) {
            throw "PowerShell module root '$root' exists but is not a directory."
        }

        return $item.FullName
    }

    $parent = Split-Path -Path $root -Parent
    if (-not $parent) {
        throw "PowerShell module root '$root' has no writable parent directory."
    }

    if (-not (Test-Path -LiteralPath $parent)) {
        throw "Parent directory '$parent' for PowerShell module root '$root' does not exist."
    }

    $null = New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop
    (Get-Item -LiteralPath $root -ErrorAction Stop).FullName
}

function Get-CdrResourceDestinationPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModulesRoot,

        [Parameter(Mandatory = $true)]
        [object]$Resource
    )

    $versionInfo = Split-CdrResourceVersion -Version $Resource.Version
    $moduleRoot = Join-Path -Path $ModulesRoot -ChildPath $Resource.Name
    $versionRoot = Join-Path -Path $moduleRoot -ChildPath $versionInfo.BaseVersion

    [pscustomobject]@{
        VersionInfo = $versionInfo
        ModuleRoot = $moduleRoot
        VersionRoot = $versionRoot
    }
}

function Get-CdrMetadataInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetadataPath
    )

    $info = $null
    $readError = $null
    $succeeded = [Microsoft.PowerShell.PSResourceGet.UtilClasses.PSResourceInfo]::TryRead(
        $MetadataPath,
        [ref]$info,
        [ref]$readError)

    if (-not $succeeded -or -not $info) {
        $message = if ($readError) { $readError } else { 'Unknown PSResourceInfo parse failure.' }
        throw "Failed to read PSResourceGet metadata '$MetadataPath': $message"
    }

    $info
}

function Get-CdrManifestPrerelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest
    )

    if ($Manifest.ContainsKey('PrivateData') -and
        $Manifest.PrivateData -is [hashtable] -and
        $Manifest.PrivateData.ContainsKey('PSData') -and
        $Manifest.PrivateData.PSData -is [hashtable] -and
        $Manifest.PrivateData.PSData.ContainsKey('Prerelease')) {
        return $Manifest.PrivateData.PSData.Prerelease
    }

    $null
}

function Get-CdrMetadataNormalizedVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.PSResourceGet.UtilClasses.PSResourceInfo]$Metadata
    )

    if ($Metadata.AdditionalMetadata -and $Metadata.AdditionalMetadata.ContainsKey('NormalizedVersion')) {
        return $Metadata.AdditionalMetadata['NormalizedVersion']
    }

    $version = $Metadata.Version.ToString()
    if ($Metadata.Prerelease) {
        return "$version-$($Metadata.Prerelease)"
    }

    $version
}

function Test-CdrExactResourceDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VersionRoot
    )

    Test-Path -LiteralPath $VersionRoot -PathType Container
}

function Assert-CdrSavedModuleIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Resource,

        [Parameter(Mandatory = $true)]
        [string]$VersionRoot,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedInstalledLocation
    )

    $versionInfo = Split-CdrResourceVersion -Version $Resource.Version
    if (-not (Test-Path -LiteralPath $VersionRoot -PathType Container)) {
        throw "Saved module for '$($Resource.Name)' version '$($Resource.Version)' was not found at '$VersionRoot'."
    }

    $manifestPath = Join-Path -Path $VersionRoot -ChildPath "$($Resource.Name).psd1"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Saved module '$($Resource.Name)' version '$($Resource.Version)' is missing manifest '$manifestPath'."
    }

    $manifest = Import-PowerShellDataFile -Path $manifestPath
    $manifestBaseVersion = if ($manifest.ModuleVersion) { $manifest.ModuleVersion.ToString() } else { $null }
    if ($manifestBaseVersion -ne $versionInfo.BaseVersion) {
        throw "Saved module '$($Resource.Name)' version '$($Resource.Version)' manifest version '$manifestBaseVersion' does not match expected base version '$($versionInfo.BaseVersion)'."
    }

    $manifestPrerelease = Get-CdrManifestPrerelease -Manifest $manifest
    if ($manifestPrerelease -ne $versionInfo.Prerelease) {
        throw "Saved module '$($Resource.Name)' version '$($Resource.Version)' prerelease '$manifestPrerelease' does not match expected prerelease '$($versionInfo.Prerelease)'."
    }

    $metadataPath = Join-Path -Path $VersionRoot -ChildPath 'PSGetModuleInfo.xml'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw "Saved module '$($Resource.Name)' version '$($Resource.Version)' is missing generated metadata '$metadataPath'."
    }

    $metadata = Get-CdrMetadataInfo -MetadataPath $metadataPath
    if ($metadata.Name -ne $Resource.Name) {
        throw "Saved module metadata name '$($metadata.Name)' does not match expected name '$($Resource.Name)'."
    }

    if ($metadata.Version.ToString() -ne $versionInfo.BaseVersion) {
        throw "Saved module metadata version '$($metadata.Version)' does not match expected base version '$($versionInfo.BaseVersion)'."
    }

    $normalizedVersion = Get-CdrMetadataNormalizedVersion -Metadata $metadata
    if ($normalizedVersion -ne $versionInfo.FullVersion) {
        throw "Saved module metadata normalized version '$normalizedVersion' does not match expected exact version '$($versionInfo.FullVersion)'."
    }

    if ($metadata.InstalledLocation -ne $ExpectedInstalledLocation) {
        throw "Saved module metadata installed location '$($metadata.InstalledLocation)' does not match expected location '$ExpectedInstalledLocation'."
    }

    $metadata
}

function Update-CdrMetadataInstalledLocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetadataPath,

        [Parameter(Mandatory = $true)]
        [string]$InstalledLocation
    )

    $metadata = Get-CdrMetadataInfo -MetadataPath $MetadataPath
    $metadata.InstalledLocation = $InstalledLocation

    $writeError = $null
    $succeeded = $metadata.TryWrite($MetadataPath, [ref]$writeError)
    if (-not $succeeded) {
        $message = if ($writeError) { $writeError } else { 'Unknown PSResourceInfo write failure.' }
        throw "Failed to update PSResourceGet metadata '$MetadataPath': $message"
    }
}

function Get-CdrDiscoveredInstalledResource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Resource,

        [Parameter(Mandatory = $true)]
        [string]$ModulesRoot
    )

    $versionInfo = Split-CdrResourceVersion -Version $Resource.Version
    @(Get-PSResource -Name $Resource.Name -ErrorAction SilentlyContinue) |
        Where-Object {
            if (-not $_) {
                return $false
            }

            $installedPrerelease = if ($_.Prerelease) { $_.Prerelease } else { $null }
            $_.InstalledLocation -eq $ModulesRoot -and
            $_.Version.ToString() -eq $versionInfo.BaseVersion -and
            $installedPrerelease -eq $versionInfo.Prerelease
        } |
        Select-Object -First 1
}

function Invoke-CdrDirectoryMove {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    Move-Item -LiteralPath $LiteralPath -Destination $Destination -ErrorAction Stop
}

function Remove-CdrInstalledVersionDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return
    }

    Remove-Item -LiteralPath $LiteralPath -Recurse -Force -ErrorAction Stop

    $moduleRoot = Split-Path -Path $LiteralPath -Parent
    if ($moduleRoot -and (Test-Path -LiteralPath $moduleRoot)) {
        $remainingEntries = @(Get-ChildItem -LiteralPath $moduleRoot -Force -ErrorAction Stop)
        if ($remainingEntries.Count -eq 0) {
            Remove-Item -LiteralPath $moduleRoot -Force -ErrorAction Stop
        }
    }

    function Remove-CdrEmptyDirectory {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$LiteralPath
        )

        if (-not (Test-Path -LiteralPath $LiteralPath)) {
            return
        }

        $entries = @(Get-ChildItem -LiteralPath $LiteralPath -Force -ErrorAction Stop)
        if ($entries.Count -eq 0) {
            Remove-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        }
    }
}

function Install-CdrVerifiedResources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Resources,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [string]$Scope,

        [Parameter(Mandatory = $false)]
        [string]$Repository,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$Prerelease,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if ($Resources.Count -eq 1 -and
        $Resources[0] -is [System.Collections.IEnumerable] -and
        -not ($Resources[0] -is [string]) -and
        -not $Resources[0].PSObject.Properties['Name']) {
        $Resources = @($Resources[0])
    }

    if (-not $Resources -or $Resources.Count -eq 0) {
        return
    }

    $modulesRoot = Get-CdrLinuxModuleRoot -Scope $Scope
    if (Test-Path -LiteralPath $modulesRoot) {
        $rootItem = Get-Item -LiteralPath $modulesRoot -ErrorAction Stop
        if (-not $rootItem.PSIsContainer) {
            throw "PowerShell module root '$modulesRoot' is not a directory."
        }
        if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "PowerShell module root '$modulesRoot' must not be a symlink or reparse point because checked promotion requires same-filesystem directory moves."
        }
    }
    else {
        $null = New-Item -ItemType Directory -Path $modulesRoot -Force -ErrorAction Stop
    }

    $operationId = [guid]::NewGuid().ToString('N')
    $lockPath = Join-Path -Path $modulesRoot -ChildPath '.microsoft.avs.cdr.install.lock'
    $lockStream = $null
    $operationRoot = $null
    $promotedDestinations = [System.Collections.Generic.List[string]]::new()
    $backupMoves = [System.Collections.Generic.List[object]]::new()
    $cleanupPaths = [System.Collections.Generic.List[string]]::new()
    $preserveRecoveryEvidence = $false
    $preparedResources = @()

    try {
        try {
            $lockStream = [System.IO.File]::Open(
                $lockPath,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None)
            $lockPayload = [System.Text.Encoding]::UTF8.GetBytes("pid=$PID`nop=$operationId")
            $lockStream.SetLength(0)
            $lockStream.Write($lockPayload, 0, $lockPayload.Length)
            $lockStream.Flush()
        }
        catch {
            throw "Failed to acquire checked-install lock for '$modulesRoot': $($_.Exception.Message)"
        }

        $modulesRootParent = Split-Path -Path $modulesRoot -Parent
        $operationRoot = Join-Path -Path $modulesRootParent -ChildPath ".microsoft.avs.cdr/$operationId"
        $stagingModulesRoot = Join-Path -Path $operationRoot -ChildPath 'staging'
        $backupRoot = Join-Path -Path $operationRoot -ChildPath 'backups'
        $null = New-Item -ItemType Directory -Path $stagingModulesRoot -Force -ErrorAction Stop
        $null = New-Item -ItemType Directory -Path $backupRoot -Force -ErrorAction Stop
        $cleanupPaths.Add($operationRoot) | Out-Null

        $preparedResources = foreach ($resource in $Resources) {
            $destinationPaths = Get-CdrResourceDestinationPaths -ModulesRoot $modulesRoot -Resource $resource
            $stagingPaths = Get-CdrResourceDestinationPaths -ModulesRoot $stagingModulesRoot -Resource $resource
            $versionInfo = $destinationPaths.VersionInfo

            $useExistingDestination = (-not $Force) -and (Test-CdrExactResourceDirectory -VersionRoot $destinationPaths.VersionRoot)
            if ($useExistingDestination) {
                Assert-CdrSavedModuleIdentity -Resource $resource -VersionRoot $destinationPaths.VersionRoot -ExpectedInstalledLocation $modulesRoot | Out-Null
                [pscustomobject]@{
                    Resource = $resource
                    VersionInfo = $versionInfo
                    DestinationRoot = $destinationPaths.VersionRoot
                    DestinationModuleRoot = $destinationPaths.ModuleRoot
                    StageRoot = $null
                    NeedsPromotion = $false
                }

                continue
            }

            $saveParams = @{
                Name = $resource.Name
                Version = $resource.Version
                Path = $stagingModulesRoot
                TrustRepository = $true
                SkipDependencyCheck = $true
                IncludeXml = $true
                ErrorAction = 'Stop'
            }

            $selectedRepository = if ($Repository) { $Repository } else { $resource.Repository }
            if ($selectedRepository) {
                $saveParams['Repository'] = $selectedRepository
            }
            if ($Credential) {
                $saveParams['Credential'] = $Credential
            }
            if ($Prerelease -or $versionInfo.Prerelease) {
                $saveParams['Prerelease'] = $true
            }

            Save-PSResource @saveParams
            Assert-CdrSavedModuleIdentity -Resource $resource -VersionRoot $stagingPaths.VersionRoot -ExpectedInstalledLocation $stagingModulesRoot | Out-Null

            [pscustomobject]@{
                Resource = $resource
                VersionInfo = $versionInfo
                DestinationRoot = $destinationPaths.VersionRoot
                DestinationModuleRoot = $destinationPaths.ModuleRoot
                StageRoot = $stagingPaths.VersionRoot
                NeedsPromotion = $true
            }
        }

        foreach ($prepared in $preparedResources) {
            $moduleDirectory = if ($prepared.NeedsPromotion) { $prepared.StageRoot } else { $prepared.DestinationRoot }
            Assert-CdrModuleSignature -ModuleDirectory $moduleDirectory `
                -ModuleName $prepared.Resource.Name -ModuleVersion $prepared.Resource.Version
        }

        foreach ($prepared in $preparedResources | Where-Object NeedsPromotion) {
            Update-CdrMetadataInstalledLocation -MetadataPath (Join-Path $prepared.StageRoot 'PSGetModuleInfo.xml') `
                -InstalledLocation $modulesRoot
        }

        foreach ($prepared in $preparedResources | Where-Object NeedsPromotion) {
            $destinationParent = Split-Path -Path $prepared.DestinationRoot -Parent
            if (-not (Test-Path -LiteralPath $destinationParent)) {
                $null = New-Item -ItemType Directory -Path $destinationParent -Force -ErrorAction Stop
            }

            if ($Force -and (Test-Path -LiteralPath $prepared.DestinationRoot)) {
                $backupDestination = Join-Path -Path $backupRoot -ChildPath (Join-Path $prepared.Resource.Name $prepared.VersionInfo.BaseVersion)
                $backupParent = Split-Path -Path $backupDestination -Parent
                if (-not (Test-Path -LiteralPath $backupParent)) {
                    $null = New-Item -ItemType Directory -Path $backupParent -Force -ErrorAction Stop
                }

                Invoke-CdrDirectoryMove -LiteralPath $prepared.DestinationRoot -Destination $backupDestination
                $backupMoves.Add([pscustomobject]@{
                    DestinationRoot = $prepared.DestinationRoot
                    BackupRoot = $backupDestination
                }) | Out-Null
            }

            try {
                Invoke-CdrDirectoryMove -LiteralPath $prepared.StageRoot -Destination $prepared.DestinationRoot
                $promotedDestinations.Add($prepared.DestinationRoot) | Out-Null
            }
            catch {
                if ((-not (Test-Path -LiteralPath $prepared.StageRoot)) -and (Test-Path -LiteralPath $prepared.DestinationRoot)) {
                    $promotedDestinations.Add($prepared.DestinationRoot) | Out-Null
                }

                throw
            }
        }

        foreach ($resource in $Resources) {
            $discovered = Get-CdrDiscoveredInstalledResource -Resource $resource -ModulesRoot $modulesRoot
            if (-not $discovered) {
                throw "Installed resource '$($resource.Name)' version '$($resource.Version)' was not discoverable through Get-PSResource at '$modulesRoot' after promotion."
            }
        }

        foreach ($backup in $backupMoves) {
            if (Test-Path -LiteralPath $backup.BackupRoot) {
                Remove-Item -LiteralPath $backup.BackupRoot -Recurse -Force -ErrorAction Stop
            }
        }
    }
    catch {
        $originalError = $_
        $rollbackIssues = [System.Collections.Generic.List[string]]::new()

        foreach ($destination in @($promotedDestinations.ToArray()) | Sort-Object -Descending) {
            if (Test-Path -LiteralPath $destination) {
                try {
                    Remove-CdrInstalledVersionDirectory -LiteralPath $destination
                }
                catch {
                    $rollbackIssues.Add($destination) | Out-Null
                }
            }
        }

        foreach ($backup in @($backupMoves.ToArray()) | Sort-Object DestinationRoot -Descending) {
            if (Test-Path -LiteralPath $backup.BackupRoot) {
                try {
                    $restoreParent = Split-Path -Path $backup.DestinationRoot -Parent
                    if (-not (Test-Path -LiteralPath $restoreParent)) {
                        $null = New-Item -ItemType Directory -Path $restoreParent -Force -ErrorAction Stop
                    }

                    Invoke-CdrDirectoryMove -LiteralPath $backup.BackupRoot -Destination $backup.DestinationRoot
                }
                catch {
                    $rollbackIssues.Add($backup.BackupRoot) | Out-Null
                    $rollbackIssues.Add($backup.DestinationRoot) | Out-Null
                }
            }
        }

        foreach ($prepared in $preparedResources) {
            try {
                Remove-CdrEmptyDirectory -LiteralPath $prepared.DestinationModuleRoot
            }
            catch {
                $rollbackIssues.Add($prepared.DestinationModuleRoot) | Out-Null
            }
        }

        if ($rollbackIssues.Count -gt 0) {
            $preserveRecoveryEvidence = $true
            $issueList = ($rollbackIssues | Select-Object -Unique) -join ', '
            throw "Failed to install verified resources and rollback was incomplete after '$($originalError.Exception.Message)'. Preserved recovery paths: $issueList"
        }

        throw
    }
    finally {
        if ($lockStream) {
            $lockStream.Dispose()
        }

        if ($lockPath -and -not $preserveRecoveryEvidence -and (Test-Path -LiteralPath $lockPath)) {
            Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
        }

        if (-not $preserveRecoveryEvidence) {
            foreach ($cleanupPath in ($cleanupPaths | Sort-Object -Descending)) {
                if (Test-Path -LiteralPath $cleanupPath) {
                    Remove-Item -LiteralPath $cleanupPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}
