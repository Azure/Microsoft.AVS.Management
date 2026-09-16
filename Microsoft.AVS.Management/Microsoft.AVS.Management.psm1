<# Private Function Import #>
. $PSScriptRoot\AVSGenericUtils.ps1

function Test-ToolsRepoUploadInput {
    param(
        [string]$SourceDatastoreName,
        [string]$ToolsZipPath,
        [string]$ExpectedHash
    )

    if ([string]::IsNullOrWhiteSpace($SourceDatastoreName) -or
        [string]::IsNullOrWhiteSpace($ToolsZipPath) -or
        [string]::IsNullOrWhiteSpace($ExpectedHash)) {
        throw "SourceDatastoreName, ToolsZipPath, and ExpectedHash are required when -Validate is not specified."
    }

    if ($ExpectedHash -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "ExpectedHash must be a valid SHA-256 hash containing exactly 64 hexadecimal characters."
    }

    $toolsZipPathSegments = $ToolsZipPath -split '/'
    $containsUnsafePathSegment = @($toolsZipPathSegments | Where-Object {
            [string]::IsNullOrWhiteSpace($_) -or $_ -eq '.' -or $_ -eq '..'
        }).Count -gt 0

    if ($toolsZipPathSegments[0] -eq 'GuestStore') {
        throw "ToolsZipPath must not be inside the managed GuestStore folder. Upload the zip file to a separate staging folder."
    }

    if ([System.IO.Path]::IsPathRooted($ToolsZipPath) -or
        $ToolsZipPath.StartsWith('/') -or
        $ToolsZipPath -match '[\\:*?\[\]]' -or
        $ToolsZipPath -notmatch '(?i)\.zip$' -or
        $containsUnsafePathSegment) {
        throw "ToolsZipPath must be a safe relative path to a zip file on the source datastore."
    }
}

function Get-ToolsRepoVsanDatastore {
    try {
        $datastores = @(Get-Datastore -ErrorAction Stop | Where-Object { $_.ExtensionData.Summary.Type -eq 'vsan' })

        if ($datastores.Count -eq 0) {
            throw "No vSAN datastores found in the environment"
        }

        Write-Information "Found $($datastores.Count) vSAN datastore(s)" -InformationAction Continue
        return $datastores
    } catch {
        throw "Failed to retrieve vSAN datastores: $_"
    }
}

function ConvertTo-ToolsRepoVersionInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $versionIdentifierPattern = '\d+(?:\.\d+){1,3}(?:-\d+(?:\.\d+)*)?'
    $plainVersionPattern = "^(?<Identifier>$versionIdentifierPattern)$"
    $namedVersionPattern = "(?i)^(?:gueststore-vmtools|vmware-tools|vmtools)-(?<Identifier>$versionIdentifierPattern)(?:\.(?:tar\.gz|zip|tgz|tar|gz|exe|msi|vib))?$"
    $candidate = [System.IO.Path]::GetFileName(($Value -replace '\\', '/'))

    if ($candidate -match $plainVersionPattern -or $candidate -match $namedVersionPattern) {
        $identifier = $Matches.Identifier
        $identifierParts = $identifier -split '-', 2
        $buildParts = @()

        if ($identifierParts.Count -eq 2) {
            $buildParts = @($identifierParts[1] -split '\.' | ForEach-Object { [long]$_ })
        }

        return [pscustomobject]@{
            Identifier = $identifier
            ReleaseParts = @($identifierParts[0] -split '\.' | ForEach-Object { [long]$_ })
            BuildParts = $buildParts
        }
    }

    return $null
}

function Compare-ToolsRepoVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,
        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    $leftVersion = ConvertTo-ToolsRepoVersionInfo -Value $Left
    $rightVersion = ConvertTo-ToolsRepoVersionInfo -Value $Right

    if ($null -eq $leftVersion -or $null -eq $rightVersion) {
        throw "Cannot compare invalid VMware Tools versions '$Left' and '$Right'."
    }

    $releasePartCount = [Math]::Max($leftVersion.ReleaseParts.Count, $rightVersion.ReleaseParts.Count)
    for ($index = 0; $index -lt $releasePartCount; $index++) {
        $leftPart = if ($index -lt $leftVersion.ReleaseParts.Count) { $leftVersion.ReleaseParts[$index] } else { 0 }
        $rightPart = if ($index -lt $rightVersion.ReleaseParts.Count) { $rightVersion.ReleaseParts[$index] } else { 0 }

        if ($leftPart -lt $rightPart) {
            return -1
        }
        if ($leftPart -gt $rightPart) {
            return 1
        }
    }

    # A build is compared only when both values include one.
    if ($leftVersion.BuildParts.Count -eq 0 -or $rightVersion.BuildParts.Count -eq 0) {
        return 0
    }

    $partCount = [Math]::Max($leftVersion.BuildParts.Count, $rightVersion.BuildParts.Count)
    for ($index = 0; $index -lt $partCount; $index++) {
        $leftPart = if ($index -lt $leftVersion.BuildParts.Count) { $leftVersion.BuildParts[$index] } else { 0 }
        $rightPart = if ($index -lt $rightVersion.BuildParts.Count) { $rightVersion.BuildParts[$index] } else { 0 }

        if ($leftPart -lt $rightPart) {
            return -1
        }
        if ($leftPart -gt $rightPart) {
            return 1
        }
    }

    return 0
}

function Get-ToolsRepoMetadataVersion {
    param(
        [Parameter(Mandatory = $true)]
        $MetadataObject,

        [Parameter(Mandatory = $true)]
        [string]$LatestVersion
    )

    if ($null -eq $MetadataObject) {
        return $null
    }

    $candidateVersions = @()

    # Leaf metadata stores the active VMware Tools version in installer.version.
    if ($MetadataObject.PSObject.Properties.Name -contains 'installer' -and $null -ne $MetadataObject.installer) {
        $installerObject = $MetadataObject.installer

        if ($installerObject.PSObject.Properties.Name -contains 'version') {
            $installerVersion = ConvertTo-ToolsRepoVersionInfo -Value ([string]$installerObject.version)
            if ($null -ne $installerVersion) {
                $candidateVersions += $installerVersion.Identifier
            }
        }
    }

    # Collection metadata stores the active folder in vmtools. Ignore its
    # schema version and historical vmtools-* entries.
    if ($MetadataObject.PSObject.Properties.Name -contains 'vmtools') {
        $activeVmtoolsFolder = ([string]$MetadataObject.vmtools) -replace '[\\/]+$', ''
        $vmtoolsField = ConvertTo-ToolsRepoVersionInfo -Value $activeVmtoolsFolder
        if ($null -ne $vmtoolsField) {
            $candidateVersions += $vmtoolsField.Identifier
        }
    }

    if ($candidateVersions.Count -gt 0) {
        $uniqueCandidates = @($candidateVersions | Select-Object -Unique)
        foreach ($candidateVersion in $uniqueCandidates) {
            if ((Compare-ToolsRepoVersion -Left $candidateVersion -Right $LatestVersion) -ne 0) {
                return $null
            }
        }

        # Return the selected folder version only when all metadata indicators agree.
        return $LatestVersion
    }

    return $null
}

function Get-ToolsRepoHighestVersionFolder {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Directories
    )

    $highestVersionFolder = $null
    $highestVersionIdentifier = $null

    foreach ($directory in $Directories) {
        $versionInformation = ConvertTo-ToolsRepoVersionInfo -Value ([string]$directory.Name)
        if ($null -eq $versionInformation -or $directory.Name -notmatch '^vmtools-') {
            continue
        }

        if ($null -eq $highestVersionIdentifier -or
            (Compare-ToolsRepoVersion -Left $versionInformation.Identifier -Right $highestVersionIdentifier) -gt 0) {
            $highestVersionIdentifier = $versionInformation.Identifier
            $highestVersionFolder = $directory
        }
    }

    return $highestVersionFolder
}

function Get-ToolsRepoDestinationPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GuestStoreFolder,
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,
        [Parameter(Mandatory = $true)]
        [string]$DriveName
    )

    return Join-Path -Path "${DriveName}:/$GuestStoreFolder" -ChildPath $ArchivePath
}

function Remove-ToolsRepoPSDrive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-PSDrive -Name $Name -ErrorAction SilentlyContinue)) {
        return
    }

    Remove-PSDrive -Name $Name -Force -ErrorAction SilentlyContinue
    if (Get-PSDrive -Name $Name -ErrorAction SilentlyContinue) {
        throw "Failed to remove temporary PSDrive '$Name'."
    }
}

function Get-ToolsRepoCombinedFailureMessage {
    param(
        [AllowNull()]
        [string]$OperationFailure,
        [AllowNull()]
        [string]$CleanupFailure
    )

    if (-not [string]::IsNullOrWhiteSpace($OperationFailure) -and
        -not [string]::IsNullOrWhiteSpace($CleanupFailure)) {
        return "$OperationFailure Additionally, cleanup failed: $CleanupFailure"
    }

    if (-not [string]::IsNullOrWhiteSpace($OperationFailure)) {
        return $OperationFailure
    }

    if (-not [string]::IsNullOrWhiteSpace($CleanupFailure)) {
        return "Cleanup failed: $CleanupFailure"
    }

    return $null
}

function Copy-ToolsRepoArchive {
    param(
        [Parameter(Mandatory = $true)]
        $SourceDatastore,
        [Parameter(Mandatory = $true)]
        [string]$ToolsZipPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash,
        [Parameter(Mandatory = $true)]
        [string]$LocalToolsFile,
        [Parameter(Mandatory = $true)]
        [string]$SourceDriveName
    )

    $sourceDriveCreated = $false
    $operationFailure = $null
    $cleanupFailure = $null

    try {
        if (Get-PSDrive -Name $SourceDriveName -ErrorAction SilentlyContinue) {
            throw "Temporary source PSDrive name '$SourceDriveName' is already in use."
        }

        New-PSDrive -Location $SourceDatastore -Name $SourceDriveName -PSProvider VimDatastore -Root '\' -ErrorAction Stop | Out-Null
        $sourceDriveCreated = $true

        $sourceItemPath = "${SourceDriveName}:/$ToolsZipPath"
        if (-not (Test-Path -Path $sourceItemPath -PathType Leaf)) {
            throw "Tools zip file was not found on datastore '$($SourceDatastore.Name)' at path '$ToolsZipPath'."
        }

        Write-Information "Copying tools zip from datastore '$($SourceDatastore.Name)'..." -InformationAction Continue
        Copy-DatastoreItem -Item $sourceItemPath -Destination $LocalToolsFile -Force -ErrorAction Stop | Out-Null

        if (-not (Test-Path -LiteralPath $LocalToolsFile -PathType Leaf)) {
            throw "Tools zip file was not copied to the local temporary directory."
        }

        $fileSize = (Get-Item -LiteralPath $LocalToolsFile -ErrorAction Stop).Length
        if ($fileSize -eq 0) {
            throw "Tools zip file is empty."
        }

        Write-Verbose "Copied tools file size: $($fileSize / 1MB) MB"
        Write-Information "Verifying tools zip SHA-256 hash..." -InformationAction Continue

        $actualHash = (Get-FileHash -LiteralPath $LocalToolsFile -Algorithm SHA256 -ErrorAction Stop).Hash
        if (-not [string]::Equals($actualHash, $ExpectedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "SHA-256 hash mismatch. Expected: $ExpectedHash. Actual: $actualHash."
        }

        Write-Information "Tools zip SHA-256 hash verified successfully." -InformationAction Continue
    } catch {
        $operationFailure = "Failed to prepare tools zip from source datastore: $($_.Exception.Message)"
    } finally {
        if ($sourceDriveCreated) {
            try {
                Remove-ToolsRepoPSDrive -Name $SourceDriveName
            } catch {
                $cleanupFailure = $_.Exception.Message
            }
        }
    }

    $failureMessage = Get-ToolsRepoCombinedFailureMessage -OperationFailure $operationFailure -CleanupFailure $cleanupFailure
    if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
        throw $failureMessage
    }
}

function Expand-ToolsRepoArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalToolsFile,
        [Parameter(Mandatory = $true)]
        [string]$TemporaryDirectory,
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    try {
        Write-Information "Extracting tools archive..." -InformationAction Continue
        Expand-Archive -LiteralPath $LocalToolsFile -DestinationPath $TemporaryDirectory -Force -ErrorAction Stop
    } catch {
        throw "Failed to extract tools archive: $_"
    }

    $windows64Path = Join-Path -Path $TemporaryDirectory -ChildPath $ArchivePath
    if (-not (Test-Path -Path $windows64Path)) {
        throw "windows64 directory not found in extracted archive at: $windows64Path"
    }

    Write-Information "windows64 directory located - will validate metadata.json files next" -InformationAction Continue

    $topLevelMetadataPath = Join-Path -Path $windows64Path -ChildPath 'metadata.json'
    if (-not (Test-Path -Path $topLevelMetadataPath)) {
        throw "metadata.json not found in windows64 directory at: $topLevelMetadataPath"
    }

    Write-Information "metadata.json found in windows64 directory: $topLevelMetadataPath" -InformationAction Continue

    $vmtoolsFolders = @(Get-ChildItem -Path $windows64Path -Directory | Where-Object {
            $_.Name -match '^vmtools-\d+(?:\.\d+){1,3}(?:-\d+(?:\.\d+)*)?$'
        })
    if ($vmtoolsFolders.Count -eq 0) {
        throw "No vmtools folder found inside windows64 at: $windows64Path"
    }

    $vmtoolsFolder = Get-ToolsRepoHighestVersionFolder -Directories $vmtoolsFolders
    $vmtoolsFolderPath = $vmtoolsFolder.FullName
    Write-Information "Found vmtools folder: $($vmtoolsFolder.Name) at $vmtoolsFolderPath" -InformationAction Continue

    $versionMetadataPath = Join-Path -Path $vmtoolsFolderPath -ChildPath 'metadata.json'
    if (-not (Test-Path -Path $versionMetadataPath)) {
        throw "metadata.json not found inside vmtools folder at: $versionMetadataPath"
    }

    Write-Information "metadata.json found inside vmtools folder: $versionMetadataPath" -InformationAction Continue
    Write-Information "Archive structure validation passed: required folders and metadata files were found. Proceeding to datastore operations." -InformationAction Continue

    $toolsVersion = Split-Path -Path $vmtoolsFolderPath -Leaf
    if ([string]::IsNullOrEmpty($toolsVersion) -or
        $toolsVersion -notmatch '^vmtools-\d+(?:\.\d+){1,3}(?:-\d+(?:\.\d+)*)?$') {
        throw "Invalid vmtools folder name detected at: $vmtoolsFolderPath"
    }

    Write-Information "Found tools version: $toolsVersion" -InformationAction Continue

    try {
        $topLevelMetadataObject = Get-Content -LiteralPath $topLevelMetadataPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $versionMetadataObject = Get-Content -LiteralPath $versionMetadataPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Failed to parse metadata.json in extracted archive: $($_.Exception.Message)"
    }

    $toolsShortVersion = $toolsVersion -replace 'vmtools-', ''
    $topLevelMetadataVersion = Get-ToolsRepoMetadataVersion -MetadataObject $topLevelMetadataObject -LatestVersion $toolsShortVersion
    $versionMetadataVersion = Get-ToolsRepoMetadataVersion -MetadataObject $versionMetadataObject -LatestVersion $toolsShortVersion

    if ($topLevelMetadataVersion -ne $toolsShortVersion -or $versionMetadataVersion -ne $toolsShortVersion) {
        throw "Archive metadata versions must match extracted VMware Tools version '$toolsShortVersion'. Top-level metadata version: '$topLevelMetadataVersion'. Version-folder metadata version: '$versionMetadataVersion'."
    }

    Write-Information "Archive metadata versions match extracted VMware Tools version: $toolsShortVersion" -InformationAction Continue

    return @{
        TopLevelMetadataPath = $topLevelMetadataPath
        VmtoolsFolderPath = $vmtoolsFolderPath
        ToolsVersion = $toolsVersion
        ToolsShortVersion = $toolsShortVersion
    }
}

function Invoke-ToolsRepoHostRepositoryConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        $Datastore,
        [Parameter(Mandatory = $true)]
        [string]$GuestStoreFolder
    )

    $datastoreName = $Datastore.Name
    $repositoryUrl = $Datastore.ExtensionData.Summary.Url + $GuestStoreFolder

    try {
        $datastoreId = $Datastore.Id
        $vmHosts = @(Get-VMHost -ErrorAction Stop | Where-Object {
                $_.ExtensionData.Datastore.value -contains ($datastoreId.Split('-', 2)[1])
            })

        if ($vmHosts.Count -eq 0) {
            throw "No hosts found for datastore $datastoreName"
        }

        Write-Information "Configuring $($vmHosts.Count) host(s) for datastore $datastoreName" -InformationAction Continue
    } catch {
        throw "Failed to retrieve hosts for datastore $datastoreName : $_"
    }

    $failedHosts = @()
    $failedHostReasons = @()
    foreach ($vmHost in $vmHosts) {
        try {
            $esxCli = Get-EsxCli -V2 -VMHost $vmHost -ErrorAction Stop
            Write-Verbose "Setting GuestStore repository for host: $vmHost"

            $arguments = $esxCli.system.settings.gueststore.repository.set.CreateArgs()
            $arguments.url = $repositoryUrl
            $result = $esxCli.system.settings.gueststore.repository.set.invoke($arguments)

            if ($result -ne $true) {
                throw "ESXCLI failed to configure the GuestStore repository"
            }

            Write-Information "Successfully configured host: $vmHost" -InformationAction Continue
        } catch {
            $hostFailure = $_.Exception.Message
            if ([string]::IsNullOrWhiteSpace($hostFailure)) {
                $hostFailure = [string]$_
            }

            Write-Warning "Failed to configure host $vmHost : $hostFailure"
            $failedHosts += $vmHost.Name
            $failedHostReasons += "'$($vmHost.Name)': $hostFailure"
        }
    }

    if ($failedHosts.Count -gt 0) {
        throw "Failed to configure hosts for datastore $datastoreName : $($failedHosts -join ', '). Failure details: $($failedHostReasons -join '; '). Check the failed hosts for connectivity or ESXCLI issues, then rerun Set-ToolsRepo with the same parameters. Run Command will retry configuring the GuestStore repository on all hosts."
    }
}

<#
    .SYNOPSIS
    Manages the Tools Repository on vSAN datastores for VMware Tools deployment.

    .DESCRIPTION
    This function creates a GuestStore folder on each cluster's vSAN datastore and configures
    hosts to pull VMware Tools from their respective vSAN datastore. The GuestStore version of the VMware Tools ZIP package is required.

    When -Validate is specified, only reads and validates metadata.json files without making changes.
    When -Validate is NOT specified, first upload the VMware Tools GuestStore zip file to a
    staging folder on one vSAN datastore by using the vCenter datastore browser. The function
    copies the zip file to an isolated temporary directory and verifies its SHA-256 hash before
    extraction. If the hash does not match, no GuestStore datastore or host configuration changes
    are made. After successful verification, the function uploads the extracted tools to the
    GuestStore repository on each vSAN datastore and configures the associated hosts.

    .PARAMETER SourceDatastoreName
    Exact name of the vSAN datastore containing the staged Tools zip file. Required when
    -Validate is NOT specified.

    .PARAMETER ToolsZipPath
    Path to the staged Tools zip file, relative to the source datastore root. Required when
    -Validate is NOT specified. Do not upload the zip file inside the managed GuestStore folder.
    For example: AVS-ToolsRepo-Staging/gueststore-vmtools-13.0.5-0.24916190.zip.

    .PARAMETER ExpectedHash
    Trusted SHA-256 hash published for the exact staged Tools zip file. Required when -Validate
    is NOT specified. The value must contain exactly 64 hexadecimal characters. The function
    stops before extraction when the calculated hash does not match this value.

    .PARAMETER Validate
    Switch to enable validation-only mode. When set, the function reads metadata.json files
    to verify they are in sync, but makes no changes to the datastore or host configuration.

    .EXAMPLE
    # Upload tools to repositories
    Set-ToolsRepo -SourceDatastoreName "vsanDatastore" -ToolsZipPath "AVS-ToolsRepo-Staging/gueststore-vmtools-13.0.5-0.24916190.zip" -ExpectedHash "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

    .EXAMPLE
    # Validate existing repositories (no upload)
    Set-ToolsRepo -Validate
#>
function Set-ToolsRepo {
    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $true)]
    param(
        [Parameter(Mandatory = $false,
            HelpMessage = 'Exact name of the vSAN datastore where the VMware Tools GuestStore ZIP was uploaded. Example: vsanDatastore.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $SourceDatastoreName,

        [Parameter(Mandatory = $false,
            HelpMessage = 'Path to the uploaded ZIP, relative to the datastore root. Example: AVS-ToolsRepo-Staging/gueststore-vmtools-13.0.5-0.24916190.zip. Do not upload it inside the managed GuestStore folder.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ToolsZipPath,

        [Parameter(Mandatory = $false,
            HelpMessage = 'The 64-character SHA-256 value for the exact ZIP. In the Broadcom Support Portal, open the required VMware Tools release, find the matching gueststore-vmtools ZIP row, and copy its SHA2 value.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExpectedHash,

        [Parameter(Mandatory = $false,
            HelpMessage = 'Select this option to check existing GuestStore metadata only. It does not upload files or change host settings.')]
        [switch]
        $Validate
    )

    # Initialize variables
    $new_folder = 'GuestStore'
    $normalizedArchivePath = 'vmware/apps/vmtools/windows64'
    $successfulDatastores = @()
    $failedDatastores = @()
    $tempWorkDir = $null
    $driveNameSuffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $srcPSDriveName = "AVSToolsSrc_$driveNameSuffix"
    $destPSDriveName = "AVSToolsDs_$driveNameSuffix"
    $destinationDriveCreated = $false

    # Main execution wrapped in try-catch-finally
    try {
        Write-Verbose "Starting Set-ToolsRepo"

        # Source datastore details and a trusted hash are required for upload mode.
        if (-not $Validate) {
            Test-ToolsRepoUploadInput -SourceDatastoreName $SourceDatastoreName -ToolsZipPath $ToolsZipPath -ExpectedHash $ExpectedHash
        }

        if ($Validate) {
            Write-Information "Running in validation-only mode. No upload or configuration changes will be made." -InformationAction Continue

            # Get vSAN datastores with error handling
            $datastores = @(Get-ToolsRepoVsanDatastore)
            $validationFailureReasons = @{}

            foreach ($datastore in $datastores) {
                $ds_name = $datastore.Name
                $localMetadataTempDir = $null
                $destinationDriveCreated = $false
                $operationFailure = $null
                $cleanupFailure = $null
                Write-Information "Validating datastore: $ds_name" -InformationAction Continue

                try {
                    if (Get-PSDrive -Name $destPSDriveName -ErrorAction SilentlyContinue) {
                        throw "Temporary destination PSDrive name '$destPSDriveName' is already in use."
                    }

                    try {
                        New-PSDrive -Location $datastore -Name $destPSDriveName -PSProvider VimDatastore -Root '\' -ErrorAction Stop | Out-Null
                        $destinationDriveCreated = $true
                    } catch {
                        throw "Failed to create PSDrive for datastore $ds_name : $_"
                    }

                    $destPath = Get-ToolsRepoDestinationPath -GuestStoreFolder $new_folder -ArchivePath $normalizedArchivePath -DriveName $destPSDriveName

                    if (-not (Test-Path -Path $destPath)) {
                        throw "GuestStore tools path not found on $ds_name : $destPath"
                    }

                    $existing_dirs = Get-ChildItem -Path $destPath -ErrorAction Stop |
                        Where-Object {
                            $_.PSIsContainer -and
                            $_.Name -match '^vmtools-\d+(?:\.\d+){1,3}(?:-\d+(?:\.\d+)*)?$'
                        }

                    if ($null -eq $existing_dirs -or $existing_dirs.Count -eq 0) {
                        throw "No vmtools-* version folders found on $ds_name under $destPath"
                    }

                    $highestVersionFolder = Get-ToolsRepoHighestVersionFolder -Directories @($existing_dirs)

                    if ($null -eq $highestVersionFolder) {
                        throw "No valid vmtools version folders could be parsed on $ds_name"
                    }

                    $latestDetectedVersionFolder = $highestVersionFolder.Name
                    $latestDetectedVersion = $latestDetectedVersionFolder -replace 'vmtools-', ''
                    Write-Host "Datastore $ds_name latest detected tools version: $latestDetectedVersionFolder"

                    $topLevelMetadataPath = Join-Path $destPath 'metadata.json'
                    $versionMetadataPath = Join-Path (Join-Path $destPath $latestDetectedVersionFolder) 'metadata.json'

                    if (-not (Test-Path -Path $topLevelMetadataPath)) {
                        throw "Top-level metadata.json not found on $ds_name at $topLevelMetadataPath"
                    }

                    if (-not (Test-Path -Path $versionMetadataPath)) {
                        throw "Version metadata.json not found on $ds_name at $versionMetadataPath"
                    }

                    # Copy metadata files locally because VimDatastore does not support Get-Content.
                    $localMetadataTempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("avs-validate-metadata-{0}-{1}" -f (Get-Date -Format 'yyyyMMddHHmmssfff'), [guid]::NewGuid().ToString('N'))
                    New-Item -Path $localMetadataTempDir -ItemType Directory -ErrorAction Stop | Out-Null

                    $localTopLevelMetadataPath = Join-Path -Path $localMetadataTempDir -ChildPath 'top-level-metadata.json'
                    $localVersionMetadataPath = Join-Path -Path $localMetadataTempDir -ChildPath 'version-metadata.json'

                    try {
                        Copy-DatastoreItem -Item $topLevelMetadataPath -Destination $localTopLevelMetadataPath -Force -ErrorAction Stop | Out-Null
                    } catch {
                        throw "Failed to copy top-level metadata.json from $ds_name : $($_.Exception.Message)"
                    }

                    try {
                        Copy-DatastoreItem -Item $versionMetadataPath -Destination $localVersionMetadataPath -Force -ErrorAction Stop | Out-Null
                    } catch {
                        throw "Failed to copy version metadata.json from $ds_name : $($_.Exception.Message)"
                    }

                    try {
                        $topLevelMetadataObj = Get-Content -Path $localTopLevelMetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                        $versionMetadataObj = Get-Content -Path $localVersionMetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    } catch {
                        throw "Failed to parse metadata.json content on $ds_name : $($_.Exception.Message)"
                    }

                    $topLevelMetadataVersion = Get-ToolsRepoMetadataVersion -MetadataObject $topLevelMetadataObj -LatestVersion $latestDetectedVersion
                    $versionFolderMetadataVersion = Get-ToolsRepoMetadataVersion -MetadataObject $versionMetadataObj -LatestVersion $latestDetectedVersion

                    Write-Host "Datastore $ds_name top-level metadata version: $topLevelMetadataVersion"
                    Write-Host "Datastore $ds_name version-folder metadata version: $versionFolderMetadataVersion"

                    $topLevelInSync = (-not [string]::IsNullOrEmpty($topLevelMetadataVersion)) -and ($topLevelMetadataVersion -eq $latestDetectedVersion)
                    $versionFolderInSync = (-not [string]::IsNullOrEmpty($versionFolderMetadataVersion)) -and ($versionFolderMetadataVersion -eq $latestDetectedVersion)

                    if (-not ($topLevelInSync -and $versionFolderInSync)) {
                        Write-Host "Datastore $ds_name validation result: FAILURE - metadata is not in sync."
                        if ([string]::IsNullOrEmpty($topLevelMetadataVersion)) {
                            Write-Warning "Unable to determine version from top-level metadata.json on $ds_name"
                        } elseif (-not $topLevelInSync) {
                            Write-Warning "top-level metadata.json version ($topLevelMetadataVersion) does not match latest detected version ($latestDetectedVersionFolder) on $ds_name"
                        }
                        if ([string]::IsNullOrEmpty($versionFolderMetadataVersion)) {
                            Write-Warning "Unable to determine version from version-folder metadata.json on $ds_name"
                        } elseif (-not $versionFolderInSync) {
                            Write-Warning "version-folder metadata.json version ($versionFolderMetadataVersion) does not match latest detected version ($latestDetectedVersionFolder) on $ds_name"
                        }
                        $operationFailure = "Metadata validation failed because the metadata files are not in sync with version '$latestDetectedVersion'."
                    }
                } catch {
                    $operationFailure = $_.Exception.Message
                    if ([string]::IsNullOrWhiteSpace($operationFailure)) {
                        $operationFailure = [string]$_
                    }
                } finally {
                    if (-not [string]::IsNullOrEmpty($localMetadataTempDir) -and (Test-Path -Path $localMetadataTempDir)) {
                        Remove-Item -Path $localMetadataTempDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    if ($destinationDriveCreated) {
                        try {
                            Remove-ToolsRepoPSDrive -Name $destPSDriveName
                        } catch {
                            $cleanupFailure = $_.Exception.Message
                        } finally {
                            $destinationDriveCreated = $false
                        }
                    }
                }

                $failureMessage = Get-ToolsRepoCombinedFailureMessage -OperationFailure $operationFailure -CleanupFailure $cleanupFailure
                if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
                    $failedDatastores += $ds_name
                    $validationFailureReasons[$ds_name] = $failureMessage
                } else {
                    Write-Host "Datastore $ds_name validation result: SUCCESS - metadata is in sync."
                    $successfulDatastores += $ds_name
                }
            }

            Write-Information "`n=== Validation Summary ===" -InformationAction Continue
            if ($successfulDatastores.Count -gt 0) {
                Write-Information "List of Datastores with metadata in sync: $($successfulDatastores -join ', ')" -InformationAction Continue
            }
            if ($failedDatastores.Count -gt 0) {
                Write-Warning "List of Datastores with metadata out of sync or validation failure: $($failedDatastores -join ', ')"
            }

            if ($failedDatastores.Count -gt 0) {
                $validationFailureDetails = @($failedDatastores | ForEach-Object {
                        $reason = $validationFailureReasons[$_]
                        if ([string]::IsNullOrWhiteSpace($reason)) {
                            $reason = 'No detailed failure reason captured.'
                        }

                        "'$_': $reason"
                    }) -join '; '

                if ($failedDatastores.Count -eq @($datastores).Count) {
                    throw "Validation failed for all datastores. Failure details: $validationFailureDetails"
                }

                throw "Validation failed for some datastores. Failure details: $validationFailureDetails"
            }

            return
        }

        $failedDatastoreReasons = @{}

        # Retrieve vSAN datastores once for source lookup and destination processing.
        $datastores = @(Get-ToolsRepoVsanDatastore)

        # Select one exact source datastore without wildcard matching.
        $sourceDatastores = @($datastores | Where-Object {
                [string]::Equals($_.Name, $SourceDatastoreName, [System.StringComparison]::OrdinalIgnoreCase)
            })

        if ($sourceDatastores.Count -eq 0) {
            throw "Source vSAN datastore '$SourceDatastoreName' was not found."
        }

        if ($sourceDatastores.Count -gt 1) {
            throw "Multiple vSAN datastores matched source name '$SourceDatastoreName'. Provide one unique datastore name."
        }

        $sourceDatastore = $sourceDatastores[0]

        # Use an isolated local directory for the copied archive.
        try {
            $tempWorkDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("avs-toolsrepo-{0}" -f [guid]::NewGuid().ToString('N'))
            New-Item -Path $tempWorkDir -ItemType Directory -ErrorAction Stop | Out-Null
            $tools_file = Join-Path -Path $tempWorkDir -ChildPath 'tools.zip'
        } catch {
            throw "Failed to create temporary work directory: $_"
        }

        # Copy the archive from the source datastore and verify its integrity.
        Copy-ToolsRepoArchive -SourceDatastore $sourceDatastore -ToolsZipPath $ToolsZipPath -ExpectedHash $ExpectedHash -LocalToolsFile $tools_file -SourceDriveName $srcPSDriveName

        # Extract the archive and get the paths needed for datastore processing.
        $archiveInformation = Expand-ToolsRepoArchive -LocalToolsFile $tools_file -TemporaryDirectory $tempWorkDir -ArchivePath $normalizedArchivePath
        $windows64_top_metadata_path = $archiveInformation.TopLevelMetadataPath
        $vmtools_folder_path = $archiveInformation.VmtoolsFolderPath
        $tools_version = $archiveInformation.ToolsVersion
        $tools_short_version = $archiveInformation.ToolsShortVersion

        # Process each datastore
        foreach ($datastore in $datastores) {
            $ds_name = $datastore.Name
            $destinationDriveCreated = $false
            $operationFailure = $null
            $cleanupFailure = $null
            Write-Information "Processing datastore: $ds_name" -InformationAction Continue

            try {
                if (Get-PSDrive -Name $destPSDriveName -ErrorAction SilentlyContinue) {
                    throw "Temporary destination PSDrive name '$destPSDriveName' is already in use."
                }

                # Create PS drive with error handling
                try {
                    New-PSDrive -Location $datastore -Name $destPSDriveName -PSProvider VimDatastore -Root '\' -ErrorAction Stop | Out-Null
                    $destinationDriveCreated = $true
                } catch {
                    throw "Failed to create PSDrive for datastore $ds_name : $_"
                }

                # Check if repo folder exists
                try {
                    $Dsbrowser = Get-View -Id $Datastore.Extensiondata.Browser -ErrorAction Stop
                    $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
                    $spec.Query += New-Object VMware.Vim.FolderFileQuery
                    $datastoreRoot = "[{0}]" -f $ds_name
                    $searchResult = $dsBrowser.SearchDatastore($datastoreRoot, $spec)
                    $folderObj = $searchResult.File | Where-Object { $_.FriendlyName -eq $new_folder }
                } catch {
                    throw "Failed to browse datastore $ds_name : $_"
                }

                # Create folder if it doesn't exist
                if ($null -eq $folderObj) {
                    try {
                        New-Item -ItemType Directory -Path "${destPSDriveName}:/$new_folder" -ErrorAction Stop | Out-Null
                        Write-Information "Created $new_folder directory on $ds_name" -InformationAction Continue
                    } catch {
                        throw "Failed to create $new_folder directory on $ds_name : $_"
                    }

                    # Verify folder creation
                    $searchResult = $dsBrowser.SearchDatastore($datastoreRoot, $spec)
                    $folderObj = $searchResult.File | Where-Object { $_.FriendlyName -eq $new_folder }

                    if ($null -eq $folderObj) {
                        throw "Folder verification failed after creation on $ds_name"
                    }
                }

                # Check existing tools versions to determine highest version
                $destPath = Get-ToolsRepoDestinationPath -GuestStoreFolder $new_folder -ArchivePath $normalizedArchivePath -DriveName $destPSDriveName
                $highestExistingVersion = $null
                $shouldUpdateTopLevelMetadata = $false

                if (Test-Path -Path $destPath) {
                    try {
                        $existing_dirs = Get-ChildItem -Path $destPath -ErrorAction Stop |
                            Where-Object {
                                $_.PSIsContainer -and
                                $_.Name -match '^vmtools-\d+(?:\.\d+){1,3}(?:-\d+(?:\.\d+)*)?$'
                            }

                        $highestExistingVersionFolder = Get-ToolsRepoHighestVersionFolder -Directories @($existing_dirs)
                        if ($null -ne $highestExistingVersionFolder) {
                            $highestExistingVersion = $highestExistingVersionFolder.Name -replace 'vmtools-', ''
                        }

                        if ($highestExistingVersion) {
                            Write-Information "Current highest version on $ds_name is $highestExistingVersion" -InformationAction Continue
                        }
                    } catch {
                        throw "Failed to check existing versions on $ds_name : $($_.Exception.Message)"
                    }
                }

                # Determine if we should update the top-level metadata.json
                # Only update if new version is greater than the highest existing version
                if ($null -eq $highestExistingVersion -or
                    (Compare-ToolsRepoVersion -Left $tools_short_version -Right $highestExistingVersion) -gt 0) {
                    $shouldUpdateTopLevelMetadata = $true
                    Write-Information "New version ($tools_short_version) is greater than existing ($highestExistingVersion). Top-level metadata.json will be updated." -InformationAction Continue
                } else {
                    Write-Information "New version ($tools_short_version) is not greater than existing ($highestExistingVersion). Top-level metadata.json will be preserved." -InformationAction Continue
                }

                # Always copy the new version (older versions are allowed)
                try {
                    Write-Information "Copying $tools_version to $ds_name..." -InformationAction Continue

                    # Use the discovered vmtools directory from the extracted archive as the source
                    $sourceDir = $vmtools_folder_path

                    # Ensure destination folder exists on the datastore
                    if (-not (Test-Path -Path $destPath)) {
                        New-Item -ItemType Directory -Path $destPath -Force -ErrorAction Stop | Out-Null
                    }

                    # Check if this version already exists on the datastore
                    $versionDestPath = Join-Path $destPath $tools_version
                    if (Test-Path -Path $versionDestPath) {
                        $versionMetadataPath = Join-Path -Path $versionDestPath -ChildPath 'metadata.json'
                        if (-not (Test-Path -Path $versionMetadataPath -PathType Leaf)) {
                            throw "Version folder '$tools_version' already exists on datastore '$ds_name', but its required metadata.json is missing. Inspect the folder and, if it is incomplete, remove it and rerun Set-ToolsRepo."
                        }

                        Write-Information "Version $tools_version already exists on $ds_name. Skipping copy." -InformationAction Continue
                    } else {
                        # Copy the vmtools-{version} folder itself (preserves folder structure)
                        Copy-DatastoreItem -Item $sourceDir -Destination $destPath -Recurse -Force -ErrorAction Stop | Out-Null

                        # Verify metadata.json exists in the copied version folder
                        $versionMeta = Get-ChildItem -Path $versionDestPath -Filter metadata.json -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                        if (-not $versionMeta) { throw "metadata.json not found in copied version folder on $ds_name" }

                        Write-Information "Successfully copied $tools_version to $ds_name" -InformationAction Continue
                    }

                    # Update top-level files only when the uploaded version is newer.
                    if ($shouldUpdateTopLevelMetadata) {
                        # Copy any additional top-level files from windows64, if present.
                        # Handle metadata.json separately below.
                        $topLevelSourceDir = Split-Path -Path $sourceDir -Parent
                        if (-not [string]::IsNullOrEmpty($topLevelSourceDir) -and (Test-Path -Path $topLevelSourceDir)) {
                            $topLevelFiles = Get-ChildItem -Path $topLevelSourceDir -File -ErrorAction SilentlyContinue |
                                Where-Object { $_.Name -ne 'metadata.json' }
                            foreach ($file in $topLevelFiles) {
                                $destFilePath = Join-Path -Path $destPath -ChildPath $file.Name
                                Copy-DatastoreItem -Item $file.FullName -Destination $destFilePath -Force -ErrorAction Stop | Out-Null
                            }
                            if ($topLevelFiles) {
                                Write-Information "Copied additional top-level files from windows64 to $ds_name" -InformationAction Continue
                            }
                        }

                        $topLevelMetadataPath = Join-Path $destPath "metadata.json"
                        Copy-DatastoreItem -Item $windows64_top_metadata_path -Destination $topLevelMetadataPath -Force -ErrorAction Stop | Out-Null
                        Write-Information "Updated top-level metadata.json on $ds_name to version $tools_short_version" -InformationAction Continue
                    } else {
                        Write-Information "Top-level files on $ds_name preserved (not overwritten)" -InformationAction Continue
                    }
                } catch {
                    throw "Failed to copy tools to $ds_name : $_"
                }

                # Configure all hosts associated with this datastore.
                Invoke-ToolsRepoHostRepositoryConfiguration -Datastore $datastore -GuestStoreFolder $new_folder
            } catch {
                $operationFailure = $_.Exception.Message
                if ([string]::IsNullOrWhiteSpace($operationFailure)) {
                    $operationFailure = [string]$_
                }
            } finally {
                # Remove only the destination drive created by this invocation.
                if ($destinationDriveCreated) {
                    try {
                        Remove-ToolsRepoPSDrive -Name $destPSDriveName
                    } catch {
                        $cleanupFailure = $_.Exception.Message
                    } finally {
                        $destinationDriveCreated = $false
                    }
                }
            }

            $failureMessage = Get-ToolsRepoCombinedFailureMessage -OperationFailure $operationFailure -CleanupFailure $cleanupFailure
            if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
                Write-Warning "Error processing datastore $ds_name : $failureMessage"
                $failedDatastores += $ds_name
                $failedDatastoreReasons[$ds_name] = $failureMessage
            } else {
                $successfulDatastores += $ds_name
            }
        }

        # Summary report
        Write-Information "`n=== Summary ===" -InformationAction Continue
        if ($successfulDatastores.Count -gt 0) {
            Write-Information "List of Successfully processed datastores: $($successfulDatastores -join ', ')" -InformationAction Continue
        }
        $failureDetails = @()
        if ($failedDatastores.Count -gt 0) {
            Write-Warning "List of Failed datastores: $($failedDatastores -join ', ')"

            foreach ($failedDs in $failedDatastores) {
                $reason = $failedDatastoreReasons[$failedDs]
                if ([string]::IsNullOrWhiteSpace($reason)) {
                    $reason = "No detailed failure reason captured."
                }

                Write-Warning "Failure reason for datastore $failedDs : $reason"
                $failureDetails += "'$failedDs': $reason"
            }
        }

        if ($failedDatastores.Count -gt 0) {
            $failureDetailsMessage = $failureDetails -join '; '
            if ($failedDatastores.Count -eq @($datastores).Count) {
                throw "All datastores failed to process. Failure details: $failureDetailsMessage"
            }

            throw "Some datastores failed to process. Failure details: $failureDetailsMessage"
        }
    } catch {
        throw "Set-ToolsRepo failed: $($_.Exception.Message)"
    } finally {
        # Remove only a destination drive created by this invocation.
        if ($destinationDriveCreated) {
            try {
                Remove-ToolsRepoPSDrive -Name $destPSDriveName
            } catch {
                Write-Warning "Final cleanup failed for temporary PSDrive '$destPSDriveName': $($_.Exception.Message)"
            } finally {
                $destinationDriveCreated = $false
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($tempWorkDir) -and (Test-Path -LiteralPath $tempWorkDir -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $tempWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

<#
    .Synopsis
        This allows the customer to change DRS from the default setting to 1-4 with 4 being the least conservative.
    .PARAMETER Drs
        The DRS setting to apply to the cluster.  3 is the default setting, 2 is one step more conservative (meaning less agressive in moving VMs).
    .PARAMETER ClustersToChange
        The clusters to apply the DRS setting to.  This can be a single cluster or a comma separated list of clusters or a wildcard.
    .EXAMPLE
        Set-CustomDRS -ClustersToChange "Cluster-1, Cluster-2" -Drs 2
        Set-CustomDRS -ClustersToChange "*" -Drs 3  # This returns it to the default setting
#>
function Set-CustomDRS {

    [AVSAttribute(15, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [String]$ClustersToChange,
        [Parameter(Mandatory = $true,
            HelpMessage = "The DRS setting. Default of 3 or more conservative of 2 or less conservative 4.")]
        [ValidateRange(1, 4)]
        [int] $Drs
    )

    switch ($Drs) {
        4 { $drsChange = 2 }
        3 { $drsChange = 3 }
        2 { $drsChange = 4 }
        1 { $drsChange = 5 }
        Default { $drsChange = 3 }
    }

    # Settings for DRS
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $spec.DrsConfig = New-Object VMware.Vim.ClusterDrsConfigInfo
    $spec.DrsConfig.VmotionRate = $drsChange
    $spec.DrsConfig.Enabled = $true
    $modify = $true
    # End DRS settings

    # $cluster is an array of cluster names or "*""
    foreach ($cluster_each in ($ClustersToChange.split(",", [System.StringSplitOptions]::RemoveEmptyEntries)).Trim()) {
        $Clusters += Get-Cluster -Name $cluster_each
    }

    foreach ($cluster in $clusters) {
        try {
            $_this = Get-View -Id $cluster.Id
            $_this.ReconfigureComputeResource_Task($spec, $modify)
            Write-Host "Successfully set DRS for cluster $($cluster.Name)."
        }
        catch {
            Write-Error "Failed to set DRS for cluster $($cluster.Name)."
        }
    }
}

function Remove-CustomRole {
    <#
    .DESCRIPTION
        This function allows customer to remove a custom role from the SDDC.
        Useful in case of roles created with greater privileges than Cloudadmin that can no longer be removed from the UI.
    #>

    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param (
        [Parameter(Mandatory = $true,
            HelpMessage = "The name of the role to remove, as displayed in the vCenter UI (case insensitive). This must be a custom role.")]
        [string]
        $roleInput
    )
    # Check if the role exists before attempting removal
    $roleToRemove = Get-VIRole | Where-Object { $_.Name -eq $roleInput}

    # Check if the role is in the protected names list or is a System role
    if ($roleToRemove.Count -eq 1) {
        if ((Test-AVSProtectedObjectName -Name $roleToRemove.Name) -or $roleToRemove.IsSystem -eq $true) {
            Write-Error "'$roleInput' is either System or Built-in. Removal not allowed."
        }
        else {
            try {
                Remove-VIRole -Role $roleToRemove -Confirm:$false -Force:$false
                Write-Host "The role '$roleInput' has been removed."
            }
            catch {
                Write-Error "Failed to remove the role '$roleInput'."
                Write-Error $_.Exception.Message
            }
        }
    }
    else {
        Write-Host "The role '$roleInput' was not found or can refer to several roles. No removal performed. Below the list of roles found:"
        foreach ($roleItem in $roleToRemove) {
            Write-Host "Role Name: $($roleItem.Name)"
            Write-Host "Role Description: $($roleItem.Description)"
        }
    }
}

function Get-EsxtopData {
    <#
    .SYNOPSIS
        Collects esxtop performance data from an ESXi host via the vCenter Esxtop service API.

    .DESCRIPTION
        Collects batch-mode esxtop snapshots from a single ESXi host via the vCenter ServiceManager
        API (no SSH) and uploads the resulting CSV to the cluster's vSAN datastore (or a
        customer-specified datastore via OutputDatastoreName).

    .PARAMETER ClusterName
        The name of the vSphere cluster containing the target ESXi host.

    .PARAMETER EsxiHostName
        The ESXi host name or prefix. The first connected host matching this prefix is used.

    .PARAMETER Iterations
        Number of FetchStats snapshots. Combined with IntervalSeconds, total spacing between the
        first and last sample must not exceed 30 seconds: (Iterations - 1) * IntervalSeconds <= 30.

    .PARAMETER IntervalSeconds
        Seconds to wait after each sample before the next (not applied after the last sample).
        Range 2-30. The minimum of 2 seconds aligns with esxtop's minimum sampling interval.

    .PARAMETER OutputDatastoreName
        Name of the datastore to upload the CSV to. When omitted, defaults to the first vSAN
        datastore on the cluster. Specify this to use a non-vSAN datastore or when automatic
        vSAN discovery does not find the desired target.

    .NOTES
        Get-View emits a non-fatal "Invalid property" error for ServiceManager and Esxtop service
        objects but still returns a usable object. ErrorAction SilentlyContinue suppresses the noise.
        The returned object is validated via Get-Member before use.

        The Esxtop SimpleCommand API (CounterInfo, FetchStats, FreeStats) is not covered in the
        official vSphere API reference. The approach used here is based on:
        - https://williamlam.com/2017/02/using-the-vsphere-api-in-vcenter-server-to-collect-esxtop-vscsistats-metrics.html
        - https://github.com/lamw/vmware-scripts/blob/master/powershell/Get-EsxtopAPI.ps1
    #>

    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the vSphere cluster containing the target ESXi host.')]
        [ValidateNotNullOrEmpty()]
        [string]$ClusterName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'ESXi host name or name prefix. The first matching host will be used.')]
        [ValidateNotNullOrEmpty()]
        [string]$EsxiHostName,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Number of FetchStats snapshots (spacing (Iterations-1)*IntervalSeconds must be <= 30s).')]
        [ValidateRange(1, 6)]
        [int]$Iterations = 6,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Seconds between snapshots (2-30; with Iterations, total spacing <= 30s).')]
        [ValidateRange(2, 30)]
        [int]$IntervalSeconds = 5,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Name of the datastore for CSV upload. Defaults to the first vSAN datastore on the cluster.')]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDatastoreName
    )

    $EsxiHostName = Limit-WildcardsandCodeInjectionCharacters -String $EsxiHostName
    $ClusterName = Limit-WildcardsandCodeInjectionCharacters -String $ClusterName
    if ($PSBoundParameters.ContainsKey('OutputDatastoreName')) {
        $OutputDatastoreName = Limit-WildcardsandCodeInjectionCharacters -String $OutputDatastoreName
    }

    $samplingSpanSec = [Math]::Max(0, $Iterations - 1) * $IntervalSeconds
    if ($samplingSpanSec -gt 30) {
        throw ("Esxtop sampling is limited to 30 seconds between the first and last sample: " +
            "(Iterations-1)*IntervalSeconds must be <= 30. Current spacing is ${samplingSpanSec}s " +
            "(Iterations=$Iterations, IntervalSeconds=$IntervalSeconds).")
    }

    $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $vmHost = $cluster | Get-VMHost |
        Where-Object { $_.Name -like "$EsxiHostName*" -and $_.ConnectionState -eq 'Connected' } |
        Select-Object -First 1

    if ($null -eq $vmHost) {
        throw "No connected ESXi host matching '$EsxiHostName' found in cluster '$ClusterName'."
    }

    Write-Host "Target host: $($vmHost.Name)"

    # Get ServiceManager via Get-View (emits non-fatal error but returns usable object)
    $serviceManager = Get-View ($global:DefaultVIServer.ExtensionData.Content.ServiceManager) -Property "" -ErrorAction SilentlyContinue
    if ($null -eq $serviceManager) {
        throw "Could not resolve ServiceManager via Get-View."
    }
    if (-not (Get-Member -InputObject $serviceManager -Name "QueryServiceList")) {
        throw "ServiceManager object is missing QueryServiceList method. MoRef may be invalid."
    }

    # Query services on the target host
    $locationString = "vmware.host." + $vmHost.Name
    $services = $serviceManager.QueryServiceList($null, $locationString)
    if (-not $services) {
        throw "No services found at location '$locationString'."
    }

    $esxtopService = $null
    foreach ($svc in $services) {
        if ($svc.ServiceName -eq "Esxtop") {
            $esxtopService = $svc
            break
        }
    }
    if ($null -eq $esxtopService) {
        $available = ($services | ForEach-Object { $_.ServiceName }) -join ', '
        throw "Esxtop service not found on host $($vmHost.Name). Available: $available"
    }

    $esxtopView = Get-View $esxtopService.Service -Property "" -ErrorAction SilentlyContinue
    if ($null -eq $esxtopView) {
        throw "Could not resolve Esxtop service view via Get-View."
    }
    if (-not (Get-Member -InputObject $esxtopView -Name "ExecuteSimpleCommand")) {
        throw "Esxtop service view is missing ExecuteSimpleCommand method. MoRef may be invalid."
    }

    # CounterInfo
    $esxtopView.ExecuteSimpleCommand("CounterInfo") | Out-Null

    # FetchStats loop — collect samples to local temp file, then upload to vSAN datastore
    $hostShort = $vmHost.Name.Split('.')[0]
    $runTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvFileName = "esxtop_${hostShort}_${runTimestamp}.csv"
    $tempCsv = Join-Path ([System.IO.Path]::GetTempPath()) $csvFileName

    Write-Host "Collecting $Iterations samples from $($vmHost.Name) (interval=${IntervalSeconds}s)..."
    '"Timestamp","SampleNumber","RawData"' | Out-File -FilePath $tempCsv -Encoding UTF8
    $totalBytes = 0

    for ($i = 1; $i -le $Iterations; $i++) {
        $stats = $esxtopView.ExecuteSimpleCommand("FetchStats")

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $escaped = $stats -replace '"', '""'
        $csvRow = '"' + $timestamp + '",' + $i + ',"' + $escaped + '"'
        $csvRow | Out-File -FilePath $tempCsv -Encoding UTF8 -Append
        $totalBytes += $stats.Length

        $pct = [math]::Round(($i / $Iterations) * 100)
        $dataKB = [math]::Round($totalBytes / 1024, 1)
        Write-Host "Sample $i/$Iterations (${pct}%) - ${dataKB} KB collected"

        if ($i -lt $Iterations) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    }

    # FreeStats
    try {
        $esxtopView.ExecuteSimpleCommand("FreeStats") | Out-Null
    }
    catch {
        Write-Warning "FreeStats call failed: $($_.Exception.Message)"
    }

    # Upload CSV to datastore
    try {
        if ($PSBoundParameters.ContainsKey('OutputDatastoreName')) {
            $datastore = Get-Datastore -Name $OutputDatastoreName -ErrorAction Stop
        }
        else {
            $datastore = Get-Datastore -RelatedObject $cluster -ErrorAction SilentlyContinue |
                Where-Object { $_.Type -eq 'vsan' -or $_.Name -like '*vsan*' -or $_.Name -like '*vsanDatastore*' } |
                Select-Object -First 1
        }

        if ($null -eq $datastore) {
            Write-Warning ("No vSAN datastore found on cluster '$ClusterName'. CSV saved locally at $tempCsv. " +
                "Use -OutputDatastoreName to specify an accessible datastore.")
        }
        else {
            $driveName = "esxtopUpload"
            if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
                Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            }
            New-PSDrive -Name $driveName -Location $datastore -PSProvider VimDatastore -Root "\" -ErrorAction Stop | Out-Null

            $destFolder = "${driveName}:\esxtop_output"
            if (-not (Test-Path $destFolder -ErrorAction SilentlyContinue)) {
                New-Item -Path $destFolder -ItemType Directory -ErrorAction Stop | Out-Null
                if (-not (Test-Path $destFolder -ErrorAction SilentlyContinue)) {
                    throw "Failed to create esxtop_output folder on datastore [$($datastore.Name)]."
                }
            }

            $destFile = "$destFolder\$csvFileName"
            Copy-DatastoreItem -Item $tempCsv -Destination $destFile -Force -ErrorAction Stop
            $fileSizeKB = [math]::Round((Get-Item $tempCsv).Length / 1024, 1)
            Write-Host "Uploaded ${fileSizeKB} KB to [$($datastore.Name)] esxtop_output/$csvFileName"
        }
    }
    catch {
        Write-Warning "Datastore upload failed: $($_.Exception.Message)"
    }

    Write-Host "Esxtop collection complete. $Iterations samples from $($vmHost.Name)."
}
