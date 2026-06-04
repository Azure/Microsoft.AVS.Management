<# Private Function Import #>
. $PSScriptRoot\AVSGenericUtils.ps1

<#
    .SYNOPSIS
    Manages the Tools Repository on vSAN datastores for VMware Tools deployment.

    .DESCRIPTION
    This function creates a GuestStore folder on each cluster's vSAN datastore and configures
    hosts to pull VMware Tools from their respective vSAN datastore. The 'gueststore-vmtools'
    file is required.

    When -Validate is specified, only reads and validates metadata.json files without making changes.
    When -Validate is NOT specified, uploads tools and configures hosts as normal.

    .PARAMETER ToolsURL
    A publicly available HTTP(S) URL to download the Tools zip file. Required when -Validate
    is NOT specified. Must be HTTPS or HTTP.

    .PARAMETER Validate
    Switch to enable validation-only mode. When set, the function reads metadata.json files
    to verify they are in sync, but makes no changes to the datastore or host configuration.

    .EXAMPLE
    # Upload tools to repositories
    Set-ToolsRepo -ToolsURL "https://example.com/tools.zip"

    .EXAMPLE
    # Validate existing repositories (no upload)
    Set-ToolsRepo -Validate
#>
function Set-ToolsRepo {
    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $false,
            HelpMessage = 'A publicly available HTTP(S) URL to download the Tools zip file.')]
        [ValidateNotNullOrEmpty()]
        [SecureString]
        $ToolsURL,

        [Parameter(Mandatory = $false)]
        [switch]$Validate
    )

    # Initialize variables
    $new_folder = 'GuestStore'
    $archive_path = '/vmware/apps/vmtools/windows64/'
    $normalizedArchivePath = if ($null -ne $archive_path) { $archive_path.Trim('/','\') } else { '' }
    $successfulDatastores = @()
    $failedDatastores = @()

    # Main execution wrapped in try-catch-finally
    try {
        Write-Verbose "Starting Set-ToolsRepo"

        # Check mutual exclusion: -Validate or -ToolsURL required
        if (-not $Validate -and $null -eq $ToolsURL) {
            throw "ToolsURL is required when -Validate is not specified."
        }

        if ($Validate) {
            Write-Information "Running in validation-only mode. No upload or configuration changes will be made." -InformationAction Continue

            $GetMetadataVersion = {
                param(
                    [Parameter(Mandatory = $true)]
                    $MetadataObject,

                    [Parameter(Mandatory = $true)]
                    [string]$LatestVersion
                )

                if ($null -eq $MetadataObject) {
                    return $null
                }

                $versionPattern = '(?i)vmtools-(\d+(?:\.\d+){1,3})'
                $installerFilePattern = '(?i)vmware-tools-(\d+(?:\.\d+){1,3})'
                $plainVersionPattern = '^\d+(?:\.\d+){1,3}$'
                $candidateVersions = @()

                if ($MetadataObject.PSObject.Properties.Name -contains 'installer' -and $null -ne $MetadataObject.installer) {
                    $installerObj = $MetadataObject.installer

                    if ($installerObj.PSObject.Properties.Name -contains 'version') {
                        $installerVersion = [string]$installerObj.version
                        if ($installerVersion -match $plainVersionPattern) {
                            $candidateVersions += $installerVersion
                        }
                        if ($installerVersion -match $versionPattern) {
                            $candidateVersions += $Matches[1]
                        }
                    }

                    if ($installerObj.PSObject.Properties.Name -contains 'file') {
                        $installerFile = [string]$installerObj.file
                        if ($installerFile -match $installerFilePattern) {
                            $candidateVersions += $Matches[1]
                        }
                    }
                }

                if ($MetadataObject.PSObject.Properties.Name -contains 'vmtools') {
                    $vmtoolsField = [string]$MetadataObject.vmtools
                    if ($vmtoolsField -match $versionPattern) {
                        $candidateVersions += $Matches[1]
                    }
                }

                foreach ($prop in $MetadataObject.PSObject.Properties) {
                    $nameCandidate = [string]$prop.Name
                    if ($nameCandidate -match $versionPattern) {
                        $candidateVersions += $Matches[1]
                    }

                    $valueCandidate = [string]$prop.Value
                    if ($valueCandidate -match $versionPattern) {
                        $candidateVersions += $Matches[1]
                    }
                }

                if ($candidateVersions.Count -gt 0) {
                    $uniqueCandidates = $candidateVersions | Select-Object -Unique
                    if ($uniqueCandidates -contains $LatestVersion) {
                        return $LatestVersion
                    }

                    $sortedCandidates = $uniqueCandidates |
                        Sort-Object {
                            try {
                                [version]$_
                            } catch {
                                [version]'0.0'
                            }
                        } -Descending

                    return [string]$sortedCandidates[0]
                }

                # Fallback: some metadata formats store only the tools version in a plain 'version' field.
                if ($MetadataObject.PSObject.Properties.Name -contains 'version') {
                    $versionField = [string]$MetadataObject.version
                    if ($versionField -match $versionPattern) {
                        return $Matches[1]
                    }
                    if ($versionField -match $plainVersionPattern -and $versionField -eq $LatestVersion) {
                        return $versionField
                    }
                }

                return $null
            }

            # Get vSAN datastores with error handling
            try {
                $datastores = @(Get-Datastore -ErrorAction Stop | Where-Object { $_.extensionData.Summary.Type -eq 'vsan' })

                if ($null -eq $datastores -or $datastores.Count -eq 0) {
                    throw "No vSAN datastores found in the environment"
                }

                Write-Information "Found $($datastores.Count) vSAN datastore(s)" -InformationAction Continue
            } catch {
                throw "Failed to retrieve vSAN datastores: $_"
            }

            foreach ($datastore in $datastores) {
                $ds_name = $datastore.Name
                $localMetadataTempDir = $null
                Write-Information "Validating datastore: $ds_name" -InformationAction Continue

                try {
                    if (Get-PSDrive -Name DS -ErrorAction SilentlyContinue) {
                        Remove-PSDrive -Name DS -Force -ErrorAction SilentlyContinue
                    }

                    try {
                        New-PSDrive -Location $datastore -Name DS -PSProvider VimDatastore -Root '\' -ErrorAction Stop | Out-Null
                    } catch {
                        throw "Failed to create PSDrive for datastore $ds_name : $_"
                    }

                    $baseDestPath = "DS:/$new_folder"
                    $destPath = if ([string]::IsNullOrEmpty($normalizedArchivePath)) {
                        $baseDestPath
                    } else {
                        Join-Path -Path $baseDestPath -ChildPath $normalizedArchivePath
                    }

                    if (-not (Test-Path -Path $destPath)) {
                        throw "GuestStore tools path not found on $ds_name : $destPath"
                    }

                    $existing_dirs = Get-ChildItem -Path $destPath -ErrorAction Stop |
                        Where-Object {
                            $_.PSIsContainer -and
                            $_.Name -match '^vmtools-\d'
                        }

                    if ($null -eq $existing_dirs -or $existing_dirs.Count -eq 0) {
                        throw "No vmtools-* version folders found on $ds_name under $destPath"
                    }

                    $highestVersionFolder = $null
                    $highestVersion = $null

                    foreach ($existing_dir in $existing_dirs) {
                        $ver = $existing_dir.Name -replace 'vmtools-', ''
                        try {
                            $parsedVersion = [version]$ver
                        } catch {
                            continue
                        }

                        if ($null -eq $highestVersion -or $parsedVersion -gt $highestVersion) {
                            $highestVersion = $parsedVersion
                            $highestVersionFolder = $existing_dir
                        }
                    }

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
                        Copy-DatastoreItem -Item $topLevelMetadataPath -Destination $localTopLevelMetadataPath -Force -ErrorAction Stop
                    } catch {
                        throw "Failed to copy top-level metadata.json from $ds_name : $($_.Exception.Message)"
                    }

                    try {
                        Copy-DatastoreItem -Item $versionMetadataPath -Destination $localVersionMetadataPath -Force -ErrorAction Stop
                    } catch {
                        throw "Failed to copy version metadata.json from $ds_name : $($_.Exception.Message)"
                    }

                    try {
                        $topLevelMetadataObj = Get-Content -Path $localTopLevelMetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                        $versionMetadataObj = Get-Content -Path $localVersionMetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    } catch {
                        throw "Failed to parse metadata.json content on $ds_name : $($_.Exception.Message)"
                    }

                    $topLevelMetadataVersion = & $GetMetadataVersion -MetadataObject $topLevelMetadataObj -LatestVersion $latestDetectedVersion
                    $versionFolderMetadataVersion = & $GetMetadataVersion -MetadataObject $versionMetadataObj -LatestVersion $latestDetectedVersion

                    Write-Host "Datastore $ds_name top-level metadata version: $topLevelMetadataVersion"
                    Write-Host "Datastore $ds_name version-folder metadata version: $versionFolderMetadataVersion"

                    $topLevelInSync = (-not [string]::IsNullOrEmpty($topLevelMetadataVersion)) -and ($topLevelMetadataVersion -eq $latestDetectedVersion)
                    $versionFolderInSync = (-not [string]::IsNullOrEmpty($versionFolderMetadataVersion)) -and ($versionFolderMetadataVersion -eq $latestDetectedVersion)

                    if ($topLevelInSync -and $versionFolderInSync) {
                        Write-Host "Datastore $ds_name validation result: SUCCESS - metadata is in sync."
                        $successfulDatastores += $ds_name
                    } else {
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
                        $failedDatastores += $ds_name
                    }
                } catch {
                    Write-Error "Validation failed for datastore $ds_name : $_"
                    $failedDatastores += $ds_name
                } finally {
                    if (-not [string]::IsNullOrEmpty($localMetadataTempDir) -and (Test-Path -Path $localMetadataTempDir)) {
                        Remove-Item -Path $localMetadataTempDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    if (Get-PSDrive -Name DS -ErrorAction SilentlyContinue) {
                        Remove-PSDrive -Name DS -Force -ErrorAction SilentlyContinue
                    }
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
                if ($failedDatastores.Count -eq @($datastores).Count) {
                    throw "Validation failed for all datastores."
                }

                throw "Validation failed for some datastores. Review failed datastore list above."
            }

            return
        }

        $failedDatastoreReasons = @{}

        # Convert SecureString to plain text for use with web requests
        $ToolsURLPlain = [System.Net.NetworkCredential]::new('', $ToolsURL).Password

        # Validate URL pattern (must be HTTP or HTTPS)
        if ($ToolsURLPlain -notmatch '^https?://') {
            throw "ToolsURL must be a valid HTTP or HTTPS URL."
        }

        # Validate URL accessibility
        try {
            $webResponse = Invoke-WebRequest -Uri $ToolsURLPlain -Method Head -TimeoutSec 30 -ErrorAction Stop
            if ($webResponse.StatusCode -ne 200) {
                throw "URL returned status code: $($webResponse.StatusCode)"
            }
        } catch {
            throw "Unable to access the provided URL: $_"
        }

        # Use current working directory (managed by agent)
        $tools_file = "./tools.zip"

        # Download the tools file
        try {
            Write-Information "Downloading tools..." -InformationAction Continue
            Invoke-WebRequest -Uri $ToolsURLPlain -OutFile $tools_file -ErrorAction Stop

            # Validate downloaded file
            if (-not (Test-Path -Path $tools_file)) {
                throw "Downloaded file not found at expected location"
            }

            $fileSize = (Get-Item $tools_file).Length
            if ($fileSize -eq 0) {
                throw "Downloaded file is empty"
            }

            Write-Verbose "Downloaded file size: $($fileSize / 1MB) MB"
        } catch {
            throw "Failed to download tools file: $_"
        }

        # Extract the archive
        try {
            Write-Information "Extracting tools archive..." -InformationAction Continue
            Expand-Archive -Path $tools_file -DestinationPath "." -Force -ErrorAction Stop
        } catch {
            throw "Failed to extract tools archive: $_"
        }

        # Locate windows64 directory in extracted archive
        $windows64_path = Join-Path -Path "." -ChildPath $normalizedArchivePath

        if (-not (Test-Path -Path $windows64_path)) {
            throw "windows64 directory not found in extracted archive at: $windows64_path"
        }

        Write-Information "windows64 directory located - will validate metadata.json files next" -InformationAction Continue

        # Build the path to windows64/metadata.json
        $windows64_top_metadata_path = Join-Path -Path $windows64_path -ChildPath "metadata.json"

        # Check if metadata.json exists in windows64
        if (-not (Test-Path -Path $windows64_top_metadata_path)) {
            throw "metadata.json not found in windows64 directory at: $windows64_top_metadata_path"
        }

        Write-Information "metadata.json found in windows64 directory: $windows64_top_metadata_path" -InformationAction Continue

        # Find the vmtools-xxx folder inside windows64
        $vmtools_folders = Get-ChildItem -Path $windows64_path -Directory | Where-Object { $_.Name -like "vmtools-*" }

        if ($null -eq $vmtools_folders -or $vmtools_folders.Count -eq 0) {
            throw "No vmtools folder found inside windows64 at: $windows64_path"
        }

        $vmtools_folder_path = $vmtools_folders[0].FullName

        Write-Information "Found vmtools folder: $($vmtools_folders[0].Name) at $vmtools_folder_path" -InformationAction Continue

        # Check if metadata.json exists inside the vmtools-xxx folder
        $vmtools_version_metadata_path = Join-Path -Path $vmtools_folder_path -ChildPath "metadata.json"

        if (-not (Test-Path -Path $vmtools_version_metadata_path)) {
            throw "metadata.json not found inside vmtools folder at: $vmtools_version_metadata_path"
        }

        Write-Information "metadata.json found inside vmtools folder: $vmtools_version_metadata_path" -InformationAction Continue

        # Validation success gate: both required metadata files were found
        Write-Information "Validation gate passed: windows64 metadata at $windows64_top_metadata_path and vmtools metadata at $vmtools_version_metadata_path. Proceeding to datastore operations." -InformationAction Continue

        # Use the already validated vmtools folder from Step 3
        $tools_version = Split-Path -Path $vmtools_folder_path -Leaf

        if ([string]::IsNullOrEmpty($tools_version) -or $tools_version -notlike 'vmtools-*') {
            throw "Invalid vmtools folder name detected at: $vmtools_folder_path"
        }

        $tools_short_version = $tools_version -replace 'vmtools-', ''
        Write-Information "Found tools version: $tools_version" -InformationAction Continue

        # Get vSAN datastores with error handling
        try {
            $datastores = @(Get-Datastore -ErrorAction Stop | Where-Object { $_.extensionData.Summary.Type -eq 'vsan' })

            if ($null -eq $datastores -or $datastores.Count -eq 0) {
                throw "No vSAN datastores found in the environment"
            }

            Write-Information "Found $($datastores.Count) vSAN datastore(s)" -InformationAction Continue
        } catch {
            throw "Failed to retrieve vSAN datastores: $_"
        }

        # Process each datastore
        foreach ($datastore in $datastores) {
            $ds_name = $datastore.Name
            Write-Information "Processing datastore: $ds_name" -InformationAction Continue

            try {
                # Ensure any existing PSDrive is removed
                if (Get-PSDrive -Name DS -ErrorAction SilentlyContinue) {
                    Remove-PSDrive -Name DS -Force -ErrorAction SilentlyContinue
                }

                # Create PS drive with error handling
                try {
                    New-PSDrive -Location $datastore -Name DS -PSProvider VimDatastore -Root '\' -ErrorAction Stop | Out-Null
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
                        New-Item -ItemType Directory -Path "DS:/$new_folder" -ErrorAction Stop | Out-Null
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
                $baseDestPath = "DS:/$new_folder"
                $destPath = if ([string]::IsNullOrEmpty($normalizedArchivePath)) {
                    $baseDestPath
                } else {
                    Join-Path -Path $baseDestPath -ChildPath $normalizedArchivePath
                }
                $highestExistingVersion = $null
                $shouldUpdateTopLevelMetadata = $false

                if (Test-Path -Path $destPath) {
                    try {
                        $existing_dirs = Get-ChildItem -Path $destPath -ErrorAction Stop |
                            Where-Object {
                                $_.PSIsContainer -and
                                $_.Name -match '^vmtools-\d'
                            }

                        foreach ($existing_dir in $existing_dirs) {
                            $ver = $existing_dir.Name -replace 'vmtools-', ''
                            if ($null -eq $highestExistingVersion -or [version]$ver -gt [version]$highestExistingVersion) {
                                $highestExistingVersion = $ver
                            }
                        }

                        if ($highestExistingVersion) {
                            Write-Information "Current highest version on $ds_name is $highestExistingVersion" -InformationAction Continue
                        }
                    } catch {
                        Write-Warning "Failed to check existing versions on $ds_name : $_"
                    }
                }

                # Determine if we should update the top-level metadata.json
                # Only update if new version is greater than the highest existing version
                if ($null -eq $highestExistingVersion -or [version]$tools_short_version -gt [version]$highestExistingVersion) {
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
                        Write-Information "Version $tools_version already exists on $ds_name. Skipping copy." -InformationAction Continue
                    } else {
                        # Copy the vmtools-{version} folder itself (preserves folder structure)
                        Copy-DatastoreItem -Item $sourceDir -Destination $destPath -Recurse -Force -ErrorAction Stop

                        # Verify metadata.json exists in the copied version folder
                        $versionMeta = Get-ChildItem -Path $versionDestPath -Filter metadata.json -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                        if (-not $versionMeta) { throw "metadata.json not found in copied version folder on $ds_name" }

                        Write-Information "Successfully copied $tools_version to $ds_name" -InformationAction Continue
                    }

                    # Ensure top-level GuestStore artifacts (for example, gueststore-vmtools) are present.
                    # Keep metadata.json handling separate below so preserve/update rules stay unchanged.
                    $topLevelSourceDir = Split-Path -Path $sourceDir -Parent
                    if (-not [string]::IsNullOrEmpty($topLevelSourceDir) -and (Test-Path -Path $topLevelSourceDir)) {
                        $topLevelFiles = Get-ChildItem -Path $topLevelSourceDir -File -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -ne 'metadata.json' }
                        foreach ($file in $topLevelFiles) {
                            $destFilePath = Join-Path -Path $destPath -ChildPath $file.Name
                            Copy-DatastoreItem -Item $file.FullName -Destination $destFilePath -Force -ErrorAction Stop
                        }
                        if ($topLevelFiles) {
                            Write-Information "Ensured top-level GuestStore artifacts are present on $ds_name" -InformationAction Continue
                        }
                    }

                    # Update top-level metadata.json only if new version is greater
                    if ($shouldUpdateTopLevelMetadata) {
                        $topLevelMetadataPath = Join-Path $destPath "metadata.json"
                        Copy-DatastoreItem -Item $windows64_top_metadata_path -Destination $topLevelMetadataPath -Force -ErrorAction Stop
                        Write-Information "Updated top-level metadata.json on $ds_name to version $tools_short_version" -InformationAction Continue
                    } else {
                        Write-Information "Top-level metadata.json on $ds_name preserved (not overwritten)" -InformationAction Continue
                    }
                } catch {
                    throw "Failed to copy tools to $ds_name : $_"
                }

                # Configure hosts
                $url = ($datastore.ExtensionData.Summary.Url) + "$new_folder"

                # Get hosts with proper error handling
                try {
                    $ds_id = $datastore.Id
                    $vmhosts = Get-VMHost -ErrorAction Stop | Where-Object {
                        $_.ExtensionData.Datastore.value -contains ($ds_id.Split('-', 2)[1])
                    }

                    if ($null -eq $vmhosts -or $vmhosts.Count -eq 0) {
                        throw "No hosts found for datastore $ds_name"
                    }

                    Write-Information "Configuring $($vmhosts.Count) host(s) for datastore $ds_name" -InformationAction Continue
                } catch {
                    throw "Failed to retrieve hosts for datastore $ds_name : $_"
                }

                # Configure each host
                $failedHosts = @()
                foreach ($vmhost in $vmhosts) {
                    try {
                        $esxcli = Get-EsxCli -V2 -VMHost $vmhost -ErrorAction Stop
                        Write-Verbose "Setting GuestStore repository for host: $vmhost"

                        $arguments = $esxcli.system.settings.gueststore.repository.set.CreateArgs()
                        $arguments.url = $url
                        $result = $esxcli.system.settings.gueststore.repository.set.invoke($arguments)

                        if ($result -eq $false) {
                            throw "ESXCLI command returned false"
                        }

                        Write-Information "Successfully configured host: $vmhost" -InformationAction Continue
                    } catch {
                        Write-Warning "Failed to configure host $vmhost : $_"
                        $failedHosts += $vmhost.Name
                    }
                }

                if ($failedHosts.Count -gt 0) {
                    throw "Failed to configure hosts for datastore $ds_name : $($failedHosts -join ', ')"
                }

                $successfulDatastores += $ds_name
            } catch {
                $failureMessage = $_.Exception.Message
                if ([string]::IsNullOrWhiteSpace($failureMessage)) {
                    $failureMessage = [string]$_
                }

                Write-Warning "Error processing datastore $ds_name : $failureMessage"
                $failedDatastores += $ds_name
                $failedDatastoreReasons[$ds_name] = $failureMessage
            } finally {
                # Always clean up PSDrive
                if (Get-PSDrive -Name DS -ErrorAction SilentlyContinue) {
                    Remove-PSDrive -Name DS -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # Summary report
        Write-Information "`n=== Summary ===" -InformationAction Continue
        if ($successfulDatastores.Count -gt 0) {
            Write-Information "List of Successfully processed datastores: $($successfulDatastores -join ', ')" -InformationAction Continue
        }
        if ($failedDatastores.Count -gt 0) {
            Write-Warning "List of Failed datastores: $($failedDatastores -join ', ')"

            foreach ($failedDs in $failedDatastores) {
                $reason = $failedDatastoreReasons[$failedDs]
                if ([string]::IsNullOrWhiteSpace($reason)) {
                    $reason = "No detailed failure reason captured."
                }

                Write-Warning "Failure reason for datastore $failedDs : $reason"
            }
        }

        if ($failedDatastores.Count -gt 0) {
            if ($failedDatastores.Count -eq @($datastores).Count) {
                throw "All datastores failed to process."
            }

            throw "Some datastores failed to process. Review successful datastore list, failed datastore list, and failure reasons above."
        }
    } catch {
        Write-Error "Set-ToolsRepo failed: $_"
        throw
    } finally {
        # Ensure PSDrive is removed
        if (Get-PSDrive -Name DS -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name DS -Force -ErrorAction SilentlyContinue
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
    $spec.DrsConfig.Option = New-Object VMware.Vim.OptionValue[] (2)
    $spec.DrsConfig.Option[0] = New-Object VMware.Vim.OptionValue
    $spec.DrsConfig.Option[0].Value = '0'
    $spec.DrsConfig.Option[0].Key = 'TryBalanceVmsPerHost'
    $spec.DrsConfig.Option[1] = New-Object VMware.Vim.OptionValue
    $spec.DrsConfig.Option[1].Value = '1'
    $spec.DrsConfig.Option[1].Key = 'IsClusterManaged'
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

function Set-VCLoginBanner {
    <#
    .SYNOPSIS
        Configures and enables the vCenter login banner via SSH to the VCSA appliance.

    .DESCRIPTION
        Sets the vCenter login banner title, message, and optional consent checkbox by
        executing sso-config.sh commands on the VCSA via the pre-established SSH session.
        This enables both Layer 1 (configuration data) and Layer 2 (activation toggle),
        which cannot be achieved through the vCenter API alone.

    .PARAMETER BannerTitle
        The title displayed on the vCenter login page (e.g., "Authorized Users Only").

    .PARAMETER BannerMessage
        The full login message or terms text shown to users on the login page.

    .PARAMETER EnableConsent
        When True, users must check a consent checkbox before logging in.

    .EXAMPLE
        Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
    #>
    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BannerTitle,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BannerMessage,

        [Parameter(Mandatory = $true)]
        [bool]$EnableConsent
    )
    begin {
        $BannerTitle = Limit-WildcardsandCodeInjectionCharacters -String $BannerTitle
        $BannerMessage = Limit-WildcardsandCodeInjectionCharacters -String $BannerMessage
    }
    process {
        # Obtain the pre-established SSH session to vCenter
        if ($null -eq $SSH_Sessions -or -not $SSH_Sessions.ContainsKey("VC")) {
            throw "SSH session to vCenter is not available. Ensure `$SSH_Sessions['VC'] is pre-established by the AVS platform."
        }
        $SshSession = $SSH_Sessions["VC"].Value
        if ($null -eq $SshSession) {
            throw "Failed to initialize SSH session to vCenter."
        }

        # Escape single quotes in user-provided text for safe shell usage
        $escapedTitle = $BannerTitle -replace "'", "'\\''"
        $escapedMessage = $BannerMessage -replace "'", "'\\''"
        $consentFlag = if ($EnableConsent) { "true" } else { "false" }
        $consentFlagYN = if ($EnableConsent) { "Y" } else { "N" }

        # Reusable command runner for future banner command fallback flows
        $InvokeBannerCommand = {
            param(
                [string]$Command,
                [string]$StepName
            )

            $cmdResult = Invoke-SSHCommand -SSHSession $SshSession -Command $Command -ErrorAction Stop
            if ($cmdResult.ExitStatus -eq 0) {
                Write-Host "$StepName succeeded."
                return $true
            }

            $errorText = $cmdResult.Error -join ' '
            Write-Warning "$StepName failed: $errorText"
            return $false
        }

        # Step 1: Set the banner title and message content (Layer 1)
        $setContentCmd = "/opt/vmware/bin/sso-config.sh -set_logon_banner -title '$escapedTitle' -content '$escapedMessage'"
        Write-Host "Setting login banner content using inline content format..."
        $setContentSucceeded = & $InvokeBannerCommand -Command $setContentCmd -StepName "Set login banner content (inline)"
        if (-not $setContentSucceeded) {
            $bannerTempDir = "/tmp/avs-login-banner-{0}" -f ([guid]::NewGuid().ToString('N'))
            $bannerFilePath = "$bannerTempDir/message.txt"
            Write-Host "Inline content format failed. Preparing banner file for fallback format..."
            $createBannerDirCmd = "/bin/sh -c ""mkdir -p '$bannerTempDir'"""
            $createDirSucceeded = & $InvokeBannerCommand -Command $createBannerDirCmd -StepName "Create temp directory for fallback"

            $createdTempDir = $null
            if ($createDirSucceeded) {
                $createdTempDir = $bannerTempDir

                $createBannerFileCmd = "/bin/sh -c ""printf '%s' '$escapedMessage' > '$bannerFilePath'"""
                $createFileSucceeded = & $InvokeBannerCommand -Command $createBannerFileCmd -StepName "Create banner file for fallback"

                if ($createFileSucceeded) {
                    $setContentCmdFallback = "/opt/vmware/bin/sso-config.sh -set_logon_banner -title '$escapedTitle' '$bannerFilePath'"
                    Write-Host "Retrying login banner content using file format..."
                    $setContentSucceeded = & $InvokeBannerCommand -Command $setContentCmdFallback -StepName "Set login banner content (file)"
                    if ($setContentSucceeded) {
                        Write-Host "Fallback content format (banner file) worked on this VCSA."
                    }
                }
            }

            # Simple strong cleanup guardrail: delete only if created and delete path are exactly same
            $deleteTempDir = $bannerTempDir
            if (
                -not [string]::IsNullOrEmpty($createdTempDir) -and
                -not [string]::IsNullOrEmpty($deleteTempDir) -and
                $createdTempDir -eq $deleteTempDir
            ) {
                $cleanupBannerDirCmd = "/bin/sh -c ""rm -rf -- '$deleteTempDir'"""
                $cleanupSucceeded = & $InvokeBannerCommand -Command $cleanupBannerDirCmd -StepName "Cleanup temporary banner directory"
                if ($cleanupSucceeded) {
                    Write-Host "Temporary banner directory was cleaned up."
                } else {
                    Write-Warning "Temporary banner directory cleanup failed (non-blocking): $deleteTempDir"
                }
            } else {
                Write-Warning "Cleanup guardrail failed. Skipping delete for safety."
            }
        }

        if (-not $setContentSucceeded) {
            throw "Failed to set login banner content using supported formats."
        }

        # Step 2: Enable the consent checkbox setting
        $setConsentCmd = "/opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox $consentFlag"
        Write-Host "Setting consent checkbox to $consentFlag..."
        $setConsentSucceeded = & $InvokeBannerCommand -Command $setConsentCmd -StepName "Set consent checkbox ($consentFlag)"
        if (-not $setConsentSucceeded) {
            $setConsentCmdLegacy = "/opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox $consentFlagYN"
            Write-Host "Retrying consent checkbox with legacy Y/N format ($consentFlagYN)..."
            $setConsentSucceeded = & $InvokeBannerCommand -Command $setConsentCmdLegacy -StepName "Set consent checkbox ($consentFlagYN)"
            if ($setConsentSucceeded) {
                Write-Host "Legacy checkbox format (Y/N) worked on this VCSA."
            }
        }

        if (-not $setConsentSucceeded) {
            throw "Failed to set consent checkbox using supported formats."
        }

        # Step 3: Enable the login banner toggle (Layer 2 — the activation switch)
        $enableCmd = "/opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
        Write-Host "Enabling login banner display (Layer 2 toggle)..."
        $enableSucceeded = & $InvokeBannerCommand -Command $enableCmd -StepName "Enable login banner toggle (-enable true)"
        if (-not $enableSucceeded) {
            Write-Warning "Enable command style (-enable true) did not work on this VCSA variant. Verifying banner state..."

            $getCmd = "/opt/vmware/bin/sso-config.sh -get_logon_banner"
            $printCmd = "/opt/vmware/bin/sso-config.sh -print_logon_banner"

            $checkResult = Invoke-SSHCommand -SSHSession $SshSession -Command $getCmd -ErrorAction Stop
            if ($checkResult.ExitStatus -ne 0) {
                Write-Warning "Primary read command (-get_logon_banner) failed. Retrying with -print_logon_banner..."
                $checkResult = Invoke-SSHCommand -SSHSession $SshSession -Command $printCmd -ErrorAction Stop
            }

            if ($checkResult.ExitStatus -ne 0) {
                throw "Failed to verify banner state: $($checkResult.Error -join ' ')"
            }

            $bannerOutput = $checkResult.Output -join "`n"
            if ($bannerOutput -match "Checkbox enabled\s*:\s*true") {
                Write-Host "Banner is already enabled on this VCSA variant (no -enable command needed)."
                $enableSucceeded = $true
            } else {
                throw "Banner is not enabled and -enable command is not supported on this VCSA."
            }
        }

        Write-Host "vCenter login banner configured and enabled successfully."
        Write-Host "Title: $BannerTitle"
        Write-Host "Consent checkbox: $consentFlag"
        Write-Host "Verify by opening the vSphere Client login page in a private/incognito browser window."
    }
}

function Get-VCLoginBanner {
    <#
    .SYNOPSIS
        Retrieves the current vCenter login banner configuration via SSH to the VCSA appliance.

    .DESCRIPTION
        Reads the current login banner settings (title, message, consent checkbox, enabled state)
        from the VCSA by executing sso-config.sh via the pre-established SSH session.
        Returns the configuration via the NamedOutputs hashtable.

    .EXAMPLE
        Get-VCLoginBanner
    #>
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param()
    begin {}
    process {
        # Obtain the pre-established SSH session to vCenter
        if ($null -eq $SSH_Sessions -or -not $SSH_Sessions.ContainsKey("VC")) {
            throw "SSH session to vCenter is not available. Ensure `$SSH_Sessions['VC'] is pre-established by the AVS platform."
        }
        $SshSession = $SSH_Sessions["VC"].Value
        if ($null -eq $SshSession) {
            throw "Failed to initialize SSH session to vCenter."
        }

        $getCmd = "/opt/vmware/bin/sso-config.sh -get_logon_banner"
        $printCmd = "/opt/vmware/bin/sso-config.sh -print_logon_banner"
        Write-Host "Retrieving login banner configuration..."

        $result = Invoke-SSHCommand -SSHSession $SshSession -Command $getCmd -ErrorAction Stop
        if ($result.ExitStatus -ne 0) {
            Write-Warning "Primary read command (-get_logon_banner) failed. Retrying with -print_logon_banner..."
            $result = Invoke-SSHCommand -SSHSession $SshSession -Command $printCmd -ErrorAction Stop
            if ($result.ExitStatus -eq 0) {
                Write-Host "Fallback read command (-print_logon_banner) worked on this VCSA."
            }
        }

        if ($result.ExitStatus -ne 0) {
            throw "Failed to retrieve login banner configuration using supported formats: $($result.Error -join ' ')"
        }

        $bannerOutput = $result.Output -join "`n"
        Write-Host $bannerOutput

        $NamedOutputs = @{ "LoginBannerConfig" = $bannerOutput }
        Set-Variable -Name NamedOutputs -Value $NamedOutputs -Scope Global
    }
}

function Remove-VCLoginBanner {
    <#
    .SYNOPSIS
        Disables the vCenter login banner via SSH to the VCSA appliance.

    .DESCRIPTION
        Disables the login banner by toggling the "Show login message" switch OFF (Layer 2)
        on the VCSA via the pre-established SSH session. The banner configuration data
        (title, message) is preserved but no longer displayed on the login page.

    .EXAMPLE
        Remove-VCLoginBanner
    #>
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param()
    begin {}
    process {
        # Obtain the pre-established SSH session to vCenter
        if ($null -eq $SSH_Sessions -or -not $SSH_Sessions.ContainsKey("VC")) {
            throw "SSH session to vCenter is not available. Ensure `$SSH_Sessions['VC'] is pre-established by the AVS platform."
        }
        $SshSession = $SSH_Sessions["VC"].Value
        if ($null -eq $SshSession) {
            throw "Failed to initialize SSH session to vCenter."
        }

        $disableCmd = "/opt/vmware/bin/sso-config.sh -set_logon_banner -enable false"
        $disableCmdFallback = "/opt/vmware/bin/sso-config.sh -disable_logon_banner"
        Write-Host "Disabling login banner display..."

        $result = Invoke-SSHCommand -SSHSession $SshSession -Command $disableCmd -ErrorAction Stop
        if ($result.ExitStatus -ne 0) {
            Write-Warning "Primary disable command (-set_logon_banner -enable false) failed. Retrying with -disable_logon_banner..."
            $result = Invoke-SSHCommand -SSHSession $SshSession -Command $disableCmdFallback -ErrorAction Stop
            if ($result.ExitStatus -eq 0) {
                Write-Host "Fallback disable command (-disable_logon_banner) worked on this VCSA."
            }
        }

        if ($result.ExitStatus -ne 0) {
            throw "Failed to disable login banner using supported formats: $($result.Error -join ' ')"
        }

        Write-Host "vCenter login banner has been disabled successfully."
        Write-Host "Banner configuration data (title, message) is preserved but no longer displayed."
        Write-Host "To re-enable, run Set-VCLoginBanner with the desired settings."
    }
}
