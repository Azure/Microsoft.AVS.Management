<# Private Function Import #>
. $PSScriptRoot\AVSGenericUtils.ps1
. $PSScriptRoot\AVSvSANUtils.ps1

function Get-StoragePolicyInternal {
    Param
    (
        [Parameter(
            Mandatory = $true)]
        $StoragePolicyName
    )
    Write-Host "Getting Storage Policy $StoragePolicyName"
    $VSANStoragePolicies = Get-SpbmStoragePolicy -Namespace "VSAN" -ErrorAction Stop
    $StoragePolicy = Get-SpbmStoragePolicy $StoragePolicyName -ErrorAction Stop
    if ($null -eq $StoragePolicy) {
        Write-Error "Could not find Storage Policy with the name $StoragePolicyName." -ErrorAction Continue
        Write-Error "Available storage policies: $(Get-SpbmStoragePolicy -Namespace "VSAN")" -ErrorAction Stop
    }
    elseif (-not ($StoragePolicy -in $VSANStoragePolicies)) {
        Write-Error "Storage policy $StoragePolicyName is not supported. Storage policies must be in the VSAN namespace" -ErrorAction Continue
        Write-Error "Available storage policies: $(Get-SpbmStoragePolicy -Namespace "VSAN")" -ErrorAction Stop
    }
    return $StoragePolicy, $VSANStoragePolicies
}

function Set-StoragePolicyOnVM {
    Param
    (
        [Parameter(
            Mandatory = $true)]
        $VM,
        [Parameter(
            Mandatory = $true)]
        $VSANStoragePolicies,
        [Parameter(
            Mandatory = $true)]
        $StoragePolicy
    )
    if (-not $(Get-SpbmEntityConfiguration $VM).StoragePolicy -in $VSANStoragePolicies) {
        Write-Error "Modifying storage policy on $($VM.Name) is not supported"
    }
    Write-Host "Setting VM $($VM.Name) storage policy to $($StoragePolicy.Name)..."
    try {
        Set-VM -VM $VM -StoragePolicy $StoragePolicy -ErrorAction Stop -Confirm:$false
        Write-Output "Successfully set the storage policy on VM $($VM.Name) to $($StoragePolicy.Name)"
    }
    catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidVmConfig] {
        Write-Error "The selected storage policy $($StoragePolicy.Name) is not compatible with $($VM.Name). You may need more hosts: $($PSItem.Exception.Message)"
    }
    catch {
        Write-Error "Was not able to set the storage policy on $($VM.Name): $($PSItem.Exception.Message)"
    }
}

function Get-UnassociatedVsanObjectsWithPolicy {
    <#
    .SYNOPSIS
        Lists all unassociated vSAN objects with a specified storage policy across all clusters.

    .DESCRIPTION
        Scans all clusters for vSAN objects that are not associated with any VM and have the specified storage policy.

    .PARAMETER PolicyName
        The name of the storage policy to filter unassociated objects.

    .PARAMETER ClusterName
        The name of the vSphere cluster to scan for unassociated objects.

    .EXAMPLE
        Get-UnassociatedVsanObjectsWithPolicy -PolicyName 'vSAN Default Storage Policy' -ClusterName 'Cluster1'
    #>

    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(Mandatory = $true, HelpMessage = 'The storage policy name to filter unassociated objects')]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,

        [Parameter(Mandatory = $true, HelpMessage = 'The name of the vSphere cluster to scan for unassociated objects')]
        [ValidateNotNullOrEmpty()]
        [string]$ClusterName
    )

    $totalObjects = 0
    $matchedObjects = 0

    try {
        $cluster = Get-Cluster $ClusterName -ErrorAction Stop

        $clusterMoRef = $cluster.ExtensionData.MoRef
        $vmHost = ($cluster | Get-VMHost | Where-Object { $_.ConnectionState -eq 'Connected' -and $_.PowerState -eq 'PoweredOn' } | Select-Object -First 1)
        if ($null -eq $vmHost) {
            throw "No connected and powered-on hosts found."
        }
        $vsanIntSys = Get-View $vmHost.ExtensionData.ConfigManager.VsanInternalSystem
        $vsanClusterObjectSys = Get-VsanView -Id VsanObjectSystem-vsan-cluster-object-system
    }
    catch {
        Write-Error "Failed to initialize vSAN objects or connect to cluster: $_"
        return
    }

    try {
		#VsanQueryObjectIdentities(Cluster, objUuids, objTypes, includeHealth, includeObjIdentity, includeSpaceSummary))
        $unassociatedObjects = ($vsanClusterObjectSys.VsanQueryObjectIdentities($clusterMoRef, $null, $null, $false, $true, $false)).Identities | Where-Object { $null -eq $_.Vm }
    }
    catch {
        Write-Error "Failed to query unassociated vSAN objects: $_"
        return
    }

    foreach ($obj in $unassociatedObjects) {
        $totalObjects++
        if ($obj.SpbmProfileName -eq $PolicyName) {
            $matchedObjects++
            try {
                $jsonResult = ($vsanIntSys.GetVsanObjExtAttrs($obj.Uuid)) | ConvertFrom-Json
                Write-Output $jsonResult
            }
            catch {
                Write-Warning "Failed to retrieve or parse attributes for object $($obj.Uuid): $_"
            }
        }
    }

    Write-Output "Total unassociated objects found: $totalObjects"
    Write-Output "Unassociated objects with policy '$PolicyName': $matchedObjects"

    if ($matchedObjects -eq 0) {
        Write-Output "No unassociated objects with policy '$PolicyName' found."
    }
}

function Update-StoragePolicyOfUnassociatedVsanObjects {
    <#
    .SYNOPSIS
        Updates the storage policy of unassociated vSAN objects from a current policy to a new target policy.

    .DESCRIPTION
        This function scans all clusters for unassociated vSAN objects with a specified current policy and updates their storage policy to a new target policy.

    .PARAMETER CurrentPolicyName
        The name of the current policy that unassociated objects currently have.

    .PARAMETER TargetPolicyName
        The name of the new storage policy to apply to the unassociated objects.

    .PARAMETER ClusterName
        The name of the vSphere cluster containing the unassociated objects to update.

    .EXAMPLE
        Update-StoragePolicyOfUnassociatedVsanObjects -CurrentPolicyName 'vSAN Default Storage Policy' -TargetPolicyName 'New Policy' -ClusterName 'Cluster1'
    #>

    [CmdletBinding()]
	[AVSAttribute(30, UpdatesSDDC = $false)]
    Param (
        [Parameter(Mandatory = $true, HelpMessage = 'Specify the name of the current storage policy assigned to the unassociated objects.')]
        [ValidateNotNullOrEmpty()]
        [string]$CurrentPolicyName,

        [Parameter(Mandatory = $true, HelpMessage = 'Specify the name of the target storage policy to assign to the unassociated objects.')]
        [ValidateNotNullOrEmpty()]
        [string]$TargetPolicyName,

        [Parameter(Mandatory = $true, HelpMessage = 'Specify the name of the vSphere cluster containing the unassociated objects to update.')]
        [ValidateNotNullOrEmpty()]
        [string]$ClusterName
    )

    try {
        $newPolicy = Get-SpbmStoragePolicy -Name $TargetPolicyName -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve target storage policy '$TargetPolicyName': $($_.Exception.Message)"
        return
    }

    $totalUnassociatedObjects = 0
    $updatedObjects = 0

    try {
        $cluster = Get-Cluster $ClusterName -ErrorAction Stop
	    $clusterMoRef = $cluster.ExtensionData.MoRef
        $vmHost = ($cluster | Get-VMHost | Where-Object { $_.ConnectionState -eq 'Connected' -and $_.PowerState -eq 'PoweredOn' } | Select-Object -First 1)
        if ($null -eq $vmHost) {
            throw "No connected and powered-on hosts found."
        }
        $vsanIntSys = Get-View $vmHost.ExtensionData.ConfigManager.VsanInternalSystem
        $vsanClusterObjectSys = Get-VsanView -Id VsanObjectSystem-vsan-cluster-object-system
    }
    catch {
        Write-Error "Failed to retrieve vSAN system views: $($_.Exception.Message)"
        return
    }

    try {
	    #VsanQueryObjectIdentities(Cluster, objUuids, objTypes, includeHealth, includeObjIdentity, includeSpaceSummary))
        $unassociatedObjects = ($vsanClusterObjectSys.VsanQueryObjectIdentities($clusterMoRef, $null, $null, $false, $true, $false)).Identities | Where-Object { $null -eq $_.Vm }
    }
    catch {
        Write-Error "Failed to query unassociated vSAN objects: $($_.Exception.Message)"
        return
    }

    if (-not $unassociatedObjects) {
        Write-Output "No unassociated objects found."
        return
    }

    foreach ($obj in $unassociatedObjects) {
        $totalUnassociatedObjects++
        try {
            $jsonResult = ($vsanIntSys.GetVsanObjExtAttrs($obj.Uuid)) | ConvertFrom-Json
            $objectID = ($jsonResult.PSObject.Properties.Name | Select-Object -First 1)
            $objectInfo = $jsonResult.$objectID
        }
        catch {
            Write-Warning "Failed to retrieve or parse attributes for object $($obj.Uuid): $($_.Exception.Message)"
            continue
        }

        if ($null -eq $objectInfo.'User friendly name') {
            Write-Warning "No user friendly name for object UUID: $($obj.Uuid). Skipping Test-AVSProtectedObjectName check."
            $friendlyName = 'NO USER FRIENDLY NAME'
        }
        else {
            $friendlyName = $objectInfo.'User friendly name'
            try {
                if (Test-AVSProtectedObjectName -Name $friendlyName) {
                    Write-Error "The object '$friendlyName' is protected. Skipping policy update for UUID: $($obj.Uuid)."
                    continue
                }
            }
            catch {
                Write-Warning "Failed to check if object name '$friendlyName' is protected: $($_.Exception.Message)"
                continue
            }
        }

        if ($obj.SpbmProfileName -eq $CurrentPolicyName) {
            Write-Output "Unassociated object $($obj.Uuid) with policy '$CurrentPolicyName' is being updated to '$TargetPolicyName'..."
            try {
                $profileSpec = New-Object VMware.Vim.VirtualMachineDefinedProfileSpec
                $profileSpec.ProfileId = $newPolicy.Id

                $vsanClusterObjectSys.VosSetVsanObjectPolicy($clusterMoRef, $obj.Uuid, $profileSpec)
                Write-Output "Successfully updated storage policy for UUID: $($obj.Uuid)"
                $updatedObjects++
                Write-Output $jsonResult
            }
            catch {
                Write-Error "Failed to update storage policy for object '$($obj.Uuid)': $($_.Exception.Message)"
            }
        }
    }
    Write-Output "Total unassociated objects: $totalUnassociatedObjects"
    Write-Output "Unassociated objects with policy '$CurrentPolicyName' updated to '$TargetPolicyName': $updatedObjects"
    if ($updatedObjects -eq 0) {
        Write-Output "No unassociated objects with policy '$CurrentPolicyName' found."
    }
}

<#
    .Synopsis
     Gets all the vSAN based storage policies available to set on a VM.
#>
function Get-StoragePolicies {
    [AVSAttribute(3, UpdatesSDDC = $False)]
    Param()

    $StoragePolicies
    try {
        $StoragePolicies = Get-SpbmStoragePolicy -Namespace "VSAN" -ErrorAction Stop | Select-Object Name, AnyOfRuleSets
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get storage policies" -ErrorAction Stop
    }
    if ($null -eq $StoragePolicies) {
        Write-Host "Could not find any storage policies."
    }
    else {
        Write-Output "Available Storage Policies:"
        $StoragePolicies | Format-List | Out-String
    }
}

<#
    .Synopsis
     Modify vSAN based storage policies on a VM(s)

    .Parameter StoragePolicyName
     Name of a vSAN based storage policy to set on the specified VM. Options can be seen in vCenter or using the Get-StoragePolicies command.

    .Parameter VMName
     Name of the VM to set the vSAN based storage policy on. This supports wildcards for bulk operations. For example, MyVM* would attempt to change the storage policy on MyVM1, MyVM2, MyVM3, etc.

    .Example
    # Set the vSAN based storage policy on MyVM to RAID-1 FTT-1
    Set-VMStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -VMName "MyVM"
#>
function Set-VMStoragePolicy {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the storage policy to set')]
        [ValidateNotNullOrEmpty()]
        [string]
        $StoragePolicyName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the VM to set the storage policy on')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName
    )
    $StoragePolicy, $VSANStoragePolicies = Get-StoragePolicyInternal $StoragePolicyName -ErrorAction Stop
    $VMList = Get-VM $VMName

    if ($null -eq $VMList) {
        Write-Error "Was not able to set the storage policy on the VM. Could not find VM(s) with the name: $VMName" -ErrorAction Stop
    }
    elseif ($VMList.count -eq 1) {
        $VM = $VMList[0]
        Set-StoragePolicyOnVM -VM $VM -VSANStoragePolicies $VSANStoragePolicies -StoragePolicy $StoragePolicy -ErrorAction Stop
    }
    else {
        foreach ($VM in $VMList) {
            Set-StoragePolicyOnVM -VM $VM -VSANStoragePolicies $VSANStoragePolicies -StoragePolicy $StoragePolicy -ErrorAction Continue
        }
    }
}

<#
    .Synopsis
     Modify vSAN based storage policies on all VMs in a Container

    .Parameter StoragePolicyName
     Name of a vSAN based storage policy to set on the specified VM. Options can be seen in vCenter or using the Get-StoragePolicies command.

    .Parameter Location
     Name of the Folder, ResourcePool, or Cluster containing the VMs to set the storage policy on.
     For example, if you would like to change the storage policy of all the VMs in the cluster "Cluster-2", then supply "Cluster-2".
     Similarly, if you would like to change the storage policy of all the VMs in a folder called "MyFolder", supply "MyFolder"

    .Example
    # Set the vSAN based storage policy on all VMs in MyVMs to RAID-1 FTT-1
    Set-LocationStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -Location "MyVMs"
#>
function Set-LocationStoragePolicy {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the storage policy to set')]
        [ValidateNotNullOrEmpty()]
        [string]
        $StoragePolicyName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the Folder, ResourcePool, or Cluster containing the VMs to set the storage policy on.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Location
    )
    $StoragePolicy, $VSANStoragePolicies = Get-StoragePolicyInternal $StoragePolicyName -ErrorAction Stop
    $VMList = Get-VM -Location $Location

    if ($null -eq $VMList) {
        Write-Error "Was not able to set storage policies. Could not find VM(s) in the container: $Location" -ErrorAction Stop
    }
    else {
        foreach ($VM in $VMList) {
            Set-StoragePolicyOnVM -VM $VM -VSANStoragePolicies $VSANStoragePolicies -StoragePolicy $StoragePolicy -ErrorAction Continue
        }
    }
}

<#
    .Synopsis
     Specify default storage policy for a cluster(s)

    .Parameter StoragePolicyName
     Name of a vSAN based storage policy to set to be the default for VMs on this cluster. Options can be seen in vCenter or using the Get-StoragePolicies command.

    .Parameter ClusterName
     Name of the cluster to set the default on. This supports wildcards for bulk operations. For example, MyCluster* would attempt to change the storage policy on MyCluster1, MyCluster2, etc.

    .Example
    # Set the default vSAN based storage policy on MyCluster to RAID-1 FTT-1
    Set-ClusterDefaultStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -ClusterName "MyCluster"
#>
function Set-ClusterDefaultStoragePolicy {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the storage policy to set')]
        [ValidateNotNullOrEmpty()]
        [string]
        $StoragePolicyName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the Cluster to set the storage policy on')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ClusterName
    )
    $StoragePolicy, $VSANStoragePolicies = Get-StoragePolicyInternal $StoragePolicyName
    $CompatibleDatastores = Get-SpbmCompatibleStorage -StoragePolicy $StoragePolicy
    $ClusterList = Get-Cluster $ClusterName
    if ($null -eq $ClusterList) {
        Write-Error "Could not find Cluster with the name $ClusterName." -ErrorAction Stop
    }

    $ClusterDatastores = $ClusterList | Get-VMHost | Get-Datastore

    if ($null -eq $ClusterDatastores) {
        $hosts = $ClusterList | Get-VMHost
        if ($null -eq $hosts) {
            Write-Error "Was not able to set the Storage policy on $ClusterList. The Cluster does not appear to have VM Hosts. Please add VM Hosts before setting storage policy" -ErrorAction Stop
        }
        else {
            Write-Error "Setting the Storage Policy on this Cluster is not supported." -ErrorAction Stop
        }
    }
    elseif ($ClusterDatastores.count -eq 1) {
        if ($ClusterDatastores[0] -in $CompatibleDatastores) {
            try {
                Write-Host "Setting Storage Policy on $ClusterList to $StoragePolicyName..."
                Set-SpbmEntityConfiguration -Configuration (Get-SpbmEntityConfiguration $ClusterDatastores[0]) -storagePolicy $StoragePolicy -ErrorAction Stop -Confirm:$false
                Write-Output "Successfully set the Storage Policy on $ClusterList to $StoragePolicyName"
            }
            catch {
                Write-Error "Was not able to set the Storage Policy on the Cluster Datastore: $($PSItem.Exception.Message)" -ErrorAction Stop
            }
        }
        else {
            Write-Error "Modifying the default storage policy on this cluster: $($ClusterDatastores[0]) is not supported" -ErrorAction Stop
        }
    }
    else {
        foreach ($Datastore in $ClusterDatastores) {
            if ($Datastore -in $CompatibleDatastores) {
                try {
                    Write-Host "Setting Storage Policy on $Datastore to $StoragePolicyName..."
                    Set-SpbmEntityConfiguration -Configuration (Get-SpbmEntityConfiguration $Datastore) -storagePolicy $StoragePolicy -ErrorAction Stop -Confirm:$false
                    Write-Output "Successfully set the storage policy on $Datastore to $StoragePolicyName"
                }
                catch {
                    Write-Error "Was not able to set the storage policy on the Cluster Datastore: $($PSItem.Exception.Message)" -ErrorAction Stop
                }
            }
            else {
                Write-Error "Modifying the default storage policy on $Datastore is not supported" -ErrorAction Continue
                continue
            }
        }
    }
}

<#
    .Synopsis
     This will create a folder on each cluster's vSAN datastore -- GuestStore and set each cluster to pull tools from their respective vsan datastore. The 'gueststore-vmtools' file is required.
     The Tools zip file must be in a publicly available HTTP(S) downloadable location.

     .EXAMPLE
     Once the function is imported, you simply need to run Set-ToolsRepo -ToolsURL <url to tools zip file>
#>
function Set-ToolsRepo {
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $true,
            HelpMessage = 'A publicly available HTTP(S) URL to download the Tools zip file.')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https?://')]
        [SecureString]
        $Tools_URL
    )

    # Initialize variables
    $new_folder = 'GuestStore'
    $archive_path = '/vmware/apps/vmtools/windows64/'
    $tmp_dir = $null
    $currentPSDrive = $null
    $successfulDatastores = @()
    $failedDatastores = @()

    # Main execution wrapped in try-catch-finally
    try {
        Write-Verbose "Starting Set-ToolsRepo with URL: $Tools_URL"

        # Validate URL accessibility
        try {
            $webResponse = Invoke-WebRequest -Uri $Tools_URL -Method Head -TimeoutSec 30 -ErrorAction Stop
            if ($webResponse.StatusCode -ne 200) {
                throw "URL returned status code: $($webResponse.StatusCode)"
            }
        } catch {
            throw "Unable to access the provided URL: $_"
        }

        # Create temporary directory with error handling
        try {
            $tmp_dir = New-Item -Path "./newtools_$(Get-Date -Format 'yyyyMMddHHmmss')" -ItemType Directory -ErrorAction Stop
            Write-Verbose "Created temporary directory: $tmp_dir"
        } catch {
            throw "Failed to create temporary directory: $_"
        }

        $tools_file = Join-Path -Path $tmp_dir -ChildPath "tools.zip"

        # Download the tools file with progress
        try {
            Write-Information "Downloading tools from $Tools_URL..." -InformationAction Continue
            $ProgressPreference = 'Continue'
            Invoke-WebRequest -Uri $Tools_URL -OutFile $tools_file -ErrorAction Stop

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
            Expand-Archive -Path $tools_file -DestinationPath $tmp_dir -Force -ErrorAction Stop
        } catch {
            throw "Failed to extract tools archive: $_"
        }

        # Find and validate tools version
        $tools_path_new = Join-Path -Path $tmp_dir -ChildPath "${archive_path}vmtools-*"
        $tools_directories = Get-ChildItem -Path $tools_path_new -Directory -ErrorAction SilentlyContinue

        if ($null -eq $tools_directories -or $tools_directories.Count -eq 0) {
            throw "Unable to find vmtools directory in the extracted archive. Is this a valid GuestStore bundle?"
        }

        $tools_version = $tools_directories[0].Name
        $tools_short_version = $tools_version -replace 'vmtools-', ''
        Write-Information "Found tools version: $tools_version" -InformationAction Continue

        # Get vSAN datastores with error handling
        try {
            $datastores = Get-Datastore -ErrorAction Stop | Where-Object { $_.extensionData.Summary.Type -eq 'vsan' }

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
                    $currentPSDrive = New-PSDrive -Location $datastore -Name DS -PSProvider VimDatastore -Root '\' -ErrorAction Stop
                } catch {
                    throw "Failed to create PSDrive for datastore $ds_name : $_"
                }

                # Check if repo folder exists
                try {
                    $Dsbrowser = Get-View -Id $Datastore.Extensiondata.Browser -ErrorAction Stop
                    $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
                    $spec.Query += New-Object VMware.Vim.FolderFileQuery
                    $searchResult = $dsBrowser.SearchDatastore("[$ds_name] \", $spec)
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
                    $searchResult = $dsBrowser.SearchDatastore("[$ds_name] \", $spec)
                    $folderObj = $searchResult.File | Where-Object { $_.FriendlyName -eq $new_folder }

                    if ($null -eq $folderObj) {
                        throw "Folder verification failed after creation on $ds_name"
                    }
                }

                # Check existing tools versions
                $do_not_copy = $false
                $tools_path = "DS:/$new_folder/$archive_path"

                if (Test-Path -Path $tools_path) {
                    try {
                        # $existing_dirs = Get-ChildItem -Path $tools_path -Directory -ErrorAction Stop
                        $existing_dirs = Get-ChildItem -Path $tools_path -ErrorAction Stop | Where-Object Name -Match vmtools

                        foreach ($existing_dir in $existing_dirs) {
                            $ver = $existing_dir.Name -replace 'vmtools-', ''
                            if ([version]$ver -ge [version]$tools_short_version) {
                                $do_not_copy = $true
                                Write-Information "Found newer or equal version ($ver) on $ds_name" -InformationAction Continue
                                break
                            }
                        }
                    } catch {
                        Write-Warning "Failed to check existing versions on $ds_name : $_"
                        # Continue with copy operation if we can't verify existing versions
                    }
                }

                # Copy files if needed
                if (-not $do_not_copy) {
                    try {
                        Write-Information "Copying $tools_version to $ds_name..." -InformationAction Continue
                        # $sourcePath = $tools_directories[0].ResolvedTarget
                        Copy-DatastoreItem -Item "$tmp_dir/vmware" -Destination "DS:/$new_folder" -Recurse -Force -ErrorAction Stop
                        Write-Information "Successfully copied tools to $ds_name" -InformationAction Continue
                    } catch {
                        throw "Failed to copy tools to $ds_name : $_"
                    }
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
                    throw "Failed to configure hosts: $($failedHosts -join ', ')"
                }

                $successfulDatastores += $ds_name
            } catch {
                Write-Error "Error processing datastore $ds_name : $_"
                $failedDatastores += $ds_name
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
            Write-Information "Successfully processed datastores: $($successfulDatastores -join ', ')" -InformationAction Continue
        }
        if ($failedDatastores.Count -gt 0) {
            Write-Warning "Failed datastores: $($failedDatastores -join ', ')"
        }

        if ($failedDatastores.Count -eq $datastores.Count) {
            throw "Failed to process any datastores successfully"
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
    Set vSAN compression and deduplication on a cluster or clusters. If deduplication is enabled then compression is required.
    The default cluster configuration is deduplication and compression but the customer can change that.
    Choosing neither compression nor deduplication will disable both.
    This requires action on every physical disk and will take time to complete.
.EXAMPLE
    Set-vSANCompressDedupe -ClustersToChange "cluster-1,cluster-2" -Compression $true
    Set-vSANCompressDedupe -ClustersToChange "cluster-1,cluster-2" -Deduplication $true
    Set-vSANCompressDedupe -ClustersToChange "cluster-1,cluster-2"
    Set-vSANCompressDedupe -ClustersToChange "*"
#>
function Set-vSANCompressDedupe {
    [AVSAttribute(60, UpdatesSDDC = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [String]$ClustersToChange,
        [Parameter(Mandatory = $false,
            HelpMessage = "Enable compression and deduplication.")]
        [bool]$Deduplication,
        [Parameter(Mandatory = $false,
            HelpMessage = "Enable compression only.")]
        [bool]$Compression
    )

    # $cluster is an array of cluster names or "*""
    foreach ($cluster_each in ($ClustersToChange.split(",", [System.StringSplitOptions]::RemoveEmptyEntries)).Trim()) {
        $Clusters += Get-Cluster -Name $cluster_each
    }

    foreach ($Cluster in $Clusters) {
        $cluster_name = $Cluster.Name

        If ($Deduplication) {
            # Deduplication requires compression
            Write-Host "Enabling deduplication and compression on $cluster_name"
            Set-VsanClusterConfiguration -Configuration $cluster_name -SpaceEfficiencyEnabled $true
        }
        elseif ($Compression) {
            # Compression only
            Write-Host "Enabling compression on $cluster_name"
            Set-VsanClusterConfiguration -Configuration $cluster_name -SpaceCompressionEnabled $true
        }
        else {
            # Disable both
            Write-Host "Disabling deduplication and compression on $cluster_name"
            Set-VsanClusterConfiguration -Configuration $cluster_name -SpaceEfficiencyEnabled $false
        }
    }
}

Function Remove-AVSStoragePolicy {
    <#
    .DESCRIPTION
        This function removes a storage policy.
    .PARAMETER Name
        Name of Storage Policy. Wildcards are not supported and will be stripped.
    .EXAMPLE
        Remove-AVSStoragePolicy -Name "Encryption"
    #>

    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    Begin {
        #Remove Wildcards characters from Name
        $Name = Limit-WildcardsandCodeInjectionCharacters $Name
        #Protected Policy Object Name Validation Check
        If (Test-AVSProtectedObjectName -Name $Name) {
            Write-Error "$Name is a protected policy name.  Please choose a different policy name."
            return
        }

    }
    Process {
        #Get Storage Policy
        $StoragePolicy = Get-SpbmStoragePolicy -Name $Name -ErrorAction SilentlyContinue
        #Remove Storage Policy
        If ([string]::IsNullOrEmpty($StoragePolicy)) {
            Write-Error "Storage Policy $Name does not exist."
            return
        }
        Else { Remove-SpbmStoragePolicy -StoragePolicy $StoragePolicy -Confirm:$false }

    }
}

<#
.SYNOPSIS
    Create vSAN storage policies for ESA and/or OSA architectures.

.DESCRIPTION
    This function detects the vSAN architecture (ESA and/or OSA) present in the environment and creates
    appropriate storage policies. If both architectures are present, it creates separate policies for each,
    appending "-ESA" and "-OSA" to the policy name.

    For ESA: Supports compression (optional). Deduplication is not supported.
    For OSA: Compression and deduplication are not supported (cluster-level settings).

.PARAMETER PolicyName
    Required. The base name for the new storage policy. The vSAN type (ESA/OSA) will be appended.

.PARAMETER FailuresToTolerate
    Optional. Number of host failures to tolerate (FTT). Valid values: 0, 1, 2, 3. Default is 1.
    - FTT=0: No data redundancy (requires FailureToleranceMethod = 'None')
    - FTT=1: 1 failure (supports RAID-1 or RAID-5)
    - FTT=2: 2 failures (supports RAID-1 or RAID-6)
    - FTT=3: 3 failures (supports RAID-1 only)

.PARAMETER FailureToleranceMethod
    Optional. The method used to achieve failure tolerance. Valid values:
    - 'None': No data redundancy (requires FTT=0)
    - 'RAID1': RAID-1 Mirroring - Performance (supports FTT 0-3)
    - 'RAID5': RAID-5 Erasure Coding - Capacity (requires FTT=1, minimum 4 hosts)
    - 'RAID6': RAID-6 Erasure Coding - Capacity (requires FTT=2, minimum 6 hosts)
    Default is 'RAID1'.

.PARAMETER DisasterTolerance
    Optional. Site disaster tolerance method. Valid values: 'None', 'Dual', 'Preferred'. Default is 'None'.

.PARAMETER VmEncryption
    Optional. Enable VM encryption. Default is $false.

.PARAMETER ObjectSpaceReservation
    Optional. Object space reservation percentage (0-100). Default is 0 (thin provisioning).

.PARAMETER StripesPerObject
    Optional. Number of disk stripes per object (1-12). Default is 1.

.PARAMETER IopsLimit
    Optional. IOPS limit for the object. Set to 0 for unlimited. Default is 0.

.PARAMETER CacheReservation
    Optional. Flash cache reservation percentage (0-100). Default is 0.

.PARAMETER DisableChecksum
    Optional. Disable object checksum. Default is $false (checksum enabled).

.PARAMETER ForceProvisioning
    Optional. Force provisioning even if resources are insufficient. Default is $false.

.PARAMETER NoCompression
    Optional. Disable compression (ESA only). Default is $false (compression enabled).

.PARAMETER Description
    Optional. A description for the storage policy. If not provided, a default description will be used.

.EXAMPLE
    New-AVSStoragePolicy -PolicyName "VSAN-RAID1"

    Detects vSAN types. If both ESA and OSA clusters exist, creates "VSAN-RAID1-ESA" and "VSAN-RAID1-OSA".
    For ESA, compression is enabled by default.

.EXAMPLE
    New-AVSStoragePolicy -PolicyName "High-Performance" -FailuresToTolerate 2 -StripesPerObject 2 -IopsLimit 5000 -NoCompression

    Creates high-performance policies (e.g., "High-Performance-ESA") with FTT=2, 2 stripes per object, 5000 IOPS limit, and compression disabled.

.EXAMPLE
    New-AVSStoragePolicy -PolicyName "Encrypted-Storage" -VmEncryption $true -ObjectSpaceReservation 50

    Creates encrypted storage policies with 50% thick provisioning.

.NOTES
    Requires VMware PowerCLI and an active connection to vCenter Server.
    The vSAN cluster must be configured for the appropriate architecture (ESA or OSA).

    Policy Configuration:
    - Storage Type: vSAN ESA or OSA (configurable)
    - Failure Tolerance Method: RAID-1 (Mirroring)
    - Failures To Tolerate: 1
    - Compression: Enabled (ESA default)
#>

function New-AVSStoragePolicy {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $true,
            HelpMessage = "Name for the new storage policy")]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,

        [Parameter(Mandatory = $false,
            HelpMessage = "Number of host failures to tolerate (0-3)")]
        [ValidateRange(0, 3)]
        [int]$FailuresToTolerate = 1,

        [Parameter(Mandatory = $false,
            HelpMessage = "Failure tolerance method: None, RAID1, RAID5, RAID6")]
        [ValidateSet("None", "RAID1", "RAID5", "RAID6")]
        [string]$FailureToleranceMethod = "RAID1",

        [Parameter(Mandatory = $false,
            HelpMessage = "Site disaster tolerance method")]
        [ValidateSet("None", "Dual", "Preferred")]
        [string]$DisasterTolerance = "None",

        [Parameter(Mandatory = $false,
            HelpMessage = "Enable VM encryption")]
        [bool]$VmEncryption = $false,

        [Parameter(Mandatory = $false,
            HelpMessage = "Object space reservation percentage (0-100)")]
        [ValidateRange(0, 100)]
        [int]$ObjectSpaceReservation = 0,

        [Parameter(Mandatory = $false,
            HelpMessage = "Number of disk stripes per object (1-12)")]
        [ValidateRange(1, 12)]
        [int]$StripesPerObject = 1,

        [Parameter(Mandatory = $false,
            HelpMessage = "IOPS limit (0 = unlimited)")]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$IopsLimit = 0,

        [Parameter(Mandatory = $false,
            HelpMessage = "Flash cache reservation percentage (0-100)")]
        [ValidateRange(0, 100)]
        [int]$CacheReservation = 0,

        [Parameter(Mandatory = $false,
            HelpMessage = "Disable object checksum")]
        [bool]$DisableChecksum = $false,

        [Parameter(Mandatory = $false,
            HelpMessage = "Force provisioning even if resources are insufficient")]
        [bool]$ForceProvisioning = $false,

        [Parameter(Mandatory = $false,
            HelpMessage = "Disable compression (ESA only)")]
        [switch]$NoCompression,

        [Parameter(Mandatory = $false,
            HelpMessage = "Description for the storage policy")]
        [string]$Description
    )

    begin {
        Write-Verbose "Using vCenter Server: $($VIServer.Name)"

        # Detect vSAN types present in the environment
        $typesToCreate = @()
        try {
            $clusters = Get-Cluster
            foreach ($cluster in $clusters) {
                try {
                    # Check for ESA by looking at the vSAN version and configuration
                    $config = Get-VsanClusterConfiguration -Cluster $cluster -ErrorAction Stop
                    if ($config.VsanEsaEnabled) {
                        if ($typesToCreate -notcontains "ESA") { $typesToCreate += "ESA" }
                    } else {
                        if ($typesToCreate -notcontains "OSA") { $typesToCreate += "OSA" }
                    }
                } catch {
                    Write-Verbose "Cluster $($cluster.Name) is not a vSAN cluster or config retrieval failed."
                }
            }
        } catch {
            Write-Error "Failed to enumerate clusters."
            return
        }

        if ($typesToCreate.Count -eq 0) {
            Write-Error "No vSAN clusters found."
            return
        }

        Write-Information "Detected vSAN types: $($typesToCreate -join ', ')"

        # Validate FTT and Failure Tolerance Method combination
        if ($FailureToleranceMethod -eq "None" -and $FailuresToTolerate -ne 0) {
            Write-Error "Failure tolerance method 'None' requires FailuresToTolerate = 0"
            return
        }
        if ($FailuresToTolerate -eq 0 -and $FailureToleranceMethod -ne "None") {
            Write-Error "FailuresToTolerate = 0 requires FailureToleranceMethod = 'None'"
            return
        }
        if ($FailureToleranceMethod -eq "RAID5" -and $FailuresToTolerate -ne 1) {
            Write-Error "RAID-5 erasure coding requires FailuresToTolerate = 1"
            return
        }
        if ($FailureToleranceMethod -eq "RAID6" -and $FailuresToTolerate -ne 2) {
            Write-Error "RAID-6 erasure coding requires FailuresToTolerate = 2"
            return
        }
    }

    process {
        $createdPolicies = @()

        foreach ($StorageType in $typesToCreate) {
            try {
                # Append type to policy name
                $CurrentPolicyName = "$PolicyName-$StorageType"

                # Generate description if not provided
                $CurrentDescription = $Description
                if (-not $CurrentDescription) {
                    $ftmText = switch ($FailureToleranceMethod) {
                        "None" { "no redundancy" }
                        "RAID1" { "RAID-1 FTT=$FailuresToTolerate" }
                        "RAID5" { "RAID-5 FTT=1" }
                        "RAID6" { "RAID-6 FTT=2" }
                    }

                    if ($StorageType -eq "ESA") {
                        $compressionText = if (-not $NoCompression) { "compression" } else { "no compression" }
                        $CurrentDescription = "vSAN ESA policy with $ftmText, $compressionText"
                    } else {
                        $CurrentDescription = "vSAN OSA policy with $ftmText"
                    }
                }

                # Check if policy with this name already exists
                $existingPolicy = Get-SpbmStoragePolicy -Name $CurrentPolicyName -ErrorAction SilentlyContinue -Server $VIServer
                if ($existingPolicy) {
                    Write-Warning "A storage policy with the name '$CurrentPolicyName' already exists. Skipping."
                    continue
                }

                Write-Information "Creating vSAN $StorageType storage policy: $CurrentPolicyName"

                # Create individual capability rules
                $rules = @()

                # VSAN Storage Type
                if ($StorageType -eq "ESA") {
                    Write-Information "Configuring for ESA architecture (Allflash)"
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.storageType" -Server $VIServer) -Value "Allflash"
                } else {
                    Write-Information "Configuring for OSA architecture"
                    # OSA can be Allflash or Hybrid - using Allflash as default
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.storageType" -Server $VIServer) -Value "Allflash"
                }

                # Failures To Tolerate
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.hostFailuresToTolerate" -Server $VIServer) -Value $FailuresToTolerate

                # Failure Tolerance Method
                if ($FailureToleranceMethod -ne "None") {
                    $replicaValue = switch ($FailureToleranceMethod) {
                        "RAID1" { "RAID-1 (Mirroring) - Performance" }
                        { $_ -in "RAID5", "RAID6" } { "RAID-5/6 (Erasure Coding) - Capacity" }
                    }
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" -Server $VIServer) -Value $replicaValue
                }

                # Site Disaster Tolerance
                if ($DisasterTolerance -ne "None") {
                    $siteToleranceValue = switch ($DisasterTolerance) {
                        "Dual" { "VSAN.siteDisasterTolerance.Dual" }
                        "Preferred" { "VSAN.siteDisasterTolerance.Preferred" }
                    }
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.siteDisasterTolerance" -Server $VIServer) -Value $siteToleranceValue
                }

                # Space Efficiency (Compression) - ESA only
                if ($StorageType -eq "ESA") {
                    if (-not $NoCompression) {
                        # Compression only
                        $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" -Server $VIServer) -Value "CompressionOnly"
                    } else {
                        # No space efficiency
                        $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" -Server $VIServer) -Value "NoSpaceEfficiency"
                    }
                }
                # OSA: No compression/dedupe rules added

                # VM Encryption
                if ($VmEncryption) {
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.dataAtRestEncryption" -Server $VIServer) -Value $true
                }

                # Object Space Reservation
                if ($ObjectSpaceReservation -gt 0) {
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.proportionalCapacity" -Server $VIServer) -Value $ObjectSpaceReservation
                }

                # Stripes Per Object
                if ($StripesPerObject -gt 1) {
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.stripeWidth" -Server $VIServer) -Value $StripesPerObject
                }

                # IOPS Limit
                if ($IopsLimit -gt 0) {
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.iopsLimit" -Server $VIServer) -Value $IopsLimit
                }

                # Cache Reservation
                if ($CacheReservation -gt 0) {
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.cacheReservation" -Server $VIServer) -Value $CacheReservation
                }

                # Disable Checksum
                if ($DisableChecksum) {
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.checksumDisabled" -Server $VIServer) -Value $true
                }

                # Force Provisioning
                if ($ForceProvisioning) {
                    $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.forceProvisioning" -Server $VIServer) -Value $true
                }

                # Create the rule set
                $ruleSet = New-SpbmRuleSet -AllOfRules $rules

                # Create the storage policy
                $policy = New-SpbmStoragePolicy -Name $CurrentPolicyName -Description $CurrentDescription -AnyOfRuleSets $ruleSet -Server $VIServer

                $createdPolicies += $policy

                Write-Information "Successfully created storage policy: $CurrentPolicyName"

                # Display policy details
                Write-Information "`nPolicy Details:"
                Write-Information "  Name: $($policy.Name)"
                Write-Information "  Description: $($policy.Description)"
                Write-Information "  ID: $($policy.Id)"
                Write-Information "`nConfiguration:"
                Write-Information "  Storage Type: vSAN $StorageType"
                Write-Information "  Failures To Tolerate: $FailuresToTolerate"
                $ftmDisplay = switch ($FailureToleranceMethod) {
                    "None" { "None (No data redundancy)" }
                    "RAID1" { "RAID-1 (Mirroring)" }
                    "RAID5" { "RAID-5 (Erasure Coding)" }
                    "RAID6" { "RAID-6 (Erasure Coding)" }
                }
                Write-Information "  Failure Tolerance Method: $ftmDisplay"
                if ($DisasterTolerance -ne "None") {
                    Write-Information "  Site Disaster Tolerance: $DisasterTolerance"
                }
                if ($StorageType -eq "ESA") {
                    if (-not $NoCompression) {
                        Write-Information "  Compression: Enabled"
                    } else {
                        Write-Information "  Compression: Disabled"
                    }
                } else {
                    Write-Information "  Compression/Deduplication: Cluster-level (OSA)"
                }
                if ($VmEncryption) {
                    Write-Information "  VM Encryption: Enabled"
                }
                if ($ObjectSpaceReservation -gt 0) {
                    Write-Information "  Object Space Reservation: $ObjectSpaceReservation%"
                }
                if ($StripesPerObject -gt 1) {
                    Write-Information "  Stripes Per Object: $StripesPerObject"
                }
                if ($IopsLimit -gt 0) {
                    Write-Information "  IOPS Limit: $IopsLimit"
                }
                if ($CacheReservation -gt 0) {
                    Write-Information "  Cache Reservation: $CacheReservation%"
                }
                if ($DisableChecksum) {
                    Write-Information "  Checksum: Disabled"
                }
                if ($ForceProvisioning) {
                    Write-Information "  Force Provisioning: Enabled"
                }
            } catch {
                Write-Error "Failed to create storage policy for $StorageType : $_"
            }
        }

        # Return the created policy objects
        return $createdPolicies
    }

    end {
        Write-Information "Storage policy creation completed"
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

Function Set-AVSVSANClusterUNMAPTRIM {
    <#
    .DESCRIPTION
        This function enables vSAN UNMAP/TRIM on the cluster defined by the -Name parameter.
        Once enabled, supported Guest OS VM's must be powered off and powered back on.  A reboot will not suffice.
        See url for more information: https://core.vmware.com/resource/vsan-space-efficiency-technologies#sec19560-sub6
    .PARAMETER Name
        Name of Clusters as defined in vCenter.  Valid values are blank or a comma separated list of cluster names.
        Set-AVSVSANClusterUNMAPTRIM -Name Cluster-1,Cluster-2,Cluster-3
        Enables UNMAP/TRIM on Clusters-1,2,3
        Set-AVSVSANClusterUNMAPTRIM -Enable:True
        Enables UNMAP/TRIM on all Clusters
    .PARAMETER Enable
        Set to true to enable UNMAP/TRIM on target cluster(s). Default is false.
        WARNING - There is a performance impact when UNMAP/TRIM is enabled.
        See url for more information: https://core.vmware.com/resource/vsan-space-efficiency-technologies#sec19560-sub6
    .EXAMPLE
        Set-AVSVSANClusterUNMAPTRIM -Name 'Cluster-1,Cluster-2,Cluster-3'
        Enables UNMAP/TRIM on Clusters-1,2,3
    .EXAMPLE
        Set-AVSVSANClusterUNMAPTRIM -Enable:True
        Enables UNMAP/TRIM on all Clusters
    #>

    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $Name,
        [Parameter(Mandatory = $true)]
        [bool]
        $Enable
    )
    begin {
        If ([string]::IsNullOrEmpty($Name)){}
        Else {
            $Name = Limit-WildcardsandCodeInjectionCharacters -String $Name
            $Array = Convert-StringToArray -String $Name
        }
        $TagName = "VSAN UNMAP/TRIM"
        $InfoMessage = "Info - There may be a performance impact when UNMAP/TRIM is enabled.
            See url for more information: https://core.vmware.com/resource/vsan-space-efficiency-technologies#sec19560-sub6"
    }
    process {
        If ([string]::IsNullOrEmpty($Array)) {
            $Clusters = Get-Cluster
            Foreach ($Cluster in $Clusters) {
                $Cluster | Set-VsanClusterConfiguration -GuestTrimUnmap:$Enable
                Add-AVSTag -Name $TagName -Description $InfoMessage -Entity $Cluster
                Write-Information "$($Cluster.Name) set to $Enabled for UNMAP/TRIM"
                If ($Enable) {
                    Write-Information $InfoMessage
                }
            }
            Get-Cluster | Set-VsanClusterConfiguration -GuestTrimUnmap:$Enable
        }
        Else {
            Foreach ($Entry in $Array) {
                If ($Cluster = Get-Cluster -name $Entry) {
                    $Cluster | Set-VsanClusterConfiguration -GuestTrimUnmap:$Enable
                    Write-Information "$($Cluster.Name) set to $Enabled for UNMAP/TRIM"
                    If ($Enable) {
                        Write-Information $InfoMessage
                        Add-AVSTag -Name $TagName -Description $InfoMessage -Entity $Cluster
                    }
                    If ($Enable -eq $false) {
                        $AssignedTag = Get-TagAssignment -Tag $Tagname -Entity $Cluster
                        Remove-TagAssignment -TagAssignment $AssignedTag -Confirm:$false
                    }
                }
            }
        }
    }
}

Function Get-AVSVSANClusterUNMAPTRIM {
    <#
    .DESCRIPTION
        This function gets vSAN UNMAP/TRIM configuration status on all clusters.
    #>

    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param ()
    begin {}
    process {
            Get-Cluster | Get-VsanClusterConfiguration | Select-Object Name, GuestTrimUnmap
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

Function Get-vSANDataInTransitEncryptionStatus {
    <#
    .DESCRIPTION
        Gets status of vSAN Data-In-Transit Encryption for all clusters in a SDDC
    #>
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param()
    begin{}
    process {
        $clusters = Get-Cluster
        $diteConfig = @()
        $vSANConigView = Get-VsanView -Id VsanVcClusterConfigSystem-vsan-cluster-config-system
        foreach ($cluster in $clusters) {
            $diteConfig += [PSCustomObject]@{
                Name = $cluster.Name
                DataEncryptionInTransit = $vSANConigView.VsanClusterGetConfig($cluster.ExtensionData.MoRef).DataInTransitEncryptionConfig.Enabled
            }
        }
        $diteConfig | Format-Table | Out-String | Write-Host
    }

}

Function Set-vSANDataInTransitEncryption {
  <#
    .DESCRIPTION
        Enable/Disable vSAN Data-In-Transit Encryption for clusters of a SDDC.
        There may be a performance impact when vSAN Data-In-Transit Encryption is enabled. Refer :  https://blogs.vmware.com/virtualblocks/2021/08/12/storageminute-vsan-data-encryption-performance/
    .PARAMETER ClusterName
        Name of the cluster. Leave blank if required to enable for whole SDDC else enter comma separated list of names.
    .PARAMETER Enable
        Specify True/False to Enable/Disable the feature.
    #>
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param (
     [Parameter(Mandatory = $false)]
     [string]
     $ClusterName,
     [Parameter(Mandatory = $true)]
     [bool]
     $Enable
    )
    begin {
        If (-not ([string]::IsNullOrEmpty($ClusterName))) {
            $ClusterNamesParsed = Limit-WildcardsandCodeInjectionCharacters -String $ClusterName
            $ClusterNamesArray = Convert-StringToArray -String $ClusterNamesParsed
        }
        Write-Host "Enable value is $Enable"
        $TagName = "vSAN Data-In-Transit Encryption" 
            $InfoMessage = "Info - There may be a performance impact when vSAN Data-In-Transit Encryption is enabled. Refer :  https://blogs.vmware.com/virtualblocks/2021/08/12/storageminute-vsan-data-encryption-performance/"
    }
    process {
        If ([string]::IsNullOrEmpty($ClusterNamesArray)) {
            $ClustersToOperateUpon = Get-Cluster
        }
        Else {
            $ClustersToOperateUpon = $ClusterNamesArray | ForEach-Object { Get-Cluster -Name $_ }
        }
        Foreach ($cluster in $ClustersToOperateUpon) {
                $vSANConfigView = Get-VsanView -Id VsanVcClusterConfigSystem-vsan-cluster-config-system
                $vSANReconfigSpec = New-Object -type VMware.Vsan.Views.VimVsanReconfigSpec
                $vSANReconfigSpec.Modify = $true
                $vSANDataInTransitConfig= New-Object -type VMware.Vsan.Views.VsanDataInTransitEncryptionConfig
                $vSANDataInTransitConfig.Enabled = $Enable
                $vSANDataInTransitConfig.RekeyInterval = 1440
                $vSANReconfigSpec.DataInTransitEncryptionConfig = $vSANDataInTransitConfig
                $task = $vSANConfigView.VsanClusterReconfig($Cluster.ExtensionData.MoRef,$vSANReconfigSpec)
                Wait-Task -Task (Get-Task -Id $task)
                If ((Get-Task -Id $task).State -eq "Success"){
                    Write-Host "$($Cluster.Name) set to $Enable"
                    If ($Enable) {
                        Add-AVSTag -Name $TagName -Description $InfoMessage -Entity $Cluster
                        Write-Information $InfoMessage
                    }
                    else {
                        $AssignedTag = Get-TagAssignment -Tag $Tagname -Entity $Cluster
                        Remove-TagAssignment -TagAssignment $AssignedTag -Confirm:$false
                    }
                }else {
                    Write-Error "Failed to set $($Cluster.Name) to $Enable"
                }
            }

        }
}
