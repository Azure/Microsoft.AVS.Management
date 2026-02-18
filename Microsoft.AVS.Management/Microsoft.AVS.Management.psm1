<# Private Function Import #>
. $PSScriptRoot\AVSGenericUtils.ps1
. $PSScriptRoot\AVSvSANUtils.ps1



function Remove-AvsUnassociatedObject {
    <#
    .SYNOPSIS
        Deletes unassociated vSAN objects from a specified cluster.

    .DESCRIPTION
        Scans a given vSphere cluster for unassociated vSAN objects.
        Performs safety checks against management VMs, system-like objects, and object health.
        Deletes objects only if they pass all checks.

        IMPORTANT: Deletion of vSAN objects is irreversible.
        Once an object is deleted, it cannot be recovered or reverted.
        Use with caution and ensure the provided UUID is correct before execution.


    .PARAMETER Uuid
        The UUID of the vSAN object to delete.

    .PARAMETER ClusterName
        The name of the vSphere cluster containing the object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uuid,
        [Parameter(Mandatory)][string]$ClusterName
    )

    $uuidNorm = ConvertTo-CanonicalUuid $Uuid
    $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop

    $mgmt = Get-MgmtResourcePoolVMs -PoolRegex (Get-AvsMgmtResourcePoolRegex) -ClusterName $ClusterName
    $mgmtNameRx = if ($mgmt.Names.Count) { New-RegexFromList -List $mgmt.Names } else { $null }
    $mgmtMoRx   = if ($mgmt.MoRefs.Count) { New-RegexFromList -List $mgmt.MoRefs } else { $null }

    $excludePattern = Get-AvsExcludePatterns
    $excludeRx = New-Object System.Text.RegularExpressions.Regex(
        $excludePattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    $vmhost = Get-VMHost -Location $cluster | Where-Object ConnectionState -eq 'Connected' | Select-Object -First 1
    $vsanIntSys = Get-View $vmhost.ExtensionData.ConfigManager.VsanInternalSystem
    $clusterMo  = $cluster.ExtensionData.MoRef
    $objSys     = Get-VsanView -Id 'VsanObjectSystem-vsan-cluster-object-system'

    $ids = $objSys.VsanQueryObjectIdentities($clusterMo, $null, $null, $true, $true, $false)
    $hit = $ids.Identities |
           Where-Object { ($_.Uuid -replace '-', '').ToLowerInvariant() -eq $uuidNorm }

    if (-not $hit) {
        Write-Warning "UUID $Uuid not found."
        return
    }

    foreach ($id in $hit) {
        $extRaw = $vsanIntSys.GetVsanObjExtAttrs($id.Uuid)
        $ext    = $null; try { $ext = $extRaw | ConvertFrom-Json } catch {}


        $fields = @($id.Name, $ext.'User friendly name', $ext.'Object path', $id.Owner, $id.Content, $id.Type, $id.Description)

        # Check if object is part of management pool
        $inMgmt = $false
        foreach ($f in $fields) {
            if ($f -and $mgmtNameRx -and ($f -match $mgmtNameRx)) { $inMgmt = $true; break }
            if ($f -and $mgmtMoRx   -and ($f -match $mgmtMoRx))   { $inMgmt = $true; break }
        }

        # Check if object is system-like
        $isSystemLike = $fields | Where-Object { $_ -and $excludeRx.IsMatch($_) } | Measure-Object | Select-Object -Expand Count
        $isSystemLike = $isSystemLike -gt 0

        $hi = Get-HealthFromExt -Ext $ext

        $safe = (-not $inMgmt) -and (-not $isSystemLike) -and (-not $hi.IsAbsent) -and (-not $hi.IsDegraded)

        if (-not $safe) {
            Write-Warning "Skipping $($id.Uuid) → InMgmt=$inMgmt SystemLike=$isSystemLike Health=$($hi.HealthState)"
            continue
        }



        try {
            [void]$vsanIntSys.DeleteVsanObjects(@($id.Uuid), $true)
            Write-Host "Deleted $($id.Uuid)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to delete $($id.Uuid): $($_.Exception.Message)"
        }
    }
}

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
        [SecureString]
        $ToolsURL
    )

    # Convert SecureString to plain text for use with web requests
    $ToolsURLPlain = [System.Net.NetworkCredential]::new('', $ToolsURL).Password

    # Validate URL pattern (must be HTTP or HTTPS)
    if ($ToolsURLPlain -notmatch '^https?://') {
        throw "ToolsURL must be a valid HTTP or HTTPS URL."
    }

    # Initialize variables
    $new_folder = 'GuestStore'
    $archive_path = '/vmware/apps/vmtools/windows64/'
    $tmp_dir = $null
    $currentPSDrive = $null
    $successfulDatastores = @()
    $failedDatastores = @()

    # Main execution wrapped in try-catch-finally
    try {
        Write-Verbose "Starting Set-ToolsRepo"

        # Validate URL accessibility
        try {
            $webResponse = Invoke-WebRequest -Uri $ToolsURLPlain -Method Head -TimeoutSec 30 -ErrorAction Stop
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
            Write-Information "Downloading tools..." -InformationAction Continue
            $ProgressPreference = 'Continue'
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

function Remove-AVSStoragePolicy {
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
    #Remove Wildcards characters from Name
    $Name = Limit-WildcardsandCodeInjectionCharacters $Name

    # Protected Policy Object Name Validation Check
    # It will throw an error if the name is protected
    Test-AVSProtectedObjectName -Name $Name

    $StoragePolicy = Get-SpbmStoragePolicy -Name $Name -ErrorAction SilentlyContinue
    if (-not $StoragePolicy) {
        throw "Storage Policy $Name does not exist."
    }

    #Remove Storage Policy
    try {
        Remove-SpbmStoragePolicy -StoragePolicy $StoragePolicy -Confirm:$false -ErrorAction Stop
        Write-Information "Storage Policy $Name removed successfully."
    } catch {
        throw "Failed to remove Storage Policy $Name. $_"
    }

    #Validate Storage Policy was removed
    $StoragePolicy = Get-SpbmStoragePolicy -Name $Name -ErrorAction SilentlyContinue
    if (-not $StoragePolicy) {
         "Storage Policy $Name removed successfully and validated."
    } else {
        throw "Storage Policy $Name still exists -- removal failed."
    }
}

function New-AVSStoragePolicy {
    <#
	.DESCRIPTION
		This function creates a new or overwrites an existing vSphere Storage Policy.
        Non vSAN-Based, vSAN Only, VMEncryption Only, Tag Only based and/or any combination of these policy types are supported.
    .PARAMETER Name
        Name of Storage Policy - Wildcards are not allowed and will be stripped.
    .PARAMETER Description
        Description of Storage Policy you are creating, free form text.
    .PARAMETER vSANSiteDisasterTolerance
        Default is "None"
        Valid Values are "None", "Preferred", "Secondary"
        None = No Site Redundancy (Recommended Option for Non-Stretch Clusters)
        Preferred = No site redundancy - keep data on Preferred (stretched cluster)
        Secondary = No site redundancy - Keep data on Secondary Site (stretched cluster)
        Only valid for stretch clusters.
    .PARAMETER vSANFailuresToTolerate
        Default is "R1FTT1"
        Valid values are "None", "R1FTT1", "R1FTT2", "R1FTT3", "R5FTT1", "R6FTT2", "R1FTT3"
        None = No Data Redundancy
        R1FTT1 = 1 failure - RAID-1 (Mirroring)
        R1FTT2 = 2 failures - RAID-1 (Mirroring)
        R1FTT3 = 3 failures - RAID-1 (Mirroring)
        R5FTT1 = 1 failure - RAID-5 (Erasure Coding)
        R6FTT2 = 2 failures - RAID-6 (Erasure Coding)
        No Data Redundancy options are not covered under Microsoft SLA.
    .PARAMETER VMEncryption
        Default is None.  Valid values are None, PreIO, PostIO.
        PreIO allows VAIO filtering solutions to capture data prior to VM encryption.
        PostIO allows VAIO filtering solutions to capture data after VM encryption.
    .PARAMETER vSANObjectSpaceReservation
        Default is 0.  Valid values are 0..100
        Object Reservation.  0=Thin Provision, 100=Thick Provision
    .PARAMETER vSANDiskStripesPerObject
        Default is 1.  Valid values are 1..12.
        The number of HDDs across which each replica of a storage object is striped.
        A value higher than 1 may result in better performance (for e.g. when flash read cache misses need to get serviced from HDD), but also results in higher use of system resources.
    .PARAMETER vSANIOLimit
        Default is unset. Valid values are 0..2147483647
        IOPS limit for the policy.
    .PARAMETER vSANCacheReservation
        Default is 0. Valid values are 0..100
        Percentage of cache reservation for the policy.
	    .PARAMETER vSANChecksumDisabled
        Default is $false. Enable or disable checksum for the policy. Valid values are $true or $false.
        WARNING - Disabling checksum may lead to data LOSS and/or corruption.
        Recommended value is $false.
    .PARAMETER NoCompression
        Switch parameter. When specified, disables space efficiency (compression) for ESA clusters.
        Only applies to vSAN ESA (Express Storage Architecture) clusters.
        When not specified (default), compression is enabled for ESA clusters.
    .PARAMETER vSANForceProvisioning
        Default is $false. Force provisioning for the policy. Valid values are $true or $false.
        WARNING - vSAN Force Provisioned Objects are not covered under Microsoft SLA.  Data LOSS and vSAN instability may occur.
        Recommended value is $false.
    .PARAMETER Tags
        Match to datastores that do have these tags.  Tags are case sensitive.
        Comma seperate multiple tags. Example: Tag1,Tag 2,Tag_3
    .PARAMETER NotTags
        Match to datastores that do NOT have these tags. Tags are case sensitive.
        Comma seperate multiple tags. Example: Tag1,Tag 2,Tag_3
    .PARAMETER Overwrite
        Overwrite existing Storage Policy.  Default is $false.
        Passing overwrite true provided will overwrite an existing policy exactly as defined.
        Those values not passed will be removed or set to default values.
    .EXAMPLE
        Creates a new storage policy named Encryption with that enables Pre-IO filter VM encryption
        New-AVSStoragePolicy -Name "Encryption" -VMEncryption "PreIO"
    .EXAMPLE
        Creates a new storage policy named "RAID-1 FTT-1 with Pre-IO VM Encryption" with a description enabled for Pre-IO VM Encryption
        New-AVSStoragePolicy -Name "RAID-1 FTT-1 with Pre-IO VM Encryption" -Description "My super secure and performant storage policy" -VMEncryption "PreIO" -vSANFailuresToTolerate "R1FTT1"
    .EXAMPLE
        Creates a new storage policy named "Tagged Datastores" to use datastores tagged with "SSD" and "NVMe" and not datastores tagged "Slow"
        New-AVSStoragePolicy -Name "Tagged Datastores" -Tags "SSD","NVMe" -NotTags "Slow"
    .EXAMPLE
        Creates a new storage policy named "Production Only" to use datastore tagged w/ Production and not tagged w/ Test or Dev.  Set with RAID-1, 100% read cache, and Thick Provisioning of Disk.
        New-AVSStoragePolicy -Name "Production Only" -Tags "Production" -NotTags "Test","Dev" -vSANFailuresToTolerate "R1FTT1" -vSANObjectSpaceReservation 100 -vSANCacheReservation 100
    .EXAMPLE
        Passing -Overwrite:$true to any examples provided will overwrite an existing policy exactly as defined.  Those values not passed will be removed or set to default values.
    .NOTES
        ESA/OSA Dual Policy Behavior:
        When both vSAN ESA (Express Storage Architecture) and OSA (Original Storage Architecture) clusters are detected,
        this function automatically creates two separate policies with '-esa' and '-osa' suffixes appended to the Name.
        - ESA policy includes space efficiency (compression) settings
        - OSA policy excludes ESA-specific settings
        When only one cluster type exists, a single policy is created with the specified Name (no suffix).
        #>
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param(
        #Add parameterSetNames to allow for vSAN, Tags, VMEncryption, StorageIOControl, vSANDirect to be optional.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [string]
        $Description,

        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Preferred", "Secondary")]
        [string]
        $vSANSiteDisasterTolerance,

        [Parameter(Mandatory = $false,
            HelpMessage = "Valid values are None, R1FTT1, R5FTT1, R1FTT2, R6FTT2, R1FTT3.")]
        [ValidateSet("None", "R1FTT1", "R5FTT1", "R1FTT2", "R6FTT2", "R1FTT3")]
        [string]
        $vSANFailuresToTolerate,

        [Parameter(Mandatory = $false,
            HelpMessage = 'Specifies the VM encryption mode. Valid values are: None, PreIO, PostIO.')]
        [ValidateSet("None", "PreIO", "PostIO")]
        [string]
        $VMEncryption,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]
        $vSANObjectSpaceReservation,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 12)]
        [int]
        $vSANDiskStripesPerObject,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 2147483647)]
        [int]
        $vSANIOLimit,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]
        $vSANCacheReservation,

        [Parameter(Mandatory = $false)]
        [boolean]
        $vSANChecksumDisabled,

        [Parameter(Mandatory = $false)]
        [boolean]
        $vSANForceProvisioning,

        [Parameter(Mandatory = $false)]
        [string]
        $Tags,

        [Parameter(Mandatory = $false)]
        [string]
        $NotTags,

        [Parameter(Mandatory = $false)]
        [Switch]
        $Overwrite,

        [Parameter(Mandatory = $false,
            HelpMessage = "Disable compression for ESA clusters.  Compression is enabled by default for ESA clusters.")]
        [Switch]
        $NoCompression
    )

    begin {
        # Set $VMEncryption to "None" if an invalid value is passed in order to prevent errors in policy creation.
        $VMEncryptionSet = @("None", "PreIO", "PostIO")
        if ($VMEncryption -notin $VMEncryptionSet) {
            $VMEncryption = "None"
        }

        try {
            $clusters = Get-Cluster
            foreach ($cluster in $clusters) {
                try {
                    # Check for ESA by looking at the vSAN version and configuration
                    $config = Get-VsanClusterConfiguration -Cluster $cluster -ErrorAction Stop
                    if ($config.VsanEsaEnabled) {
                        $hasESA = $true
                    } else {
                        $hasOSA = $true
                    }
                } catch {
                    Write-Verbose "Cluster $($cluster.Name) is not a vSAN cluster or config retrieval failed."
                }
            }
        } catch {
            Write-Error "Failed to detect vSAN cluster types: $($_.Exception.Message)"
            return $null
        }

        #Cleanup Wildcard and Code Injection Characters
        Write-Debug "Cleaning up Wildcard and Code Injection Characters from Name value: $Name"
        $Name = Limit-WildcardsandCodeInjectionCharacters -String $Name
        Write-Information "Name value after cleanup: $Name"
        Write-Debug "Cleaning up Wildcard and Code Injection Characters from Description value: $Description"
        if (![string]::IsNullOrEmpty($Description)) {
            $Description = Limit-WildcardsandCodeInjectionCharacters -String $Description
        } else {
            $Description = "AVS Storage Policy created via PowerCLI"
        }
        Write-Information "Description value after cleanup: $Description"

        #Protected Policy Object Name Validation Check
        if (Test-AVSProtectedObjectName -Name $Name) {
            Write-Error "$Name is a protected policy name.  Please choose a different policy name."
            break
        }

        #Check for existing policy names
        $checkNames = @($Name)
        if ($hasESA -and $hasOSA) {
            # When both cluster types exist, check for suffixed policy names
            $esaName = "$Name-esa"
            $osaName = "$Name-osa"
            $checkNames += $esaName, $osaName
        }

        foreach ($policyName in $checkNames) {
            $ExistingPolicy = Get-AVSStoragePolicy -Name $policyName
            Write-Information ("Existing Policy: " + $ExistingPolicy.name)
            if ($ExistingPolicy -and $Overwrite) {
                Write-Information "Storage Policy $policyName already exists and will be overwritten."
                Remove-SpbmStoragePolicy -StoragePolicy $policyName -Confirm:$false
            } elseif ($ExistingPolicy -and !$Overwrite) {
                Write-Error "Storage Policy $policyName already exists.  Set -Overwrite to `$true to overwrite existing policy."
                break
            }
        }

        $rules = @()
        # vSAN Storage Type - All Flash
        Write-Information "Adding VSAN.storageType = Allflash to ProfileSpec"
        $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.storageType" ) -Value "Allflash"

        #vSANFailurestoTolerate / FTT (intra-site when stretch cluster selected)
        Write-Information "vSANFailurestoTolerate value set to: $vSANFailuresToTolerate"
        $isStretch = ($vSANSiteDisasterTolerance -and $vSANSiteDisasterTolerance -ne 'None')
        $fttId = if ($isStretch) { 'VSAN.subFailuresToTolerate' } else { 'VSAN.hostFailuresToTolerate' }
        switch ($vSANFailuresToTolerate) {
            'None' {
                # Add-VsanCapabilityInstanceLocal -Id $fttId -Value 0 -ProfileSpecRef $profilespec | Out-Null
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 0
                $Description = $Description + " - FTT 0 based policy objects are unprotected by Microsoft SLA and data loss/corruption may occur."
                Write-Warning "$Name policy setting $vSANFailurestoTolerate based policy objects are unprotected by Microsoft SLA and data loss/corruption may occur."
            }
            'R1FTT1' {
                Write-Information "Adding VSAN.replicaPreference = RAID-1 (Mirroring) - Performance to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-1 (Mirroring) - Performance"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 1 # $vSANFailuresToTolerate
            }
            'R5FTT1' {
                Write-Information "Adding VSAN.replicaPreference = RAID-5/6 (Erasure Coding) - Capacity to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-5/6 (Erasure Coding) - Capacity"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 1 # $vSANFailuresToTolerate
                Write-Information "All Flash added to ProfileSpec as required for $vSANFailuresToTolerate"
            }
            'R1FTT2' {
                Write-Information "Adding VSAN.replicaPreference = RAID-1 (Mirroring) - Performance to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-1 (Mirroring) - Performance"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 2 # $vSANFailuresToTolerate
            }
            'R6FTT2' {
                Write-Information "Adding VSAN.replicaPreference = RAID-5/6 (Erasure Coding) - Capacity to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-5/6 (Erasure Coding) - Capacity"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 2 # $vSANFailuresToTolerate
                Write-Information "All Flash added to ProfileSpec as required for $vSANFailuresToTolerate"
            }
            'R1FTT3' {
                Write-Information "Adding VSAN.replicaPreference = RAID-1 (Mirroring) - Performance to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-1 (Mirroring) - Performance"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 3 # $vSANFailuresToTolerate
            }
            default {}
        }

        # vSAN Site Disaster Tolerance
        Write-Information "Configuring vSAN Site Disaster Tolerance and Failures to Tolerate settings"
        switch ($vSANSiteDisasterTolerance) {
            "Preferred" {
                Write-Information "Writing to Preferred Fault Domain only"
                Write-Information "Unreplicated objects in a stretch cluster are unprotected by Microsoft SLA and data loss/corruption may occur."
                $locality = "Preferred Fault Domain"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.locality" ) -Value $locality
            }
            "Secondary" {
                Write-Information "Writing to Secondary Fault Domain only"
                Write-Information "Unreplicated objects in a stretch cluster are unprotected by Microsoft SLA and data loss/corruption may occur."
                $locality = "Secondary Fault Domain"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.locality" ) -Value $locality
            }
            default { $fttId = 'VSAN.hostFailuresToTolerate' }
        }

        #vSANChecksumDisabled
        Write-Information "vSANChecksumDisabled value is: $vSANChecksumDisabled"
        if ($vSANChecksumDisabled) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.checksumDisabled" ) -Value $true
        }

        # vSANForceProvisioning
        Write-Information "vSANForceProvisioning value is: $vSANForceProvisioning"
        if ($vSANForceProvisioning) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.forceProvisioning" ) -Value $true
        }

        #vSANDiskStripesPerObject
        Write-Information "vSANDiskStripesPerObject value is: $vSANDiskStripesPerObject"
        if ($vSANDiskStripesPerObject -gt 1) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.stripeWidth" ) -Value $vSANDiskStripesPerObject
        }

        #VSANIOLimit
        Write-Information "vSANIOLimit set to: $vSANIOLimit"
        if ($vSANIOLimit -gt 0) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.iopsLimit" ) -Value $vSANIOLimit
        }

        # VSANCacheReservation
        Write-Information "vSANCacheReservation set to: $vSANCacheReservation"
        if ($vSANCacheReservation -gt 0) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.cacheReservation" ) -Value $vSANCacheReservation
        }

        #VSANObjectReservation
        if ($vSANObjectReservation -gt 0) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.proportionalCapacity" ) -Value $vSANObjectReservation
        }

        # Tags Based Placement
        $tagCategoryName = "AVS"
        if ($Tags -or $NotTags) {
            $tagCategory = Get-TagCategory -Name $tagCategoryName -ErrorAction SilentlyContinue
            if (-not $tagCategory) {
                Write-Information "Creating Tag Category '$tagCategoryName' for Storage Policy Tag based placement"
                $tagCategory = New-TagCategory -Name $tagCategoryName -Cardinality Single -EntityType Datastore
            }

            Write-Debug $Tags
            $withTagNames = @()
            $notTagNames = @()
            $tagNames = @()
            # Split strings into arrays
            if ($Tags) {
                $withTagNames = Convert-StringToArray -String $Tags | ForEach-Object { Limit-WildcardsandCodeInjectionCharacters $_ }
                $TagNames += $withTagNames
            }
            if ($NotTags) {
                $notTagNames = Convert-StringToArray -String $NotTags | ForEach-Object { Limit-WildcardsandCodeInjectionCharacters $_ }
                $TagNames += $notTagNames
            }

            foreach ($TagName in $TagNames) {
                New-AVSTag -Name $TagName
            }

            if ($Tags) {
                $withTagRules = $withTagNames | ForEach-Object {
                    $t = Get-Tag -Name $_ -Category $tagCategory
                    New-SpbmRule -AnyOfTags $t
                }
                # Now pass the rules
                $withTagRuleSet = New-SpbmRuleSet -AllOfRules $withTagRules
            }

            if ($NotTags) {
                # Create SpbmRule objects from each tag
                $notTagRules = $notTagNames | ForEach-Object {
                    $tag = Get-Tag -Name $_ -Category $tagCategory
                    New-SpbmRule -AnyOfTags $tag -SpbmOperatorType 1
                }
                # Now pass the rules
                $notTagRuleSet = New-SpbmRuleSet -AllOfRules $notTagRules
            }
        }

        # Space Efficiency (Compression) - ESA only
        if ( $hasESA) {
            if ( $NoCompression) {
                # No space efficiency
                # $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "NoSpaceEfficiency"
                $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "NoSpaceEfficiency"
            } else {
                # Compression only
                $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "CompressionOnly"
            }
        }

        # IMPORTANT - Any additional functionality should be added before the VMEncryption Parameter.
        # The reason is that this subprofile must be added as a capability to all subprofile types for API to accept.
        Write-Information "VMEncryption set to: $VMEncryption"
        switch ($VMEncryption) {
            "PreIO" {
                Write-Information "Adding VM Encryption with Pre-IO filter capability to ProfileSpec"
                # $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.dataAtRestEncryption" ) -Value $true
                $IOPolicy = Get-AVSStoragePolicy -Name "AVS PRE IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
                if (!$IOPolicy) { $IOPolicy = New-AVSCommonStoragePolicy -Encryption -Name "AVS PRE IO Encryption" -Description "Encrypts VM before VAIO Filter" -PostIOEncryption $false }
                $IOPolicy = Get-AVSStoragePolicy -Name "AVS PRE IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
            }
            "PostIO" {
                Write-Information "Adding VM Encryption with Post-IO filter capability to ProfileSpec"
                # $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.dataAtRestEncryption" ) -Value $true
                $IOPolicy = Get-AVSStoragePolicy -Name "AVS POST IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
                if (!$IOPolicy) { $IOPolicy = New-AVSCommonStoragePolicy -Encryption -Name "AVS POST IO Encryption" -Description "Encrypts VM after VAIO Filter" -PostIOEncryption $true }
                $IOPolicy = Get-AVSStoragePolicy -Name "AVS POST IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
            }
            default {
                Write-Information "No VM Encryption capability added to ProfileSpec"
            }
        }
    }

    process {
        Write-Debug "=== PROCESS BLOCK START ==="
        Write-Debug "hasESA: $hasESA"
        Write-Debug "hasOSA: $hasOSA"
        Write-Debug "Name: $Name"
        Write-Debug "rules count: $($rules.Count)"
        Write-Debug "esaRules count: $($esaRules.Count)"
        Write-Debug "withTagRuleSet: $($withTagRuleSet -ne $null)"
        Write-Debug "notTagRuleSet: $($notTagRuleSet -ne $null)"

        # if ($Description -eq "") {
        #     $Description = "AVS Common Storage Policy created via PowerCLI"
        # }

        $createdPolicyNames = @()

        if ($hasESA -and $hasOSA) {
            Write-Debug "=== CREATING BOTH ESA AND OSA POLICIES ==="
            # Create ESA policy with -esa suffix
            $esaRules = $rules
            if ($hasESA -and $NoCompression) {
                Write-Debug "Creating ESA policy with No Compression with name: $esaName"
            } else {
                Write-Debug "Creating ESA policy with Compression Only with name: $esaName"
                $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "CompressionOnly"
            }
            $esaRuleSet = New-SpbmRuleSet -AllOfRules $esaRules
            # $esaName = "$Name-esa"

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet -Confirm:$false
            }
            Write-Debug "Created ESA policy: $esaName"
            $createdPolicyNames += $esaName

            # Create OSA policy with -osa suffix
            Write-Debug "Creating OSA policy with name: $osaName"
            $osaRuleSet = New-SpbmRuleSet -AllOfRules $rules
            # $osaName = "$Name-osa"

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet -Confirm:$false
            }
            Write-Debug "Created OSA policy: $osaName"
            $createdPolicyNames += $osaName
        } elseif ($hasESA) {
            Write-Debug "=== CREATING ESA-ONLY POLICY ==="
            # ESA only - include esaRules
            $esaRules = $Rules
            $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "CompressionOnly"
            $ruleSet = New-SpbmRuleSet -AllOfRules $esaRules # $esaRules, $rules
            Write-Debug "=== CREATING ESA-ONLY ruleset ==="

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet -Confirm:$false
            }
            Write-Debug "Created ESA-only policy: $Name"
            $createdPolicyNames += $Name
        } else {
            Write-Debug "=== CREATING OSA-ONLY POLICY ==="
            # OSA only - no esaRules
            $ruleSet = New-SpbmRuleSet -AllOfRules $rules

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet -Confirm:$false
            }
            Write-Debug "Created OSA-only policy: $Name"
            $createdPolicyNames += $Name
        }

        if ($vmencryption -ne "None") {
            # switch ($VMEncryption) {
            #     "PreIO" {
            #         Write-Information "Adding VM Encryption with Pre-IO filter capability to ProfileSpec"
            #         # $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.dataAtRestEncryption" ) -Value $true
            #         $IOPolicy = Get-AVSStoragePolicy -Name "AVS PRE IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
            #         if (!$IOPolicy) { $IOPolicy = New-AVSCommonStoragePolicy -Encryption -Name "AVS PRE IO Encryption" -Description "Encrypts VM before VAIO Filter" -PostIOEncryption $false }
            #         $IOPolicy = Get-AVSStoragePolicy -Name "AVS PRE IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
            #     }
            #     "PostIO" {
            #         Write-Information "Adding VM Encryption with Post-IO filter capability to ProfileSpec"
            #         # $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.dataAtRestEncryption" ) -Value $true
            #         $IOPolicy = Get-AVSStoragePolicy -Name "AVS POST IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
            #         if (!$IOPolicy) { $IOPolicy = New-AVSCommonStoragePolicy -Encryption -Name "AVS POST IO Encryption" -Description "Encrypts VM after VAIO Filter" -PostIOEncryption $true }
            #         $IOPolicy = Get-AVSStoragePolicy -Name "AVS POST IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
            #     }
            #     default {
            #         Write-Information "No VM Encryption capability added to ProfileSpec"
            #     }
            # }
            # Get the PBM profile manager
            $serviceInstanceView = Get-SpbmView -Id "PbmServiceInstance-ServiceInstance"
            $spbmServiceContent = $serviceInstanceView.PbmRetrieveServiceContent()
            $spbmProfMgr = Get-SpbmView -Id $spbmServiceContent.ProfileManager

            # Build the encryption capability instance (NOT a SubProfile)
            $encCapability = New-Object VMware.Spbm.Views.PbmCapabilityInstance
            $encCapability.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
            $encCapability.Id.Namespace = "com.vmware.storageprofile.dataservice"
            $encCapability.Id.Id = $IOPolicy.ProfileId.UniqueId
            $encCapability.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
            $encCapability.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
            $encCapability.Constraint[0].PropertyInstance[0].Id = $IOPolicy.ProfileId.UniqueId
            $encCapability.Constraint[0].PropertyInstance[0].Value = $IOPolicy.ProfileId.UniqueId

            # Retrieve the full profile we just created
            $pbmProfileResourceType = New-Object VMware.Spbm.Views.PbmProfileResourceType
            $pbmProfileResourceType.ResourceType = "STORAGE"
            $allProfiles = $spbmProfMgr.PbmQueryProfile($pbmProfileResourceType, "REQUIREMENT")
            $fullProfiles = $spbmProfMgr.PbmRetrieveContent($allProfiles)
            $targetProfile = $fullProfiles | Where-Object { $_.Name -eq $Name }

            # Add to EVERY existing sub-profile (VAIO rules must be identical across all rulesets)
            $existingConstraints = $targetProfile.Constraints
            foreach ($subProfile in $existingConstraints.SubProfiles) {
                $subProfile.Capability += $encCapability
            }

            $updateSpec = New-Object VMware.Spbm.Views.PbmCapabilityProfileUpdateSpec
            $updateSpec.Name = $targetProfile.Name
            $updateSpec.Description = $targetProfile.Description
            $updateSpec.Constraints = $existingConstraints

            # Update
            $spbmProfMgr.PbmUpdate($targetProfile.ProfileId, $updateSpec)
        }

        Write-Debug "=== PROCESS BLOCK END ==="
        Write-Debug "Returning policy names: $($createdPolicyNames -join ', ')"
        return $createdPolicyNames
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
