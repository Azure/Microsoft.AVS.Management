using module Microsoft.AVS.Management

<#
    .SYNOPSIS
     This function updates all hosts in the specified cluster to have the following iSCSI configurations:

     1. SCSI IP address are added as dynamic iSCSI addresses.
     2. iSCSI Software Adapter is enabled.
     3. Apply iSCSI best practices configuration on dynamic targets.

    .PARAMETER ClusterName
     Cluster name

    .PARAMETER ScsiIpAddress
     IP Address to add as dynamic iSCSI target

    .EXAMPLE
     Set-VmfsIscsi -ClusterName "myCluster" -ScsiIpAddress "192.168.0.1"

    .INPUTS
     vCenter cluster name, Primary SCSI IP Addresses.

    .OUTPUTS
     None.
#>
function Set-VmfsIscsi {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Cluster name in vCenter')]
        [ValidateNotNull()]
        [String]
        $ClusterName,

        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Primary IP Address to add as dynamic iSCSI target')]
        [ValidateNotNull()]
        [String]
        $ScsiIpAddress
    )

    try {
        [ipaddress] $ScsiIpAddress
    }
    catch {
        throw "Invalid SCSI IP address $ScsiIpAddress provided."
    }

    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $ClusterName does not exist."
    }

    $VMHosts = $Cluster | Get-VMHost
    foreach ($VMHost in $VMHosts) {
        $Iscsi = $VMHost | Get-VMHostStorage
        if ($Iscsi.SoftwareIScsiEnabled -ne $true) {
            $VMHost | Get-VMHostStorage | Set-VMHostStorage -SoftwareIScsiEnabled $True | Out-Null
        }

        $IscsiAdapter = $VMHost | Get-VMHostHba -Type iScsi | Where-Object {$_.Model -eq "iSCSI Software Adapter"}
        if (!(Get-IScsiHbaTarget -IScsiHba $IscsiAdapter -Type Send -ErrorAction stop | Where-Object {$_.Address -cmatch $ScsiIpAddress})) {
            New-IScsiHbaTarget -IScsiHba $IscsiAdapter -Address $ScsiIpAddress -ErrorAction stop
        }

        $EsxCli = $VMHost | Get-EsxCli -v2
        $IscsiArgs = $EsxCli.iscsi.adapter.discovery.sendtarget.param.get.CreateArgs()
        $IscsiArgs.adapter = $IscsiAdapter.Device
        $IscsiArgs.address = $ScsiIpAddress
        $DelayedAck = $EsxCli.iscsi.adapter.discovery.sendtarget.param.get.invoke($IscsiArgs) | Where-Object {$_.name -eq "DelayedAck"}
        $LoginTimeout = $EsxCli.iscsi.adapter.discovery.sendtarget.param.get.invoke($IscsiArgs) | Where-Object {$_.name -eq "LoginTimeout"}
        if ($DelayedAck.Current -eq "true") {
            $IscsiArgs = $EsxCli.iscsi.adapter.discovery.sendtarget.param.set.CreateArgs()
            $IscsiArgs.adapter = $IscsiAdapter.Device
            $IscsiArgs.address = $ScsiIpAddress
            $IscsiArgs.value = "false"
            $IscsiArgs.key = "DelayedAck"
            $EsxCli.iscsi.adapter.discovery.sendtarget.param.set.invoke($IscsiArgs) | Out-Null
        }

        if ($LoginTimeout.Current -ne "30") {
            $IscsiArgs = $EsxCli.iscsi.adapter.discovery.sendtarget.param.set.CreateArgs()
            $IscsiArgs.adapter = $IscsiAdapter.Device
            $IscsiArgs.address = $ScsiIpAddress
            $IscsiArgs.value = "30"
            $IscsiArgs.key = "LoginTimeout"
            $EsxCli.iscsi.adapter.discovery.sendtarget.param.set.invoke($IscsiArgs) | Out-Null
        }
    }

    Write-Host "Successfully configured VMFS iSCSI for cluster $ClusterName."
}

<#
    .SYNOPSIS
     Creates a new VMFS datastore and mounts to a VMware cluster.

    .PARAMETER ClusterName
     Cluster name

    .PARAMETER DatastoreName
     Datastore name

    .PARAMETER DeviceNaaId
     NAA ID of device used to create a new VMFS datastore

    .PARAMETER Size
     Datastore capacity size in bytes

    .EXAMPLE
     New-VmfsDatastore -ClusterName "myCluster" -DatastoreName "myDatastore" -DeviceNaaId $DeviceNaaId -Size <size-in-bytes>

    .INPUTS
     vCenter cluster name, datastore name, device NAA ID and datastore size.

    .OUTPUTS
     None.
#>
function New-VmfsDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Cluster name in vCenter')]
        [ValidateNotNull()]
        [String]
        $ClusterName,

        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Name of VMFS datastore to be created in vCenter')]
        [ValidateNotNull()]
        [String]
        $DatastoreName,

        [Parameter(
            Mandatory=$true,
            HelpMessage = 'NAA ID of device used to create a new VMFS datastore')]
        [ValidateNotNull()]
        [String]
        $DeviceNaaId,

        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Capacity of new datastore in bytes')]
        [ValidateNotNull()]
        [String]
        $Size
    )

    try {
        $SizeInBytes = [UInt64] $Size
    } catch {
        throw "Invalid Size $Size provided."
    }

    if (($SizeInBytes -lt 1073741824) -or ($SizeInBytes -gt 68169720922112)) {
        throw "Invalid Size $SizeInBytes provided. Size should be between 1 GB and 62 TB."
    }

    if ($DeviceNaaId -notlike 'naa.624a9370*') {
        throw "Invalid Device NAA ID $DeviceNaaId provided."
    }

    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $ClusterName does not exist."
    }

    $Datastore = Get-Datastore -Name $DatastoreName -ErrorAction Ignore
    if ($Datastore) {
        throw "Unable to create a datastore. Datastore '$DatastoreName' already exists."
    }

    # Create a new VMFS datastore with the specified size and rescan storage
    try {
        Write-Host "Creating datastore $DatastoreName..."

        $TotalSectors = $SizeInBytes / 512
        $Esxi = Get-View -ViewType HostSystem | Where-Object { ($_.Runtime.ConnectionState -eq 'connected') } | Select-Object -last 1
        $DatastoreSystem = Get-View -Id $Esxi.ConfigManager.DatastoreSystem
        $Device = $DatastoreSystem.QueryAvailableDisksForVmfs($null) | Where-Object { ($_.CanonicalName -eq $DeviceNaaId) }
        $DatastoreCreateOptions = $DatastoreSystem.QueryVmfsDatastoreCreateOptions($Device.DevicePath, $null)
        
        $VmfsDatastoreCreateSpec = New-Object VMware.Vim.VmfsDatastoreCreateSpec
        $VmfsDatastoreCreateSpec.DiskUuid = $Device.Uuid
        $VmfsDatastoreCreateSpec.Partition = $DatastoreCreateOptions[0].Spec.Partition
        $VmfsDatastoreCreateSpec.Partition.Partition[0].EndSector = $VmfsDatastoreCreateSpec.Partition.Partition[0].StartSector + $TotalSectors
        $VmfsDatastoreCreateSpec.Partition.TotalSectors = $TotalSectors
        $VmfsDatastoreCreateSpec.Vmfs = New-Object VMware.Vim.HostVmfsSpec
        $VmfsDatastoreCreateSpec.Vmfs.VolumeName = $DatastoreName
        
        $HostScsiDiskPartition = New-Object VMware.Vim.HostScsiDiskPartition
        $HostScsiDiskPartition.DiskName = $DeviceNaaId
        $HostScsiDiskPartition.Partition = $DatastoreCreateOptions[0].Info.Layout.Partition[0].Partition
        
        $VmfsDatastoreCreateSpec.Vmfs.Extent = $HostScsiDiskPartition
        $VmfsDatastoreCreateSpec.vmfs.MajorVersion = $DatastoreCreateOptions[0].Spec.Vmfs.MajorVersion
        
        $DatastoreSystem.CreateVmfsDatastore($VmfsDatastoreCreateSpec)
    } catch {
        Write-Error $Global:Error[0]
    }

    $Cluster | Get-VMHost | Get-VMHostStorage -RescanAllHba | Out-Null
    $Datastore = Get-Datastore -Name $DatastoreName -ErrorAction Ignore
    if (-not $Datastore -or $Datastore.type -ne "VMFS") {
        throw "Failed to create datastore $DatastoreName."
    }
}

<#
    .DESCRIPTION
     Detach and unmount a VMFS datastore from a cluster.

    .PARAMETER ClusterName
     Cluster name

    .PARAMETER DatastoreName
     Datastore name

    .EXAMPLE
     Dismount-VmfsDatastore -ClusterName "myCluster" -DatastoreName "myDatastore"

    .INPUTS
     vCenter cluster name and datastore name.

    .OUTPUTS
     None.
#>
function Dismount-VmfsDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Cluster name in vCenter')]
        [ValidateNotNull()]
        [String]
        $ClusterName,

        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Name of VMFS datastore to be unmounted in vCenter')]
        [ValidateNotNull()]
        [String]
        $DatastoreName
    )
    
    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $ClusterName does not exist."
    }

    $Datastore = Get-Datastore -Name $DatastoreName -ErrorAction Ignore
    if (-not $Datastore) {
        throw "Datastore $DatastoreName does not exist."
    }
    if ("VMFS" -ne $Datastore.Type) {
        throw "Datastore $DatastoreName is of type $($Datastore.Type). This cmdlet can only process VMFS datastores."
    }

    Write-Host "Unmounting datastore $DatastoreName from all hosts and detaching the SCSI device associated with it..."
    $VMHosts = $Cluster | Get-VMHost
    foreach ($VMHost in $VMHosts) {
        $IsDatastoreConnectedToHost = Get-Datastore -VMHost $VMHost | Where-Object {$_.name -eq $DatastoreName}
        if ($null -ne $IsDatastoreConnectedToHost) {
            $VMs = $Datastore | Get-VM
            if ($VMs -and $VMs.Count -gt 0) {
                $vmNames = $VMs | Join-String -SingleQuote -Property {$_.Name}  -Separator ", "
                throw "Cannot unmount datastore $DatastoreName. It is already in use by $vmNames."
            }

            $Datastore = Get-Datastore -Name $DatastoreName
            $VmfsUuid = $Datastore.ExtensionData.info.Vmfs.uuid
            $ScsiLunUuid = ($Datastore | Get-ScsiLun).ExtensionData.uuid | Select-Object -last 1
            $HostStorageSystem = Get-View $VMHost.Extensiondata.ConfigManager.StorageSystem
            
            $HostStorageSystem.UnmountVmfsVolume($VmfsUuid) | Out-Null
            $HostStorageSystem.DetachScsiLun($ScsiLunUuid) | Out-Null
            $VMHost | Get-VMHostStorage -RescanAllHba -RescanVmfs | Out-Null
        }
    }
}

<#
    .DESCRIPTION
     Expand existing VMFS volume to new size.

    .PARAMETER ClusterName
     Cluster name
    
    .PARAMETER DeviceNaaId
     NAA ID of device associated with the existing VMFS volume

    .EXAMPLE
     Resize-VmfsVolume -ClusterName "myClusterName" -DeviceNaaId $DeviceNaaId

    .INPUTS
     vCenter cluster name and device NAA ID.

    .OUTPUTS
     None.
#>
function Resize-VmfsVolume {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Cluster name in vCenter')]
        [ValidateNotNull()]
        [String]
        $ClusterName,

        [Parameter(
            Mandatory=$true,
            HelpMessage = 'NAA ID of device associated with the existing VMFS volume')]
        [ValidateNotNull()]
        [String]
        $DeviceNaaId
    )

    if ($DeviceNaaId -notlike 'naa.624a9370*') {
        throw "Invalid Device NAA ID $DeviceNaaId provided."
    }

    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $ClusterName does not exist."
    }

    $Esxi = $Cluster | Get-VMHost | Where-Object { ($_.ConnectionState -eq 'Connected') } | Select-Object -last 1
    $Cluster | Get-VMHost | Get-VMHostStorage -RescanAllHba | Out-Null
    $Datastores = $Esxi | Get-Datastore -ErrorAction stop
    foreach ($Datastore in $Datastores) {
        $CurrentNaaId = $Datastore.ExtensionData.Info.Vmfs.Extent.DiskName
        if ($CurrentNaaId -eq $DeviceNaaId) {
            $DatastoreToResize = $Datastore
            break
        }
    }
  
    if (-not $DatastoreToResize) {
        throw "Failed to re-size VMFS volume."
    }

    foreach ($DatastoreHost in $DatastoreToResize.ExtensionData.Host.Key) {
      Get-VMHost -id "HostSystem-$($DatastoreHost.value)" | Get-VMHostStorage -RescanAllHba -RescanVmfs -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    }

    $Esxi = Get-View -Id ($DatastoreToResize.ExtensionData.Host | Select-Object -last 1 | Select-Object -ExpandProperty Key)
    $DatastoreSystem = Get-View -Id $Esxi.ConfigManager.DatastoreSystem
    $ExpandOptions = $DatastoreSystem.QueryVmfsDatastoreExpandOptions($DatastoreToResize.ExtensionData.MoRef)

    Write-Host "Increasing the size of the VMFS volume..."
    $DatastoreSystem.ExpandVmfsDatastore($DatastoreToResize.ExtensionData.MoRef, $ExpandOptions[0].spec)
}

<#
    .DESCRIPTION
     Re-signature existing VMFS volume to recover to previous version.

    .PARAMETER ClusterName
     Cluster name
    
    .PARAMETER DeviceNaaId
     NAA ID of device associated with the existing VMFS volume

    .EXAMPLE
     Restore-VmfsVolume -ClusterName "myClusterName" -DeviceNaaId $DeviceNaaId

    .INPUTS
     vCenter cluster name and device NAA ID.

    .OUTPUTS
     None.
#>
function Restore-VmfsVolume {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Cluster name in vCenter')]
        [ValidateNotNull()]
        [String]
        $ClusterName,

        [Parameter(
            Mandatory=$true,
            HelpMessage = 'NAA ID of device associated with the existing VMFS volume')]
        [ValidateNotNull()]
        [String]
        $DeviceNaaId
    )

    if ($DeviceNaaId -notlike 'naa.624a9370*') {
        throw "Invalid Device NAA ID $DeviceNaaId provided."
    }

    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $ClusterName does not exist."
    }

    $Esxi = $Cluster | Get-VMHost | Where-Object { ($_.ConnectionState -eq 'Connected') } | Select-Object -last 1
    $Cluster | Get-VMHost | Get-VMHostStorage -RescanAllHba | Out-Null

    $HostStorageSystem = Get-View -ID $Esxi.ExtensionData.ConfigManager.StorageSystem
    $ResigVolumes = $HostStorageSystem.QueryUnresolvedVmfsVolume()

    foreach ($ResigVolume in $ResigVolumes) {
        foreach ($ResigExtent in $ResigVolume.Extent) {
            if ($ResigExtent.Device.DiskName -eq $DeviceNaaId) {
                if ($ResigVolume.ResolveStatus.Resolvable -eq $false) {
                    if ($ResigVolume.ResolveStatus.MultipleCopies -eq $true) {
                        Write-Error "The volume cannot be re-signatured as more than one non re-signatured copy is present."
                        Write-Error "The following volume(s) need to be removed/re-signatured first:"
                        $ResigVolume.Extent.Device.DiskName | Where-Object {$_ -ne $DeviceNaaId}
                    }

                    throw "Failed to re-signature VMFS volume."
                } else {
                    $VolumeToResignature = $ResigVolume
                    break
                }
            }
        }
    }

    if ($null -eq $VolumeToResignature) {
        Write-Error "No unresolved volume found on the created volume."
        throw "Failed to re-signature VMFS volume."
    }

    Write-Host "Starting re-signature for VMFS volume..."
    $EsxCli = Get-EsxCli -VMHost $Esxi -v2 -ErrorAction stop
    $ResigOp = $EsxCli.storage.vmfs.snapshot.resignature.createargs()
    $ResigOp.volumelabel = $VolumeToResignature.VmfsLabel
    $EsxCli.storage.vmfs.snapshot.resignature.invoke($ResigOp) | Out-Null

    Start-Sleep -s 5

    $Cluster | Get-VMHost | Get-VMHostStorage -RescanAllHba -RescanVMFS | Out-Null
}

<#
    .SYNOPSIS
     Rescans host storage

    .PARAMETER VMHostName
     Name of the VMHost (ESXi server)


    .EXAMPLE
     Sync-VMHostStorage -VMHostName "vmhost1"

    .INPUTS
     VMHostName.

    .OUTPUTS
     None.
#>
function Sync-VMHostStorage {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
                Mandatory=$true,
                HelpMessage = 'VMHost name')]
        [ValidateNotNull()]
        [String]
        $VMHostName
    )

    Get-VMHost $VMHostName | Get-VMHostStorage -RescanAllHba -RescanVMFS | Out-Null
}

<#
    .SYNOPSIS
     This function removes the static iSCSI configurations from a specified Esxi Host

    .PARAMETER VMHostName
     Name of the VMHost (ESXi server)

    .EXAMPLE
     Remove-VMHostStaticiSCSITargets -VMHostName "vmhost1"

    .INPUTS
     VMHostName

    .OUTPUTS
     None
#>
function Remove-VMHostStaticiSCSITargets {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
                Mandatory=$true,
                HelpMessage = 'VMost name')]
        [ValidateNotNull()]
        [String]
        $VMHostName
    )
    Get-VMHost $VMHostName | Get-VMHostHba -Type iScsi | Get-IScsiHbaTarget | Where {$_.Type -eq "Static"} | Remove-IScsiHbaTarget -Confirm:$false
}
