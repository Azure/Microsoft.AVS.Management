using module Microsoft.AVS.Management
<#
    .SYNOPSIS
     This function mounts the NFS datastore on all hosts in the cluster.

    .PARAMETER ClusterName
     Cluster name

    .PARAMETER DatastoreName
     Name of the NFS Datastore to be mounted on hosts in the cluster.
    
    .PARAMETER NfsSharePath
     Path to NFS share.
    
    .PARAMETER NfsHost
     IP of NFS server.

    .EXAMPLE
     New-NFSDatastore -ClusterName Cluster1 -DatastoreName testfileshare -NfsHost 172.24.1.8 -NfsSharePath /ankstorageacct/testfileshare/

    .INPUTS
     vCenter cluster name, Name of the NFS datastore, Path to the NFS share, IP of the NFS server.

    .OUTPUTS
     None.
#>
function New-NFSDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false, AutomationOnly = $true)]
    Param (
         [ Parameter(
            Mandatory=$true,
            HelpMessage = 'vSphere Cluster name in vCenter')]
            [ValidateNotNull()]
            [String]
            $ClusterName,
            [Parameter(
                Mandatory=$true,
                HelpMessage = 'Name of NFS datastore to be mounted on host(s) in vCenter')]
            [ValidateNotNull()]
            [String]
            $DatastoreName,
            [Parameter(
                Mandatory=$true,
                HelpMessage = 'Path to NFS share')]
            [ValidateNotNull()] 
            [String]
            $NfsSharePath,
            [Parameter(
                Mandatory=$true,
                HelpMessage = 'IP of NFS server')]
            [ValidateNotNull()]
            [String]
            $NfsHost
        )

    # Setting the default NFS version to 3. When required, we can extend to support 4.1 version as well. 
    $DefaultNfsVersion = "3"
    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $($ClusterName) does not exist."
    }
        
    $Datastore = Get-Datastore -Name $DatastoreName -ErrorAction Ignore
    if ($Datastore) {
        throw "Unable to create a datastore. Datastore '$($DatastoreName)' already exists."
    }

    $VmHosts = $Cluster | Get-VMHost

    $HostCount = $VmHosts.Count
    $HostUnmountedCount = $HostCount

    foreach ($VmHost in $VmHosts){
          
      try {
          New-Datastore -Name $DatastoreName -Nfs -FileSystemVersion $DefaultNfsVersion -VMHost $VmHost -NfsHost $NfsHost -Path $NfsSharePath -ErrorAction Stop
      }
      catch {
           Write-Error "Failed to NFS Datastore $($DatastoreName) on host  $($VmHost.Name). Error: $($_.Exception.Message)"
           $HostUnmountedCount--
           continue
      }
    }

    Write-Host "Datastore $($DatastoreName)  mounted successfully on $HostUnmountedCount/$HostCount hosts in cluster $($ClusterName)."
}

<#
    .SYNOPSIS
     This function unmounts the NFS datastore on all hosts in the cluster.

    .PARAMETER ClusterName
     Cluster name

    .PARAMETER DatastoreName
     Name of the NFS Datastore to be mounted on hosts in the cluster.

    .EXAMPLE
      Remove-NFSDatastore -ClusterName Cluster1 -DatastoreName testfileshare

    .INPUTS
     vCenter cluster name, Name of the NFS datastore.

    .OUTPUTS
     None.
#>
function Remove-NFSDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false, AutomationOnly = $true)]
    Param (
         [ Parameter(
            Mandatory=$true,
            HelpMessage = 'vSphere Cluster name in vCenter')]
            [ValidateNotNull()]
            [String]
            $ClusterName,
            [Parameter(
                Mandatory=$true,
                HelpMessage = 'Name of NFS datastore to be unmounted on host(s) in vCenter')]
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
    if ($datastore.type -notlike "*NFS*") {
        throw "Datastore $DatastoreName is of type $($Datastore.Type). This cmdlet can only process NFS datastores."
    }
    if ((Get-Datastore -Name $name | Get-VM).Count > 0) {
        throw "Virtual machines found on Datastore $DatastoreName. Please remove all virtual machines from the datastore before removing the datastore."
    }

    $VmHosts = $Cluster | Get-VMHost
    
    $HostCount = $VmHosts.Count
    $HostUnmountedCount = $HostCount

    foreach ($VmHost in $VmHosts){
          
      try {
          Remove-Datastore -Datastore $DatastoreName -VMHost $VMHost -Confirm:$false -ErrorAction Stop
      }
      catch {
           Write-Error "Failed to remove NFS Datastore $($DatastoreName) on host $($VmHost.Name). Error: $($_.Exception.Message)"
           $HostUnmountedCount--
           continue
      }
    }

    Write-Host "Datastore $($DatastoreName) unmounted successfully on $HostUnmountedCount/$HostCount hosts in cluster $($ClusterName)."
}

