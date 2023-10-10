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
    [AVSAttribute(10, UpdatesSDDC = $false)]
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
          New-Datastore -Name $DatastoreName -Nfs -FileSystemVersion '4.1' -VMHost $VmHost -NfsHost $NfsHost -Path $NfsSharePath -ErrorAction Stop
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
    [AVSAttribute(10, UpdatesSDDC = $false)]
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
    if ("NFS41" -ne $Datastore.Type) {
        throw "Datastore $DatastoreName is of type $($Datastore.Type). This cmdlet can only process NFS datastores."
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

