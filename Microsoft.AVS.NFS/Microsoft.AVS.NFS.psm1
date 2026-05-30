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

<#
    .SYNOPSIS
     Gets NFS NConnect value for a specific datastore across all hosts in a cluster.

    .DESCRIPTION
     Retrieves the NConnect (number of TCP connections) configuration for the specified NFS datastore 
     mounted on each host in the cluster.

    .PARAMETER ClusterName
     Name of the vSphere cluster to query for NFS NConnect information.
    
    .PARAMETER DatastoreName
     Name of the NFS datastore to retrieve NConnect value for.

    .EXAMPLE
     Get-NFSDatastoreNConnectValue -ClusterName "Cluster1" -DatastoreName "nfs-datastore-01"

    .INPUTS
     vCenter cluster name, NFS datastore name.

    .OUTPUTS
     NamedOutputs hashtable containing NConnect details per host.
#>
function Get-NFSDatastoreNConnectValue {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'vSphere Cluster name in vCenter')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ClusterName,
        
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of NFS datastore to get NConnect value for')]
        [ValidateNotNullOrEmpty()]
        [String]
        $DatastoreName
    )

    $ClusterName = Limit-WildcardsandCodeInjectionCharacters -String $ClusterName
    $DatastoreName = Limit-WildcardsandCodeInjectionCharacters -String $DatastoreName

    Write-Host "Collecting NConnect value for NFS datastore '$DatastoreName' across hosts in cluster '$ClusterName'"
    Write-Host ""

    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster '$ClusterName' does not exist."
    }

    $Datastore = $Cluster | Get-Datastore -Name $DatastoreName -ErrorAction Ignore
    if (-not $Datastore) {
        throw "Datastore '$DatastoreName' not found on cluster '$ClusterName'."
    }
    
    # NFS datastores have Type 'NFS' (v3) or 'NFS41' (v4.1)
    if ($Datastore.Type -notin @('NFS', 'NFS41')) {
        throw "Datastore '$DatastoreName' is of type '$($Datastore.Type)'. This cmdlet only supports NFS datastores (NFS or NFS41)."
    }
    
    # Get only connected hosts (filter out disconnected/maintenance mode hosts)
    $AllVMHosts = $Cluster | Get-VMHost -ErrorAction Ignore
    if (-not $AllVMHosts) {
        throw "No hosts found in cluster '$ClusterName'."
    }
    
    $VMHosts = $AllVMHosts | Where-Object { $_.ConnectionState -eq 'Connected' }
    if (-not $VMHosts) {
        throw "No connected hosts found in cluster '$ClusterName'. All hosts are disconnected or in maintenance mode."
    }
    
    $DisconnectedHosts = $AllVMHosts | Where-Object { $_.ConnectionState -ne 'Connected' }
    if ($DisconnectedHosts) {
        Write-Warning "Skipped $($DisconnectedHosts.Count) host(s) due to disconnected or maintenance state: $($DisconnectedHosts.Name -join ', ')"
    }

    $NamedOutputs = @{}
    $HostsNotMounted = @()
    $HostsFailed = @()

    foreach ($VMHost in $VMHosts) {
        try {
            $EsxCli = Get-EsxCli -VMHost $VMHost -V2 -ErrorAction Stop
            $NfsDatastores = $EsxCli.storage.nfs.list.invoke()
            
            if (-not $NfsDatastores) {
                $HostsNotMounted += $VMHost.Name
                continue
            }

            $NfsDs = $NfsDatastores | Where-Object { $_.VolumeName -eq $DatastoreName }
            if (-not $NfsDs) {
                $HostsNotMounted += $VMHost.Name
                continue
            }

            $IsNfsV41 = $NfsDs.NFSv41 -eq $true
            $NConnectValue = if ($null -ne $NfsDs.Connections) { $NfsDs.Connections } else { "N/A" }
            
            $NamedOutputs[$VMHost.Name] = "
            {
                DatastoreName : $($NfsDs.VolumeName),
                NfsServerHost : $($NfsDs.Host),
                SharePath : $($NfsDs.Share),
                NfsVersion : $(if ($IsNfsV41) { '4.1' } else { '3' }),
                NConnectValue : $NConnectValue,
                Accessible : $($NfsDs.Accessible),
                Mounted : $($NfsDs.Mounted)
            }"
        }
        catch {
            $HostsFailed += $VMHost.Name
            Write-Error "Failed to query host '$($VMHost.Name)': $($_.Exception.Message)"
            continue
        }
    }

    if ($HostsNotMounted.Count -gt 0) {
        Write-Warning "Datastore '$DatastoreName' not mounted on $($HostsNotMounted.Count) host(s): $($HostsNotMounted -join ', ')"
    }
    
    if ($HostsFailed.Count -gt 0) {
        Write-Warning "Failed to query $($HostsFailed.Count) host(s): $($HostsFailed -join ', ')"
    }

    if ($NamedOutputs.Count -eq 0) {
        throw "Failed to query all hosts in cluster '$ClusterName'. Check hosts connectivity."
    }

    Write-Host ($NamedOutputs | ConvertTo-Json -Depth 10)

    Set-Variable -Name NamedOutputs -Value $NamedOutputs -Scope Global
    Write-Host " "
}

