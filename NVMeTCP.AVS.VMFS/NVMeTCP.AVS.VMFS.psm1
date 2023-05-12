using module Microsoft.AVS.Management

<#
    .SYNOPSIS
     This function connects an esxi host to the specified storage cluster node/target.

     1. ESXi host IP address or DNS
     2. ESXi NVMe/TCP Storage adaper name 
     3. Storage Node EndPoint IP address
     4. Storage SystemNQN 
     5. NVMe/TCP Admin Queue Size (Optional)
     6. Controller Id (Optional) 
     7. IO Queue Number (Optional)
     8. IO Queue Size (Optional)
     9. Keep Alive Timeout (Optional)
     10. Target Port Number (Optional)
     
     
    .PARAMETER HostAddress
     ESXi host IP Address 

    .PARAMETER HostAdapter
     ESXi host storage adapter name 

    .PARAMETER NodeAddress
     Storage Node EndPoint Address

    .PARAMETER StorageSystemNQN
     Storage system NQN
    
    .PARAMETER  AdminQueueSize
     NVMe/TCP Admin Queue Size, default 32

    .PARAMETER  ControllerId
     NVMe/TCP Controller ID, default 65535 

    .PARAMETER  IoQueueNumber
     IO Queue Number, default 8

    .PARAMETER IoQueueSize
     IO Queue Size, default 256
     
    .PARAMETER KeepAliveTimeout
     Keep Alive Timeout, default 256
     
    .PARAMETER  PortNumber
     Target Port Number, default 4420

    .EXAMPLE
     Connect-NVMeTCPTarget HostAddress "192.168.0.1" -HostAdapter "adapter-name" -NodeAddress "192.168.0.1" -StorageSystemNQN "nqn.2016-01.com.lightbitslabs:uuid:46edb489-ba18-4dd4-a157-1d8eb8c32e21"

    .INPUTS
     ESXi Address, Storage Adapter, Storage Node Address, Storage System NQN

    .OUTPUTS
     None.
#>

function Connect-NVMeTCPTarget {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'ESXi host network address')]
        [string] $HostAddress,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'NVMe/TCP Storage Adapter Name')]
        [string] $HostAdapter,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Target storage Node datapath address')]
        [string]     $NodeAddress,


        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Target storage SystemNQN')]
        [string]     $StorageSystemNQN,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'NVMe/TCP Admin Queue Size')]
        [int]     $AdminQueueSize = 32,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'NVMe/TCP Controller Id')]
        [int]     $ControllerId = 65535,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'NVMe/TCP IO Queue Number')]
        [int]     $IoQueueNumber = 8,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'NVMe/TCP IO Queue Size')]
        [int]     $IoQueueSize = 256,


        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Keep Alive Timeout')]
        [int]     $KeepAliveTimeout = 256,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Port Number')]
        [int]     $PortNumber = 4420



    )
       
    Write-Host "Connecting to targets via Storage Adapter on given ESXi host " $HostAddress;
    Write-Host " " ;

    $HostEsxcli = $null;
 
    try {
        $HostEsxcli = Get-EsxCli -VMHost $HostAddress 
    }
    catch {
        throw "Failed to execute Get-EsxCli cmdlet on host $($HostAddress). Make sure valid ESXi IP/DNS is provided."
    }

    if ($HostEsxcli) { 
        Write-Host "Connected to host via PowerCLI-esxcli"
     
        try {
   
            $EsxCliResult = $HostEsxcli.nvme.fabrics.connect(
                $HostAdapter, $AdminQueueSize, $ControllerId, 
                $null, $IoQueueNumber, $IoQueueSize, $NodeAddress,
                $KeepAliveTimeout, $PortNumber, $StorageSystemNQN, $null, $null 
            );
       
            if ($EsxCliResult) {
                Write-Host "ESXi host is connected to storage controller " $hostAddress 
            }
            else {
                throw
            }
        }
        catch {
            throw "Failed to connect ESXi NVMe/TCP storage adapter to storage controller  $($item) " 
        }  
        Write-Host "Connecting Controller status: "$EsxCliResult;
    }

    Write-Host "Rescanning NVMe/TCP storage adapter.."

    $RescanResult = Get-VMHostStorage -VMHost $HostAddress -RescanAllHba 
    
    Write-Host "Rescanning Completed."

} 
    


<#
    .SYNOPSIS
     This function disconnects an esxi host from the specified storage cluster node/target.

     1. ESXi host IP address or DNS
     2. ESXi NVMe/TCP Storage adaper name 
     3. Storage SystemNQN

    .PARAMETER HostAddress
     ESXi host IP Address 

    .PARAMETER HostAdapter
     ESXi host storage adapter name

    .PARAMETER StorageSystemNQN
     Storage system NQN

    .EXAMPLE
     Disconnect-NVMeTCPTarget -HostAddress "192.168.0.1" -HostAdapter "adapter-name"  -StorageSystemNQN "nqn.2016-01.com.lightbitslabs:uuid:46edb489-ba18-4dd4-a157-1d8eb8c32e21"

    .INPUTS
     ESXi Address, Storage Adapter, Storage systemNQN

    .OUTPUTS
     None.
#>

function Disconnect-NVMeTCPTarget {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
   
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'ESXi host network address')]
        [string] $HostAddress,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'NVMe/TCP Storage Adapter Name')]
        [string] $HostAdapter,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Target storage SystemNQN')]
        [string]     $StorageSystemNQN




    )

    Write-Host "Disconnecting controllers from targets on given ESXi host " $HostAddress;
    Write-Host " " ;
    
    $hostEsxcli = $null;

    try {
        <#Do this if a terminating exception happens#>

        $HostEsxcli = Get-EsxCli -VMHost $HostAddress ;
        Write-Host "EsxCli connected to host $($HostAddress)"
        if ($null -eq $HostEsxcli) {
            throw;
        }
    }
    catch {
        throw "Failed to execute Get-EsxCli cmdlet on host $($HostAddress). Make sure valid ESXi IP/DNS is provided."
    }

    try {

        $Controllers = $HostEsxcli.nvme.controller.list();

        if ($Controllers -and $Controllers.Count -ge 0) {

            foreach ($item in $Controllers) {
                $result = $HostEsxcli.nvme.fabrics.disconnect($item.Adapter, $item.ControllerNumber, $StorageSystemNQN);
                Write-Host "Diconnecting Controller status: "$result;
            }
       
            Write-Host "Rescanning NVMe/TCP storage adapter.."
            $RescanResult = Get-VMHostStorage -VMHost $HostAddress -RescanAllHba 
            
            Write-Host "Rescanning Completed."

        }
       
        else {
            Write-Host "No NVMe/TCP controller found on given host " $HostAddress    
        } 
    }
    catch {
        throw "Failed to execute Get-EsxCli cmdlet on host $($HostAddress). Make sure valid ESXi IP/DNS is provided."
    } 
    Write-Host ""
}


<#
    .SYNOPSIS
     This function creates VMFS datastore on given ESXi host using NVMe/TCP transport.

     1. vCenter IP address or DNS
     2. ESXi IP address or DNS
     3. New Datastore Name
     4. Device Path on ESXi host
     
    .PARAMETER vCenterAddress
     vCenter IP Address 

    .PARAMETER HostAddress
     ESXi host IP Address 

    .PARAMETER DatastoreName
     New Datastore Name

    .PARAMETER DevicePath
     Device Path on ESXi host

    .EXAMPLE
     Create-NVMeDatastore -vCenterAddress "192.168.0.1" -HostAddress "192.168.0.10"  -DatastoreName "data-name01" -DevicePath "eui.58204375a0b5408285a89390e1510fec"

    .INPUTS
     vCenter address, ESXi host address, New datastore name, available NVMe device path 

    .OUTPUTS
     None.
#>

function New-NVMeDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
   
    Param
    (
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'vCenter network address')]
        [string] $vCenterAddress,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'ESXi host network address')]
        [string] $HostAddress,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'New datastore name')]
        [string] $DatastoreName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'NVMe device path')]
        [string]     $DevicePath

    )

    Write-Host "Creating new datastore $($DatastoreName) on vCenter Server "  $vCenterAddress 
     
    $AvailableDatastore = $null
     
    try {
        Write-Host "Checking if datastore already exist.."
        $AvailableDatastore = Get-Datastore -Name $DatastoreName  -ErrorAction ignore
        if ($AvailableDatastore) {
            Write-Host "Datastore with given name alreay exist, use different name for new datastore"
            Exit 

        } 

    }
    catch {
        Write-Host "Get-Datastore didn't find datastore by name $($DatastoreName)."
    }

    try {
        
        Write-Host "Creating datastore now.. "
        $result = New-Datastore -Vmfs -FileSystemVersion 6 -VMHost $HostAddress -Name $DatastoreName -Path $DevicePath
        Write-Host $result
          
        Write-Host "Rescanning NVMe/TCP storage adapter.."

        $RescanResult = Get-VMHostStorage -VMHost $HostAddress -RescanAllHba 
    
        Write-Host "Rescanning Completed."

        $AvailableDatastore = Get-Datastore -Name $DatastoreName  -ErrorAction ignore

        if ($AvailableDatastore) {
            Write-Host "New datastore created successfully"
        }

    }
    catch {
        throw "Failed to create  new datastore on host $($HostAddress)."
    }
  
    Write-Host " " ;
     
}

<#
    .SYNOPSIS
     This function removes VMFS datastore on a given ESXi host using NVMe/TCP transport.

     1. ESXi IP address or DNS
     2. Datastore Name
     
    .PARAMETER HostAddress
     ESXi host IP Address 

    .PARAMETER DatastoreName
     Datastore Name

    
    .EXAMPLE
     Remove-NVMeDatastore -HostAddress "192.168.0.10"  -DatastoreName "data-name01" 

    .INPUTS
     ESXi host address, Datastore name 

    .OUTPUTS
     None.
#>

function Remove-NVMeDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
   
    Param
    (
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'ESXi host network address')]
        [string] $HostAddress,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'New datastore name')]
        [string] $DatastoreName
    )
       
    Write-Host "Removing datastore $($DatastoreName) on ESXi host"  $HostAddress
     
    $AvailableDatastore = $null
     
    try {
        Write-Host "Checking if datastore already exist.."
        $AvailableDatastore = Get-Datastore -Name $DatastoreName -ErrorAction ignore
        if ($AvailableDatastore) {
            Write-Host "Removing the Datastore.. "
            try {
                Remove-Datastore -VMHost $HostAddress $DatastoreName -Confirm:$false    
                Write-Host "Datastores removed. "
                Write-Host "Rescanning datastore "
                $RescanResult = Get-VMHostStorage -VMHost $HostAddress -RescanAllHba 
            }
            catch {
                Write-Host "Failed to delete datasore $($DatastoreName)."
            }
               
        } 
        else {
            Write-Host "Didn't find datasore $($DatastoreName) to delete."
        } 

    }
    catch {
        Write-Host "Get-Datastore didn't find datastore $($DatastoreName)."
    }
    Write-Host " " ;
     
}


<#
    .SYNOPSIS
     This function mount VMFS datastore to already attached ESXi host(s) using NVMe/TCP transport.

     1. vCenter Address IP/FQDN
     2. Datastore Name

    .PARAMETER DatastoreName
     Datastore Name

    
    .EXAMPLE
     Mount-NVMeDatastore -DatastoreName "datastore-name" 

    .INPUTS
     Datastore name 

    .OUTPUTS
     None.
#>

Function Mount-NVMeDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
   
    Param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'vCenter Address')]
        [string] $vCenterAddress,
    
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Datastore name')]
        [string] $DatastoreName
    )

    Process {

        if ($null -eq $DatastoreName) {
            Write-Host "No Datastore name provided"
            Exit
        }

        if ($null -eq $vCenterAddress) {
            Write-Host "No vCenter Address provided"
            Exit
        }
        

        $Datastore = $null 
        try {
            $Datastore = Get-Datastore -Server $vCenterAddress -Name $DatastoreName -ErrorAction ignore
        }
        catch {
            throw " Failed to execute Get-Datastore by name  $($DatastoreName)."
        }
		
        if ( $null -eq $Datastore) {
            throw " No datastore found by the given name $($DatastoreName) to mount "
        } 
        

        if ($Datastore) {
            Write-Host "Datastore found and mounting on all associated ESXi host(s)."
            $hostviewDSDiskName = $Datastore.ExtensionData.Info.vmfs.extent[0].Diskname
            

            if ($Datastore.ExtensionData.Host) {
                $attachedHosts = $Datastore.ExtensionData.Host
                Foreach ($VMHost in $attachedHosts) {
                    if (!($VMHost.MountInfo.Accessible)) {
                        $hostview = Get-View $VMHost.Key
                        $StorageSys = Get-View $HostView.ConfigManager.StorageSystem
                        Write-Host "Mounting VMFS Datastore $($Datastore.Name) on host $($hostview.Name)..."
                        $StorageSys.MountVmfsVolume($Datastore.ExtensionData.Info.vmfs.uuid);
                        Write-Host "Datastore $($Datastore.Name) mounted successfully on host $($hostview.Name)."
                    }
                    else {
                        Write-Host "No action needed, datastore is accessible to host " $VMHost.Key
                    } 

                }
            }
        }

        Write-Host " "
     
    }
}



<#
    .SYNOPSIS
     This function unmount VMFS datastore from ESXi host(s) using NVMe/TCP transport.

     1. Datastore Name
     
    .PARAMETER DatastoreName
     Datastore Name
    
    .EXAMPLE
     Unmount-NVMeDatastore -DatastoreName "datastore-name" 

    .INPUTS
     Datastore name 

    .OUTPUTS
     None.
#>

Function Dismount-NVMeDatastore {
    #[CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
      
    Param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'vCenter Address')]
        [string] $vCenterAddress,
    
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Datastore name')]
        [string] $DatastoreName
        
    )

    Process {

        
        if ($null -eq $vCenterAddress) {
            Write-Host "No vCenter Address provided"
            Exit
        }
                
        if (-not $DatastoreName) {
            Write-Host "No Datastore name provided"
            Exit
        }
     
        $Datastore = $null 
        try {
            $Datastore = Get-Datastore -Server $vCenterAddress -Name $DatastoreName -ErrorAction ignore
        }
        catch {
            throw " No datastore found by the given name $($DatastoreName)."
        }
		
        if ($Datastore) {
            Write-Host "Datastore found and unmounting from ESXi host(s)."
            $hostviewDSDiskName = $Datastore.ExtensionData.Info.vmfs.extent[0].Diskname
            
            if ($Datastore.ExtensionData.Host) {
                $attachedHosts = $Datastore.ExtensionData.Host
                Foreach ($VMHost in $attachedHosts) {
                    if ($VMHost.MountInfo.Accessible) {
                        $hostview = Get-View $VMHost.Key
                        $StorageSys = Get-View $HostView.ConfigManager.StorageSystem
                        Write-Host "Unmounting VMFS Datastore $($Datastore.Name) from host $($hostview.Name).."
                        $StorageSys.UnmountVmfsVolume($Datastore.ExtensionData.Info.vmfs.uuid);
                        Write-Host "Datastore $($Datastore.Name) unmounted successfully from host $($hostview.Name) ."
                    }
                    else {
                        Write-Host "No action needed, datastore is not accessible to host " $VMHost.Key
                    } 

                }
            }
        }

        Write-Host " "

    }

  
}



