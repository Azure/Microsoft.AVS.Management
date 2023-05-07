<# Private Function Import #>
. $PSScriptRoot\NVMeTCPConstants

<#
    .SYNOPSIS
     This function connects an esxi host to the specified storage cluster node/target.

     1. ESXi host IP address or DNS
     2. ESXi NVMe/TCP Storage adaper name 
     3. Storage Node EndPoint IP address
     4. Storage SystemNQN
     
    .PARAMETER HostAddress
     ESXi host IP Address 

    .PARAMETER HostAdapter
     ESXi host storage adapter name 

    .PARAMETER NodeAddress
     Storage Node EndPoint Address

    .PARAMETER StorageSystemNQN
     Storage system NQN


    .EXAMPLE
     Connect-NVMeTCPTarget HostAddress "192.168.0.1" -HostAdapter "adapter-name" -NodeAddress "192.168.0.1" -StorageSystemNQN "nqn.2016-01.com.lightbitslabs:uuid:46edb489-ba18-4dd4-a157-1d8eb8c32e21"

    .INPUTS
     ESXi Address, Storage Adapter, Storage Node Address, Storage System NQN

    .OUTPUTS
     None.
#>

function Connect-NVMeTCPTarget {
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
        [string]     $StorageSystemNQN

    )
       
    Write-Host "Connecting to targets via Storage Adapter on given ESXi host " $HostAddress;
    Write-Host " " ;

    $HostEsxcli = $null;
 
    try {
        $HostEsxcli = Get-EsxCli -VMHost $HostAddress 
    }
    catch {
        throw " Failed to execute Get-EsxCli cmdlet on host $($HostAddress). Make sure valid ESXi IP/DNS is provided."
    }

    if ($HostEsxcli) { 
        Write-Host "Connected to host via powercli-esxcli"
     
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

    Get-VMHostStorage -VMHost $HostAddress -RescanAllHba

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

    try {<#Do this if a terminating exception happens#>

        $HostEsxcli = Get-EsxCli -VMHost $HostAddress ;
        Write-Host " EsxCli connected to host $($HostAddress)"
        if (!$HostEsxcli) {
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
       
            Get-VMHostStorage -VMHost $HostAddress -RescanAllHba 

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




