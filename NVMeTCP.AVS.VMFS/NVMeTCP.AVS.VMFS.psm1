<#
    .SYNOPSIS
     This function connects an ESXi host to the specified storage cluster node/target.

     1. ESXi host IP address or DNS
     2. Storage Node EndPoint IP address.
     
    .PARAMETER HostAddress
     ESXi host IP Address 

    .PARAMETER NodeAddress
     Node EndPoint Address


    .EXAMPLE
     Connect-NVMeTCPTarget -HostAddress "192.168.0.1" -NodeAddress "10.10.22.10"

    .INPUTS
     ESXi IP Address, NVMeTCP Cluster Node Address. 

    .OUTPUTS
     None.
#>
function Connect-NVMeTCPTarget {
    
    Write-Host "Connect-NVMeTCPTarget - Not fully Implemented ."

}


<#
    .SYNOPSIS
     This function disconnects an ESXi host from the specified storage cluster node/target.

    2. ESXi host IP address or DNS
    1. Storage SystemNQN.
     
    .PARAMETER HostAddress
     ESXi host IP Address 

    .PARAMETER SystemNQN
     Storage System NQN


    .EXAMPLE
     Disconnect-NVMeTCPTarget -HostAddress "192.168.0.1" -SystemNQN "nqn.2016-01.com.lightbitslabs:uuid:46edb489-ba18-4dd4-a157-1d8eb8c32e21" 

    .INPUTS
     ESXi IP Address, NVMeTCP Cluster SystemNQN

    .OUTPUTS
     None.
#>
function Disconnect-NVMeTCPTarget {
 
    Write-Host "Disconnect function - Not fully Implemented."
}


