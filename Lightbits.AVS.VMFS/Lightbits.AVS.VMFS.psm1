#using module Lightbits.AVS.Core

<#
    .SYNOPSIS
     This function connects an esxi host to the specified storage cluster node/target.

     1. Storage Node EndPoint IP address.
     2. ESXi host IP address or DNS
     
    .PARAMETER NodeAddress
     Node Address

    .PARAMETER hostAddress
     ESXi host IP Address 

    .EXAMPLE
     Connect-LightbitsTarget -NodeAddress "10.10.22.10" -hostAddress "192.168.0.1"

    .INPUTS
     Lightbits Cluster Node Address, ESXi IP Address.

    .OUTPUTS
     None.
#>
function Connect-LightbitsTarget {
    
    
    Write-Host "Connect-LightbitsTarget - Not fully Implemented ."

}

<#
    .SYNOPSIS
     This function disconnects an esxi host from the specified storage cluster node/target.

     1. Storage SystemNQN.
     2. ESXi host IP address or DNS
     
    .PARAMETER SystemNQN
     Storage System NQN

    .PARAMETER hostAddress
     ESXi host IP Address 

    .EXAMPLE
     Connect-LightbitsTarget -SystemNQN "nqn.2016-01.com.lightbitslabs:uuid:46edb489-ba18-4dd4-a157-1d8eb8c32e21" -hostAddress "192.168.0.1"

    .INPUTS
     Lightbits Cluster SystemNQN, ESXi IP Address.

    .OUTPUTS
     None.
#>
function Disconnect-LightbitsTarget {
 
    Write-Host "Disconnect function - Not fully Implemented."
}


