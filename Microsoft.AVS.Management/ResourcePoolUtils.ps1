<#PSScriptInfo
    .VERSION 1.0

    .GUID e1b10288-581e-4b3d-b315-f0bb54572d93

    .AUTHOR Frantz Prinvil

    .COMPANYNAME Microsoft

    .COPYRIGHT (c) Microsoft. All rights reserved

    .DESCRIPTION This script file contains utility functions for managing VMware vSphere resource pools through PowerShell commands
#>

<#
    .SYNOPSIS
    Retrieves a specified resource pool by name from a given server.

    .DESCRIPTION
    The Get-ResourcePoolByName function connects to a specified server and retrieves the resource pool with the provided name. If the resource pool is not found, it throws an error.

    .PARAMETER Server
    Specifies the server from which to retrieve the resource pool. This parameter is mandatory.

    .PARAMETER ResourcePoolName
    Specifies the name of the resource pool to retrieve. This parameter  accepts a string value.

    .EXAMPLE
    Get-ResourcePoolByName -Server "ServerName" -ResourcePoolName "MyResourcePool"
    This example retrieves a resource pool named "MyResourcePool" from the server "ServerName".
#>
function Get-ResourcePoolByName {
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the server to use')]
        [ValidateNotNullOrEmpty()]
        $Server,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Specify the name of the resource pool')]
        [string]$ResourcePoolName = 'MGMT-ResourcePool'
    )

    $ResourcePool = Get-ResourcePool -Name $ResourcePoolName -Server $Server -ErrorAction Stop

    if ($null -eq $ResourcePool) {
        throw "Resource pool '$ResourcePoolName' not found on server '$Server'."
    } else {
            return $ResourcePool
    }
}

<#
    .SYNOPSIS
    Increases the CPU and memory reservations for a specified resource pool on a server.

    .DESCRIPTION
    The Set-ResourcePoolReservation function increases the CPU and memory reservations of a specified resource pool by a given amount. It retrieves the current resource pool's reservation settings, adds the specified increases, and updates the resource pool with the new values.

    .PARAMETER Server
    Specifies the server on which the resource pool is located. This parameter is mandatory.

    .PARAMETER ResourcePool
    Specifies the resource pool whose reservations are to be updated. This parameter is mandatory.

    .PARAMETER MemReservationGB
    Specifies the amount by which to increase the memory reservation, in gigabytes (GB). This parameter is mandatory.

    .PARAMETER CpuReservationMhz
    Specifies the amount by which to increase the CPU reservation, in megahertz (MHz). This parameter is mandatory.

    .EXAMPLE
    Set-ResourcePoolReservation -Server 'Server1' -ResourcePool 'ResourcePoolA' MemReservationGB 5 CpuReservationMhz 10
    This command increases the memory reservation of 'ResourcePoolA' on 'Server1' by 5 GB and the CPU reservation by 10 MHz.
#>
function Set-ResourcePoolReservation {
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the server to use')]
        [ValidateNotNullOrEmpty()]
        $Server,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the resource pool')]
        $ResourcePool,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the memory reservation in GB')]
        [int]$MemReservationGB,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the CPU reservation in MHz')]
        [int]$CpuReservationMhz
    )

    $ResourcePoolVms = $ResourcePool | Get-VM
    [int]$NewMemReservation = ($ResourcePoolVms.MemoryGb | Measure-Object -Sum).Sum + $MemReservationGB
    [int]$NewCpuReservation = ($ResourcePoolVms.NumCpu | Measure-Object -Sum).Sum + $CpuReservationMhz
    $CpuReservationMhzTotal = $NewCpuReservation * 1000
    $CpuSharesTotal = $NewCpuReservation * 2000

    Write-Host "ResourcePool-Scale: Current CPU Reservation: $($ResourcePool.CpuReservationMhz) MHz, New CPU Reservation: $CpuReservationMhzTotal MHz; Delta $($CpuReservationMhzTotal - $ResourcePool.CpuReservationMhz) MHz"
    Write-Host "ResourcePool-Scale: Current CPU Shares: $($ResourcePool.NumCpuShares), New CPU Shared: $CpuSharesTotal; Delta Shares $($CpuSharesTotal - $ResourcePool.NumCpuShares)"
    Write-Host "ResourcePool-Scale: Current Memory Reservation: $($ResourcePool.MemReservationGB) GB, New Memory Reservation: $NewMemReservation GB; Delta $($NewMemReservation - $ResourcePool.MemReservationGB) GB"

    Set-ResourcePool -ResourcePool $ResourcePool -CpuReservationMhz $CpuReservationMhzTotal -CpuSharesLevel:Custom -NumCpuShares $CpuSharesTotal -MemReservationGB $NewMemReservation -MemSharesLevel:High -Server $Server -ErrorAction Stop | out-null

    $UpdatedResourcePool = Get-ResourcePoolByName -Server $Server
    if ($UpdatedResourcePool.CpuReservationMhz -ne $CpuReservationMhzTotal -or
        $UpdatedResourcePool.MemReservationGB -ne $NewMemReservation) {
        throw "Failed to update reservations correctly for $($UpdatedResourcePool.Name)"
    }
}