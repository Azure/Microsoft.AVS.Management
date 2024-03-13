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
    Specifies the name of the resource pool to retrieve. This parameter is mandatory and accepts a string value.

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
            Mandatory = $true,
            HelpMessage = 'Specify the name of the resource pool')]
        [string]$ResourcePoolName
    )

    $resourcePool = Get-ResourcePool -Name $ResourcePoolName -Server $Server -ErrorAction Stop

    if ($null -eq $resourcePool) {
        throw "Resource pool '$ResourcePoolName' not found on server '$Server'."
    } else {
            return $resourcePool
    }
}

<#
    .SYNOPSIS
    Increases the CPU and memory reservations for a specified resource pool on a server.

    .DESCRIPTION
    The Set-ResourcePoolReservation function increases the CPU and memory reservations of a specified resource pool by a given amount. It retrieves the current resource pool's reservation settings, adds the specified increases, and updates the resource pool with the new values.

    .PARAMETER Server
    Specifies the server on which the resource pool is located. This parameter is mandatory.

    .PARAMETER ResourcePoolName
    Specifies the name of the resource pool whose reservations are to be updated. This parameter is mandatory.

    .PARAMETER MemReservationMBIncrease
    Specifies the amount by which to increase the memory reservation, in megabytes (MB). This parameter is mandatory.

    .PARAMETER CpuReservationMhzIncrease
    Specifies the amount by which to increase the CPU reservation, in megahertz (MHz). This parameter is mandatory.

    .EXAMPLE
    Set-ResourcePoolReservation -Server 'Server1' -ResourcePoolName 'ResourcePoolA' -MemReservationMBIncrease 500 -CpuReservationMhzIncrease 1000
    This command increases the memory reservation of 'ResourcePoolA' on 'Server1' by 500 MB and the CPU reservation by 1000 MHz.
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
            HelpMessage = 'Specify the name of the resource pool')]
        [string]$ResourcePoolName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the increase in memory reservation in MB')]
        [int]$MemReservationMBIncrease,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the increase in CPU reservation in MHz')]
        [int]$CpuReservationMhzIncrease
    )

    $resourcePool = Get-ResourcePoolByName -Server $Server -ResourcePoolName $ResourcePoolName
    $currentMemReservation = $resourcePool.MemReservationMB
    $currentCpuReservation = $resourcePool.CpuReservationMhz

    $newMemReservation = $currentMemReservation + $MemReservationMBIncrease
    $newCpuReservation = $currentCpuReservation + $CpuReservationMhzIncrease

    Write-Host "Resource-Pool-Scale: Current CPU Reservation: $currentCpuReservation MHz, New CPU Reservation: $newCpuReservation MHz; Delta $CpuReservationMhzIncrease MHz"
    Write-Host "Resource-Pool-Scale: Current Memory Reservation: $currentMemReservation MB, New Memory Reservation: $newMemReservation MB; Delta $MemReservationMBIncrease MB"

    Set-ResourcePool -ResourcePool $resourcePool -CpuReservationMhz $newCpuReservation -MemReservationMB $newMemReservation -Server $Server -ErrorAction Stop | out-null

    $updatedResourcePool = Get-ResourcePoolByName -Server $Server -ResourcePoolName $ResourcePoolName
    if ($updatedResourcePool.CpuReservationMhz -ne $newCpuReservation -or
        $updatedResourcePool.MemReservationMB -ne $newMemReservation) {
        throw "Failed to update reservations correctly for '$ResourcePoolName'."
    }
}