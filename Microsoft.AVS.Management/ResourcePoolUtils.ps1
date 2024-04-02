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
    Specifies the name of the resource pool to retrieve. This parameter accepts a string value.

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

    if ($null -eq $ResourcePool) { throw "Resource pool '$ResourcePoolName' not found on server '$Server'." }

    return $ResourcePool
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

    .PARAMETER MemoryReservation
    Specifies the amount by which to increase the memory reservation, in gigabytes (GB). This parameter is mandatory.

    .PARAMETER CpuReservation
    Specifies the amount by which to increase the CPU reservation, in megahertz (MHz). This parameter is mandatory.

    .PARAMETER SharesReservation
    Specifies the amount by which to increase the CPU shares reservation. This parameter is mandatory.

    .EXAMPLE
    Set-ResourcePoolReservation -Server 'Server1' -ResourcePool 'ResourcePoolA' -MemoryReservation 5 -CpuReservation 10 -SharesReservation 0
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
        [int]$MemoryReservation,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the CPU reservation in Mhz')]
        [int]$CpuReservation,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the CPU shares reservation')]
        [int]$SharesReservation
    )

    $Defaults = Get-DefaultResourcePoolConfig

    $NewMemReservation = $ResourcePool.MemReservationGB + $MemoryReservation
    $NewCpuReservation = $ResourcePool.CpuReservationMHz + $CpuReservation
    $NewSharesReservation = $ResourcePool.NumCpuShares + $SharesReservation

    $NewMemReservation = AdjustReservationValue $NewMemReservation $MemoryReservation $Defaults.MemReservationGB 'Mem' $Defaults
    $NewCpuReservation = AdjustReservationValue $NewCpuReservation $CpuReservation $Defaults.CpuReservationMhz 'Cpu' $Defaults
    $NewSharesReservation = AdjustReservationValue $NewSharesReservation $SharesReservation $Defaults.NumCpuShares 'Shares' $Defaults

    Write-Host "ResourcePool-Scale: Current Memory Reservation: $($ResourcePool.MemReservationGB) GB, New Memory Reservation: $NewMemReservation GB; Delta $($NewMemReservation - $ResourcePool.MemReservationGB) GB; Default Value Used: $($Defaults.DefaultsUsed.Mem)"
    Write-Host "ResourcePool-Scale: Current CPU Reservation: $($ResourcePool.CpuReservationMhz) MHz, New CPU Reservation: $NewCpuReservation MHz; Delta $($NewCpuReservation - $ResourcePool.CpuReservationMhz) MHz; Default Value Used: $($Defaults.DefaultsUsed.Cpu)"
    Write-Host "ResourcePool-Scale: Current CPU Shares: $($ResourcePool.NumCpuShares), New CPU Shares: $NewSharesReservation; Delta $($NewSharesReservation - $ResourcePool.NumCpuShares); Default Value Used: $($Defaults.DefaultsUsed.Shares)"

    Set-ResourcePool -ResourcePool $ResourcePool -CpuReservationMhz $NewCpuReservation -CpuSharesLevel $Defaults.CpuSharesLevel -NumCpuShares $NewSharesReservation -MemReservationGB $NewMemReservation -MemSharesLevel $Defaults.MemSharesLevel -Server $Server -ErrorAction Stop | Out-Null

    $UpdatedResourcePool = Get-ResourcePoolByName -Server $Server
    if ($UpdatedResourcePool.CpuReservationMhz -ne $NewCpuReservation -or
        $UpdatedResourcePool.MemReservationGB -ne $NewMemReservation -or
        $UpdatedResourcePool.NumCpuShares -ne $NewSharesReservation) {
        throw "Failed to update reservations correctly for $($UpdatedResourcePool.Name)"
    }
}

<#
    .SYNOPSIS
    Retrieves the default configuration settings for a resource pool.

    .DESCRIPTION
    The Get-DefaultResourcePoolConfig function returns a hashtable containing default configuration settings for resource pools.

    .PARAMETER None
    This function does not take any parameters.

    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable with the default configuration settings for resource pools, including:
    - CpuReservationMhz: The default CPU reservation in MHz.
    - CpuSharesLevel: The default CPU shares level (custom).
    - NumCpuShares: The default CPU allocation shares.
    - MemReservationGB: The default memory reservation in GB.
    - MemSharesLevel: The default memory shares level (high).

    .EXAMPLE
    $defaultConfig = Get-DefaultResourcePoolConfig
    This example retrieves the default resource pool configuration settings and stores them in the `$defaultConfig` variable.
#>
function Get-DefaultResourcePoolConfig {
    $ResourcePoolDefaults = @{
        CpuReservationMhz = 46000
        CpuSharesLevel = 'Custom'
        NumCpuShares = 92000
        MemReservationGB = 176
        MemSharesLevel = 'High'
        DefaultsUsed = @{
            Cpu = $false
            Shares = $false
            Mem = $false
        }
    }

    return $ResourcePoolDefaults
}

<#
    .SYNOPSIS
    Adjusts a reservation value based on given parameters and default settings.

    .DESCRIPTION
    The AdjustReservationValue function updates a current reservation value by adding a specified amount to it if the current value is less than a default value. It also updates a hashtable to indicate that defaults were used for a particular type of reservation.

    .PARAMETER CurrentValue
    The current reservation value as an integer.

    .PARAMETER ReservationToAdd
    The amount to add to the current reservation value, as an integer.

    .PARAMETER DefaultValue
    The default reservation value. If the current value is less than this value, the function will adjust the current value based on the reservation to add.

    .PARAMETER Type
    The type of reservation being adjusted. This string parameter is used to update the hashtable indicating that defaults were applied.

    .PARAMETER Defaults
    A hashtable that tracks whether default values have been used for different types of reservations. The function updates this hashtable based on the operation performed.

    .OUTPUTS
    Int
    Returns the adjusted current value after applying the reservation addition. If the current value was less than the default value, the return value reflects the sum of the default value and the reservation to add; otherwise, the original current value is returned unchanged.

    .EXAMPLE
    $defaults = @{DefaultsUsed = @{}}
    $adjustedValue = AdjustReservationValue -CurrentValue 50 -ReservationToAdd 20 -DefaultValue 100 -Type "CPU" -Defaults $defaults
    This example adjusts the reservation value for a CPU type. Since the current value (50) is less than the default value (100), the function will return 120 (100 + 20), and the hashtable will indicate that defaults were used for the CPU type.

#>
function AdjustReservationValue {
    param (
        [int]$CurrentValue,
        [int]$ReservationToAdd,
        [int]$DefaultValue,
        [string]$Type,
        [hashtable]$Defaults
    )

    if ($CurrentValue -lt $DefaultValue) {
        $CurrentValue = $DefaultValue + $ReservationToAdd
        $Defaults.DefaultsUsed.$Type = $true
    }

    return $CurrentValue
}