<#PSScriptInfo
    .VERSION 1.0

    .GUID ec3edfc1-f50d-4220-b01a-ee1ae983d6a3

    .AUTHOR Microsoft

    .COMPANYNAME Microsoft

    .COPYRIGHT (c) Microsoft. All rights reserved.

    .DESCRIPTION Supporting classes for vendors
#>

<#
AVSAttribute applied to a commandlet function indicates:
- whether the SDDC should be marked as Building while the function executes.
- default timeout for the commandlet, maximum: 3h.
AVS SDDC in Building state prevents other changes from being made to the SDDC until the function completes/fails.
#>
class AVSAttribute : Attribute {
    [bool]$UpdatesSDDC = $false
    [TimeSpan]$Timeout
    AVSAttribute($timeoutMinutes) { $this.Timeout = New-TimeSpan -Minutes $timeoutMinutes }
}

<#
SecurePool class provides a way to create a pool protected from CloudAdmins.
#>
class AVSSecurePool {
    <#
        Returns $null in case of any error.
    #>
    static [VMware.VimAutomation.ViCore.Types.V1.Inventory.ResourcePool] Create([string]$cluster, [string]$name) {
        $admin = Get-VIRole -Name "Admin" -ErrorAction Stop
        $noAccess = Get-VIRole -Name "NoAccess" -ErrorAction Stop
        $scripting = Get-VIAccount -Id "scripting" -Domain "vsphere.local" -ErrorAction Stop
        $group = Get-VIAccount -Group -Id "CloudAdmins" -Domain "vsphere.local" -ErrorAction Stop
        $location = Get-Cluster -Name $cluster -ErrorAction Stop
        $pool = New-ResourcePool -Location $location -Name $name -ErrorAction Stop
        New-VIPermission -Entity $pool -Principal $scripting -Role $admin -Propagate $true -ErrorAction Stop
        New-VIPermission -Entity $pool -Principal $group -Role $noAccess -Propagate $true -ErrorAction Stop
        return $pool
    }
}
