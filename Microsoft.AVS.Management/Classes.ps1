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
SecureFolder class provides a way to create a folder protected from CloudAdmins.
#>
class AVSSecureFolder {
    hidden static [string]$vendors = "AVS-vendor-folders"
    <#
        Returns vendors root folder or $null in case of any error.
    #>
    static [VMware.VimAutomation.ViCore.Types.V1.Inventory.Folder] Root() {
        $admin = Get-VIRole -Name "Admin" -ErrorAction Stop
        $noAccess = Get-VIRole -Name "NoAccess" -ErrorAction Stop
        $scripting = Get-VIAccount -Id "scripting" -Domain "vsphere.local" -ErrorAction Stop
        $group = Get-VIAccount -Group -Id "CloudAdmins" -Domain "vsphere.local" -ErrorAction Stop
        $location = Get-Folder -Location ((Get-Datacenter)[0]) -Name "vm"
        $root = Get-Folder -Name ([AVSSecureFolder]::vendors) -NoRecursion -Location $location -ErrorAction SilentlyContinue
        if($null -eq $root) {
            $root = New-Folder -Location $location -Name ([AVSSecureFolder]::vendors) -ErrorAction Stop
            New-VIPermission -Entity $root -Principal $scripting -Role $admin -Propagate $true -ErrorAction Stop
            New-VIPermission -Entity $root -Principal $group -Role $noAccess -Propagate $true -ErrorAction Stop
        }
        return $root
    }

    <#
        Creates a subfolder or returns existing one given the name.
        Returns $null in case of any error.
    #>
    static [VMware.VimAutomation.ViCore.Types.V1.Inventory.Folder] GetOrCreate([string]$name) {
        $root = [AVSSecureFolder]::Root()
        $folder = Get-Folder -Location $root -Name $name -NoRecursion -ErrorAction SilentlyContinue
        if($null -eq $folder) {
            $folder = New-Folder -Location $root -Name $name -ErrorAction Stop
        }
        return $folder
    }
}
