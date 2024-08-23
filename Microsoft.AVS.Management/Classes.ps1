<#PSScriptInfo
    .VERSION 1.0

    .GUID 9fbc3ba5-9ee0-4910-950b-b24ecc4919b8

    .AUTHOR Microsoft

    .COMPANYNAME Microsoft

    .COPYRIGHT (c) Microsoft. All rights reserved.

    .DESCRIPTION Common classes for AVS cmdlets
#>

<#
AVSAttribute applied to a commandlet function indicates:
- whether the SDDC should be marked as Building while the function executes.
- default timeout for the commandlet, maximum: 3h.
- whether a commandlet is intended to be only for automation or is visible to all customers.
AVS SDDC in Building state prevents other changes from being made to the SDDC until the function completes/fails.
#>
class AVSAttribute : Attribute {
    [bool]$UpdatesSDDC = $false
    [TimeSpan]$Timeout
    [bool]$AutomationOnly = $false
    AVSAttribute($timeoutMinutes) { $this.Timeout = New-TimeSpan -Minutes $timeoutMinutes }
}

<#
SecureFolder class provides a way to create a folder protected from CloudAdmins.
#>
class AVSSecureFolder {
    hidden static [string]$vendors = "AVS-vendor-folders"
    <#
        Applies propagating permissions to specified objects.
    #>
    hidden static ApplyPermissions($objects) {
        $admin = Get-VIRole -Name "Admin" -ErrorAction Stop
        $readOnly = Get-VIRole -Name "ReadOnly" -ErrorAction Stop
        $scripting = Get-VIAccount -Id "scripting" -Domain "vsphere.local" -ErrorAction Stop
        $group = Get-VIAccount -Group -Id "CloudAdmins" -Domain "vsphere.local" -ErrorAction Stop
        $objects | New-VIPermission -Principal $scripting -Role $admin -Propagate $true
        $objects | New-VIPermission -Principal $group -Role $readOnly -Propagate $true
        if ($objects.Folder -ne [AVSSecureFolder]::Root()) {
            $external = `
                $objects | Get-VIPermission `
                | Where-Object { -not $_.Principal.StartsWith("VSPHERE.LOCAL") } `
                | ForEach-Object { Get-VIAccount -Group:$_.IsGroup -Domain $_.Principal.Split("\")[0] -Id $_.Principal.Split("\")[1]}
            foreach ($x in $external) {
                $objects | New-VIPermission -Principal $x -Role $readOnly -Propagate $true
            }
        }
    }

    <#
        Returns vendors root folder or $null in case of any error.
    #>
    static [VMware.VimAutomation.ViCore.Types.V1.Inventory.Folder] Root() {
        $location = Get-Folder -Location ((Get-Datacenter)[0]) -Name "vm"
        $root = Get-Folder -Name ([AVSSecureFolder]::vendors) -NoRecursion -Location $location -ErrorAction SilentlyContinue
        if ($null -eq $root) {
            $root = New-Folder -Location $location -Name ([AVSSecureFolder]::vendors) -ErrorAction Stop
            [AVSSecureFolder]::ApplyPermissions($root)
        }
        return $root
    }

    <#
        Secure all objects in the specified folder.
    #>
    static Secure([VMware.VimAutomation.ViCore.Types.V1.Inventory.Folder]$folder) {
        $objects = @(Get-VM -Location $folder) + @(Get-VApp -Location $folder)
        [AVSSecureFolder]::ApplyPermissions($objects)
    }

    <#
        Creates a subfolder or returns existing one given the name.
        Returns $null in case of any error.
    #>
    static [VMware.VimAutomation.ViCore.Types.V1.Inventory.Folder] GetOrCreate([string]$name) {
        $root = [AVSSecureFolder]::Root()
        $folder = Get-Folder -Location $root -Name $name -NoRecursion -ErrorAction SilentlyContinue
        if ($null -eq $folder) {
            $folder = New-Folder -Location $root -Name $name -ErrorAction Stop
        }
        return $folder
    }
}
