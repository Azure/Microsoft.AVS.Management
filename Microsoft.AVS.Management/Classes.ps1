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

Defined via Add-Type (compiled C#) rather than the PowerShell `class` keyword so the
resulting type is registered in the AppDomain and resolvable from any module scope —
including dot-sourced .ps1 files inside consumer modules whose attribute-bind happens
after Microsoft.AVS.Management's ScriptsToProcess has already run in a different
SessionState (e.g., when Microsoft.AVS.CDR.Import-ModulePinned imports Management
from inside its own module function). PowerShell `class` types are scoped to the
declaring SessionState's type table and are not visible to dot-sourced consumers in
that scenario.
#>
if (-not ('AVSAttribute' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @"
using System;
[AttributeUsage(AttributeTargets.All, AllowMultiple = false)]
public sealed class AVSAttribute : Attribute {
    public bool UpdatesSDDC { get; set; }
    public bool AutomationOnly { get; set; }
    public TimeSpan Timeout { get; private set; }
    public AVSAttribute(double timeoutMinutes) {
        this.Timeout = TimeSpan.FromMinutes(timeoutMinutes);
    }
}
"@
}

<#
SecureFolder class provides a way to create a folder protected from CloudAdmins.
#>
if (-not ('AVSSecureFolder' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @"
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;

public sealed class AVSSecureFolder {
    private static readonly string vendors = "AVS-vendor-folders";

    private static Collection<PSObject> Invoke(string script, params object[] args) {
        return ScriptBlock.Create(script).Invoke(args);
    }

    public static void ApplyPermissions(object objects) {
        Invoke(@"
param($objects)
$admin = Get-VIRole -Name ""Admin"" -ErrorAction Stop
$readOnly = Get-VIRole -Name ""ReadOnly"" -ErrorAction Stop
$scripting = Get-VIAccount -Id ""scripting"" -Domain ""vsphere.local"" -ErrorAction Stop
$group = Get-VIAccount -Group -Id ""CloudAdmins"" -Domain ""vsphere.local"" -ErrorAction Stop
$objects | New-VIPermission -Principal $scripting -Role $admin -Propagate $true
$objects | New-VIPermission -Principal $group -Role $readOnly -Propagate $true
if ($objects.Folder -ne [AVSSecureFolder]::Root()) {
    $external = $objects | Get-VIPermission |
        Where-Object { -not $_.Principal.StartsWith(""VSPHERE.LOCAL"") } |
        ForEach-Object {
            $parts = $_.Principal -split '\\', 2
            Get-VIAccount -Group:$_.IsGroup -Domain $parts[0] -Id $parts[1]
        }

    foreach ($x in $external) {
        $objects | New-VIPermission -Principal $x -Role $readOnly -Propagate $true
    }
}
", objects);
    }

    public static object Root() {
        var result = Invoke(@"
param($vendors)
$location = Get-Folder -Location ((Get-Datacenter)[0]) -Name ""vm""
$root = Get-Folder -Name $vendors -NoRecursion -Location $location -ErrorAction SilentlyContinue
if ($null -eq $root) {
    $root = New-Folder -Location $location -Name $vendors -ErrorAction Stop
    [AVSSecureFolder]::ApplyPermissions($root)
}
return $root
", vendors);

        return result.Count > 0 ? result[0].BaseObject : null;
    }

    public static void Secure(object folder) {
        Invoke(@"
param($folder)
$objects = @(Get-VM -Location $folder) + @(Get-VApp -Location $folder)
[AVSSecureFolder]::ApplyPermissions($objects)
", folder);
    }

    public static object GetOrCreate(string name) {
        var result = Invoke(@"
param($name)
$root = [AVSSecureFolder]::Root()
$folder = Get-Folder -Location $root -Name $name -NoRecursion -ErrorAction SilentlyContinue
if ($null -eq $folder) {
    $folder = New-Folder -Location $root -Name $name -ErrorAction Stop
}
return $folder
", name);

        return result.Count > 0 ? result[0].BaseObject : null;
    }
}
"@
}
