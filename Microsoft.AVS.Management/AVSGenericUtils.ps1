<#PSScriptInfo

.VERSION 1.1

.GUID ce8e0201-4bcd-4e42-9918-1f81d110f520

.AUTHOR K. Chris Nakagaki

.COMPANYNAME Microsoft

.COPYRIGHT (c) Microsoft. All rights reserved.

.DESCRIPTION Powershell generic private functions for general manipulation or validation of strings.

#>

function Get-AvsExcludePatterns {
    <#
      Returns a single case-insensitive regex used to exclude system/infra artifacts.
      Keep this list curated here so all cmdlets share the same defaults.
    #>
    [CmdletBinding()]
    param()

    # Add or remove tokens here as your estate evolves
    $tokens = @(
        'vsan','mgmt','vcenter','nsx','system','infra','stats',
        'hcx','srm','replication','backup','sr','drs'
    )

    # Build a single (?i) … | … regex
    $escaped = $tokens | Sort-Object -Unique | ForEach-Object { [regex]::Escape($_) }
    return '(?i)(' + ($escaped -join '|') + ')'
}

function Get-AvsMgmtResourcePoolRegex {
    <#
      Default regex that identifies your "management" resource pool(s).
      Modules and scripts should call this to remain consistent.
    #>
    [CmdletBinding()]
    param()
    '(?i)^mgmt-resourcepool$'
}

function New-RegexFromList {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$List)
    if (-not $List -or $List.Count -eq 0) { return $null }
    $escaped = $List | Sort-Object -Unique | ForEach-Object { [regex]::Escape($_) }
    '(?i)(' + ($escaped -join '|') + ')'
}

function Get-HealthFromExt {
    [CmdletBinding()]
    param($Ext)
    $state = "Unknown"; $abs=$false; $deg=$false; $pol="Unknown"
    if ($null -eq $Ext) { return [pscustomobject]@{ HealthState=$state; IsAbsent=$abs; IsDegraded=$deg; PolicyCompliance=$pol } }
    foreach ($p in $Ext.PSObject.Properties) {
        $n=$p.Name; $v=[string]$p.Value
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        if ($n -match '(?i)health|state|status') {
            if ($v -match '(?i)absent') { $abs=$true; $state='Absent' }
            elseif ($v -match '(?i)degrad') { $deg=$true; $state='Degraded' }
            elseif ($v -match '(?i)healthy|ok|green') { if(-not $abs -and -not $deg){ $state='Healthy' } }
        }
        if ($n -match '(?i)compliance|policy') {
            if ($v -match '(?i)non.?compliant|out.?of.?date|incompatible') { $pol='NonCompliant' }
            elseif ($v -match '(?i)compliant') { $pol='Compliant' }
        }
        if ($n -match '(?i)absent' -and $v -match '(?i)true|yes|1') { $abs=$true; $state='Absent' }
    }
    [pscustomobject]@{ HealthState=$state; IsAbsent=$abs; IsDegraded=$deg; PolicyCompliance=$pol }
}

function Get-MgmtResourcePoolVMs {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PoolRegex)

    $names = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList @([System.StringComparer]::OrdinalIgnoreCase)
    $mors  = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList @([System.StringComparer]::OrdinalIgnoreCase)

    $rps = Get-ResourcePool -ErrorAction Stop | Where-Object { $_.Name -match $PoolRegex }
    if (-not $rps) { return [pscustomobject]@{ Names=@(); MoRefs=@(); Count=0 } }

    foreach ($rp in $rps) {
        $vms = Get-VM -Location $rp -ErrorAction SilentlyContinue
        foreach ($vm in $vms) {
            if ($vm.Name) { [void]$names.Add([string]$vm.Name) }
            try {
                $mo = $vm.ExtensionData.MoRef.Value
                if ($mo) { [void]$mors.Add([string]$mo) }
            } catch { }
        }
    }
    [pscustomobject]@{
        Names = @($names)
        MoRefs = @($mors)
        Count = $names.Count
    }
}

function Test-AssociatedIdentity {
    [CmdletBinding()]
    param($Identity)
    $txt = @()
    foreach ($p in @('Type','Content','Owner','Name')) {
        if ($Identity.PSObject.Properties.Match($p)) {
            $v = [string]$Identity.$p
            if ($v) { $txt += $v }
        }
    }
    $blob = ($txt -join ' ').ToLowerInvariant()
    $pats = @('vm namespace','namespace','vmdk','v disk','vdisk','swap','snapshot','hcx','interconnect','srm','replication','dr','sr','ctk','vswp')
    foreach ($pat in $pats) { if ($blob -like "*$pat*") { return $true } }
    if ($blob -match '\bvm-\d+\b' -or $blob -match '\bpolicy\b' -or $blob -match '\bspbm\b') { return $true }
    $false
}

Function Test-AVSProtectedObjectName {
    <#
    .DESCRIPTION
        This function tests if an object name is valid.
    .PARAMETER Name
        Name of Object
    .EXAMPLE
        Test-AVSProtectedObjectName -Name "Encryption"
        Returns True if the name is protected.

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    Begin {
        #Protected Policy Object Name Validation Check
        $ProtectedNames = @(
            "Microsoft vSAN Management Storage Policy"
            "vSAN Default Storage Policy"
            "AVS POST IO Encryption"
            "AVS PRE IO Encryption"
            "RAID-1 FTT-1"
            "RAID-1 FTT-1 Dual Site"
            "RAID-1 FTT-1 Preferred"
            "RAID-1 FTT-1 Secondary"
            "RAID-1 FTT-2"
            "RAID-1 FTT-2 Dual Site"
            "RAID-1 FTT-2 Preferred"
            "RAID-1 FTT-2 Secondary"
            "RAID-1 FTT-3"
            "RAID-1 FTT-3 Dual Site"
            "RAID-1 FTT-3 Preferred"
            "RAID-1 FTT-3 Secondary"
            "RAID-5 FTT-1"
            "RAID-5 FTT-1 Dual Site"
            "RAID-5 FTT-1 Preferred"
            "RAID-5 FTT-1 Secondary"
            "RAID-6 FTT-2"
            "RAID-6 FTT-2 Dual Site"
            "RAID-6 FTT-2 Preferred"
            "RAID-6 FTT-2 Secondary"
            "NsxViAdministrator"
            "HMSCloudAdmin"
            "HmsReplicationUser"
            "HmsView"
            "jea-ro-role"
            "HmsAdmin"
            "jea-admin-role"
            "HmsDatastoreUser"
            "vStatsAdmin"
            "HmsCloudAdmin"
            "jea-ca-role"
            "VirtualMachinePowerUser"
            "VirtualMachineUser"
            "ResourcePoolAdministrator"
            "VMwareConsolidatedBackupUser"
            "DatastoreConsumer"
            "NetworkConsumer"
            "VirtualMachineConsoleUser"
            "AutoUpdateUser"
            "InventoryService.Tagging.TaggingAdmin"
            "SyncUsers"
            "vSphere Client Solution User"
            "WorkloadStorageManagement"
            "vSphereKubernetesManager"
            "com.vmware.Content.Registry.Admin"
            "SupervisorServiceCluster"
            "SupervisorServiceRootFolder"
            "SupervisorServiceGlobal"
            "VMOperatorController"
            "VMOperatorControllerGlobal"
            "NSOperatorController"
            "SrmAdministrator"
            "SrmProtectionGroupsAdministrator"
            "SrmRecoveryPlansAdministrator"
            "SrmTestAdministrator"
            "SrmRecoveryAdministrator"
            "SrmRemoteUser"
            "HmsDiagnostics"
            "vCLSAdmin"
            "vStatsUser"
            "HmsRecoveryUser"
            "VMServicesAdministrator"
            "NSX Administrator"
            "com.vmware.Content.Admin"
            "CloudAdmin"
            "HmsRemoteUser"
            "NsxAuditor"
            )
        $Name = Limit-WildcardsandCodeInjectionCharacters -String $Name
    }
    Process {
        ForEach ($ProtectedName in $ProtectedNames) {
            if ($ProtectedName -eq $Name) {
                Write-Error "$ProtectedName is a protected name.  Please use a different name."
                Return $true
                return
            }
        }
        Write-Host -ForegroundColor Green "$Name is not a protected name."
        Return $false
    }
}

Function Limit-WildcardsandCodeInjectionCharacters {
    <#
        .DESCRIPTION
            This function removes wildcards and code injection characters from a string.
        .PARAMETER String
            String to remove wildcards and code injection characters from.
        .EXAMPLE
            Limit-WildcardsandCodeInjectionCharacters -String "Encryption*"
            Returns "Encryption"
        .EXAMPLE
            Limit-WildcardsandCodeInjectionCharacters -String "|Encryption?*"
            Returns "Encryption"

        #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )
    Begin {
        #Remove Wildcards characters from string
        $String = $String.Replace("*", "").Replace("?", "").Replace("[", "").Replace("]", "").Replace(";", "").Replace("|", "").Replace("\", "").Replace('$_', "").Replace("{", "").Replace("}", "")
    }
    Process {
        Return $String
    }

}

Function Convert-StringToArray {
    <#
        .DESCRIPTION
            This function converts a string to an array based on defined delimiter.
        .PARAMETER String
            String value to convert into an array.
        .PARAMETER Delimiter
            Delimiter to use to split the string into an array.
            Default is ","
        .PARAMETER TrimandCleanup
            Removes any empty entries and preceding/trailing spaces.
            Default is $true.
    #>

    [CmdletBinding(DefaultParameterSetName = "Encryption")]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $String,
        [Parameter(Mandatory = $false)]
        [string]
        $Delimiter = ",",
        [Parameter(Mandatory = $false)]
        [boolean]
        $TrimandCleanup = $true
    )
    Begin {
        #Convert string to array
        Switch ($TrimandCleanup) {
            $true { $Array = $String.Split($Delimiter, [System.StringSplitOptions]::RemoveEmptyEntries).Trim() }
            $false { $Array = $String.Split($Delimiter) }
        }

    }
    Process {
        Return $Array
    }

}

Function Add-AVSTag{
    <#
        .DESCRIPTION
            This function creates or adds a tag w/ associated to an AVS Tag Category
        .PARAMETER Name
            Name of Tag to create or add.
        .PARAMETER Description
            Description of Tag.  Description of existing tag will be updated if it already exists.
        .PARAMETER Entity
            vCenter Object to add tag to.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        [Parameter(Mandatory = $false)]
        [string]
        $Description,
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Interop.V1.VIObjectCoreInterop]
        $Entity
    )
    Begin {
        $TagCategory = Get-TagCategory -Name "AVS"
        If (!$TagCategory) {
            $TagCategory = New-TagCategory -Name "AVS" -Description "Category for AVS Operations" -Cardinality:Multiple
        }
        $Tag = Get-Tag -Name $Name -Category $TagCategory
        If (!$Tag) {
            $Tag = New-Tag -Name $Name -Description $Description -Category $TagCategory
        }
        Else {Set-Tag -Description $Description -Tag $Tag}
        }

    Process {
        try {
            New-TagAssignment -Tag $Tag -Entity $Entity -ErrorAction Stop
            return
        }
        catch {
            <#Do this if a terminating exception happens#>
        }

    }

}