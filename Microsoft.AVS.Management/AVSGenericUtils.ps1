<#PSScriptInfo

.VERSION 1.1

.GUID ce8e0201-4bcd-4e42-9918-1f81d110f520

.AUTHOR K. Chris Nakagaki

.COMPANYNAME Microsoft

.COPYRIGHT (c) Microsoft. All rights reserved.

.DESCRIPTION Powershell generic private functions for general manipulation or validation of strings.

#>

function ConvertTo-CanonicalUuid {
    <#
    .SYNOPSIS
        Normalizes a UUID by removing non-hex characters and converting to lowercase.
    .DESCRIPTION
        Takes a UUID string, removes any characters not in 0-9 or A-F/a-f, and returns a lowercase version.
    .PARAMETER Uuid
        The UUID string to normalize.
    .EXAMPLE
        ConvertTo-CanonicalUuid -Uuid ""
    #>
    param([string]$Uuid)
    return ($Uuid -replace '[^A-Fa-f0-9]', '').ToLowerInvariant()
}

function Format-RegexToken {
    <#
    .SYNOPSIS
        Escapes special regex characters in a string.
    .DESCRIPTION
        Ensures the input string is safe to use in a regex pattern by escaping special characters.
    .PARAMETER Value
        The string value to escape.
    .EXAMPLE
        Format-RegexToken -Value "VM*01"
    #>
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    return [Regex]::Escape($Value.Trim())
}

function Get-AvsExcludePatterns {
    <#
    .SYNOPSIS
        Returns a regex pattern to match system-like or excluded vSAN objects.
    .DESCRIPTION
        Combines a predefined list of keywords (like vsan, mgmt, system) into a single regex pattern.
    .EXAMPLE
        $pattern = Get-AvsExcludePatterns
    #>
    $tokens = @(
        'vsan','mgmt','vcenter','nsx','system','infra','stats',
        'hcx','srm','replication','backup','sr','drs','EVM','APP','VRM','VRS'
    )
    $escaped = $tokens | Sort-Object -Unique | ForEach-Object { Format-RegexToken $_ }
    return '(?i)(' + ($escaped -join '|') + ')'
}

function Get-AvsMgmtResourcePoolRegex {
    <#
    .SYNOPSIS
        Returns a regex pattern for identifying management resource pools.
    .DESCRIPTION
        This regex matches resource pool names considered part of management.
    .EXAMPLE
        $regex = Get-AvsMgmtResourcePoolRegex
    #>
    '(?i)^mgmt-resourcepool$'
}

function New-RegexFromList {
    <#
    .SYNOPSIS
        Converts a list of strings into a single regex pattern.
    .DESCRIPTION
        Escapes all strings in the list and joins them with '|' for use in regex matching.
    .PARAMETER List
        An array of strings to include in the regex pattern.
    .EXAMPLE
        $rx = New-RegexFromList -List @("VM1","VM2")
    #>
    param([string[]]$List)
    if (-not $List -or $List.Count -eq 0) { return $null }
    $escaped = $List | Sort-Object -Unique | ForEach-Object { Format-RegexToken $_ }
    return '(?i)(' + ($escaped -join '|') + ')'
}

function Get-HealthFromExt {
    <#
    .SYNOPSIS
        Returns health information from vSAN object extended attributes.
    .DESCRIPTION
        Parses extended attributes of a vSAN object and extracts health state, absent/degraded flags, and policy compliance.
    .PARAMETER Ext
        The extended attributes object (usually parsed JSON).
    .EXAMPLE
        $health = Get-HealthFromExt -Ext $extJson
    #>
    param($Ext)
    $state = "Unknown"; $abs = $false; $deg = $false; $pol = "Unknown"

    if ($null -eq $Ext) { return [pscustomobject]@{ HealthState=$state; IsAbsent=$abs; IsDegraded=$deg; PolicyCompliance=$pol } }

    foreach ($p in $Ext.PSObject.Properties) {
        $n = $p.Name; $v = [string]$p.Value
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

    return [pscustomobject]@{ HealthState=$state; IsAbsent=$abs; IsDegraded=$deg; PolicyCompliance=$pol }
}

function Get-MgmtResourcePoolVMs {
    <#
    .SYNOPSIS
        Lists all VMs in management resource pools of a cluster.
    .DESCRIPTION
        Returns a collection of VM names and MoRefs that are part of resource pools matching the management regex.
    .PARAMETER PoolRegex
        Regex pattern to identify management resource pools.
    .PARAMETER ClusterName
        Name of the vSphere cluster to query.
    .EXAMPLE
        $mgmtVMs = Get-MgmtResourcePoolVMs -PoolRegex (Get-AvsMgmtResourcePoolRegex) -ClusterName "Cluster-1"
    #>
    param([string]$PoolRegex, [string]$ClusterName)

    $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $mors  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    $rps = Get-ResourcePool -Location $cluster | Where-Object { $_.Name -match $PoolRegex }
    foreach ($rp in $rps) {
        foreach ($vm in (Get-VM -Location $rp)) {
            if ($vm.Name) { $null = $names.Add($vm.Name) }
            try { $mo = $vm.ExtensionData.MoRef.Value; if ($mo) { $null = $mors.Add($mo) } } catch {}
        }
    }

    return [pscustomobject]@{ Names=@($names); MoRefs=@($mors); Count=$names.Count }
}

function Test-AVSProtectedObjectName {
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
    begin {
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
    process {
        # Check if the name is in the protected names list
        # If it is a protected name 'throw' and don't continue
        if ($ProtectedNames -contains $Name) {
            throw "$Name is a protected name.  Please use a different name."
        }
        # If not a protected name, return false
        Write-Information "$Name is not a protected name."
        return $false
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