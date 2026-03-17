<#PSScriptInfo

.VERSION 1.1

.GUID ce8e0201-4bcd-4e42-9918-1f81d110f520

.AUTHOR K. Chris Nakagaki

.COMPANYNAME Microsoft

.COPYRIGHT (c) Microsoft. All rights reserved.

.DESCRIPTION Powershell generic private functions for general manipulation or validation of strings.

#>

function Write-Log {
    <#
    .SYNOPSIS
        Writes a formatted log message to the console.

    .DESCRIPTION
        Writes a timestamped message with a severity level and color-codes the output
        for easier readability.
    #>
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERR","OK")][string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $msg = "[$ts] [$Level] $Message"

    switch ($Level) {
        "INFO" { Write-Host $msg -ForegroundColor Cyan }
        "WARN" { Write-Host $msg -ForegroundColor Yellow }
        "ERR"  { Write-Host $msg -ForegroundColor Red }
        "OK"   { Write-Host $msg -ForegroundColor Green }
    }
}

function Ensure-OutFolder {
    <#
    .SYNOPSIS
        Ensures that an output folder exists and returns its resolved path.

    .DESCRIPTION
        Creates the folder if it does not already exist, then returns the absolute path.
    #>
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path $Path).Path
}

function Get-SafeObjectForJson {
    <#
    .SYNOPSIS
        Converts objects into a JSON-safe structure.

    .DESCRIPTION
        Removes non-serializable or unwanted properties and flattens complex values into
        simple strings so the result can be safely exported to JSON or CSV.
    #>
    param(
        [Parameter(Mandatory = $true)]$InputObject
    )

    $safeList = New-Object System.Collections.Generic.List[object]

    foreach ($item in @($InputObject)) {
        if ($null -eq $item) {
            $safeList.Add($null) | Out-Null
            continue
        }

        $props = [ordered]@{}
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -in @("LinkedView","ExtensionData","Client","Uid")) {
                continue
            }

            $val = $p.Value

            if ($null -eq $val) {
                $props[$p.Name] = $null
                continue
            }

            if (
                $val -is [string] -or
                $val -is [int] -or
                $val -is [long] -or
                $val -is [double] -or
                $val -is [decimal] -or
                $val -is [bool] -or
                $val -is [datetime]
            ) {
                $props[$p.Name] = $val
            }
            elseif ($val -is [System.Array]) {
                try {
                    $props[$p.Name] = ($val | ForEach-Object { "$_" }) -join "; "
                }
                catch {
                    $props[$p.Name] = "$val"
                }
            }
            else {
                try {
                    $props[$p.Name] = "$val"
                }
                catch {
                    $props[$p.Name] = "<unserializable>"
                }
            }
        }

        $safeList.Add([pscustomobject]$props) | Out-Null
    }

    return $safeList
}

function Save-JsonSafe {
    <#
    .SYNOPSIS
        Safely exports an object to a JSON file.

    .DESCRIPTION
        Converts the input object into a JSON-safe structure and writes it to disk.
        Logs a warning if serialization fails.
    #>
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Path
    )

    try {
        $safe = Get-SafeObjectForJson -InputObject $Object
        $safe | ConvertTo-Json -Depth 8 | Out-File -FilePath $Path -Encoding utf8
    }
    catch {
        Write-Log "JSON export skipped for $Path. Error: $($_.Exception.Message)" "WARN"
    }
}

function Get-SupportedVmLabels {
    <#
    .SYNOPSIS
        Gets supported vSAN performance metric labels for virtual machines.

    .DESCRIPTION
        Queries the vSAN Performance Manager for supported entity types, finds the
        virtual-machine entity definition, and returns the supported metric labels.
    #>
    $vpm = Get-VsanView -Id "VsanPerformanceManager-vsan-performance-manager"
    $supported = $vpm.VsanPerfGetSupportedEntityTypes()

    $entity = $supported | Where-Object { $_.name -eq "virtual-machine" } | Select-Object -First 1
    if (-not $entity) {
        throw "virtual-machine entity type not found."
    }

    $allMetrics = @()
    foreach ($bucket in @($entity.graphs) + @($entity.advancedGraphs) + @($entity.verboseGraphs)) {
        if ($bucket -and $bucket.metrics) {
            $allMetrics += $bucket.metrics
        }
    }

    $labels = $allMetrics |
        Where-Object { $_.label } |
        Select-Object -ExpandProperty label -Unique |
        Sort-Object

    return [pscustomobject]@{
        Supported = $supported
        Labels    = $labels
    }
}

function Get-InterestingClusterMetrics {
    <#
    .SYNOPSIS
        Returns the list of cluster metrics to collect.

    .DESCRIPTION
        Provides the predefined set of vSAN cluster-level metrics used by the raw
        metrics export workflow.
    #>
    return @(
        "VMConsumption.ReadIops",
        "VMConsumption.WriteIops",
        "VMConsumption.ReadThroughput",
        "VMConsumption.WriteThroughput",
        "VMConsumption.AverageReadLatency",
        "VMConsumption.AverageWriteLatency",
        "VMConsumption.OutstandingIO",
        "Backend.ReadThroughput",
        "Backend.WriteThroughput",
        "Backend.AverageReadLatency",
        "Backend.AverageWriteLatency",
        "Backend.OutstandingIO"
    )
}

function Export-RawStatsForEntity {
    <#
    .SYNOPSIS
        Exports raw vSAN stats for a given entity and metric set.

    .DESCRIPTION
        Queries vSAN stats for the supplied entity over the requested time window,
        flattens important fields for CSV output, writes per-metric and combined
        exports, and returns summary counts.
    #>
    param(
        [Parameter(Mandatory = $true)]$Entity,
        [Parameter(Mandatory = $true)][string]$EntityName,
        [Parameter(Mandatory = $true)][string[]]$MetricNames,
        [Parameter(Mandatory = $true)][datetime]$StartTime,
        [Parameter(Mandatory = $true)][datetime]$EndTime,
        [Parameter(Mandatory = $true)][string]$Folder
    )

    $allRaw = New-Object System.Collections.Generic.List[object]
    $flatRows = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]

    foreach ($metric in $MetricNames) {
        try {
            Write-Log "Querying $EntityName :: $metric" "INFO"

            $stats = Get-VsanStat -Entity $Entity -Name $metric -StartTime $StartTime -EndTime $EndTime -ErrorAction Stop

            if ($stats) {
                foreach ($row in @($stats)) {
                    $allRaw.Add($row) | Out-Null

                    $timeVal = $null
                    $valueVal = $null
                    $unitVal = $null
                    $entityVal = $EntityName

                    foreach ($p in $row.PSObject.Properties) {
                        if ($p.Name -match 'timestamp|time') {
                            if (-not $timeVal) { $timeVal = $p.Value }
                        }
                        elseif ($p.Name -match 'value|values|statvalue') {
                            if (-not $valueVal) { $valueVal = $p.Value }
                        }
                        elseif ($p.Name -match 'unit') {
                            if (-not $unitVal) { $unitVal = $p.Value }
                        }
                        elseif ($p.Name -match 'entity') {
                            if (-not $entityVal -and $p.Value) { $entityVal = $p.Value }
                        }
                    }

                    if ($null -eq $valueVal -and $row.PSObject.Properties["Value"]) {
                        $valueVal = $row.Value
                    }

                    $flatRows.Add([pscustomobject]@{
                        EntityName = $EntityName
                        Metric     = $metric
                        Time       = $timeVal
                        Value      = $valueVal
                        Unit       = $unitVal
                        RawType    = $row.GetType().FullName
                    }) | Out-Null
                }

                $safeMetric = ($metric -replace '[\\/:*?"<>| ]','_')

                Save-JsonSafe -Object $stats -Path (Join-Path $Folder "$safeMetric.json")

                try {
                    $safeCsvRows = Get-SafeObjectForJson -InputObject $stats
                    $safeCsvRows | Export-Csv -NoTypeInformation -Path (Join-Path $Folder "$safeMetric.csv")
                }
                catch {
                    Write-Log "Per-metric CSV export skipped for $EntityName :: $metric. Error: $($_.Exception.Message)" "WARN"
                }
            }
            else {
                Write-Log "No rows returned for $EntityName :: $metric" "WARN"
            }
        }
        catch {
            $errors.Add([pscustomobject]@{
                Entity = $EntityName
                Metric = $metric
                Error  = $_.Exception.Message
            }) | Out-Null

            Write-Log "Metric query failed for $EntityName :: $metric. Error: $($_.Exception.Message)" "WARN"
        }
    }

    if ($allRaw.Count -gt 0) {
        Save-JsonSafe -Object $allRaw -Path (Join-Path $Folder "_all_raw.json")
    }

    if ($flatRows.Count -gt 0) {
        $flatRows | Export-Csv -NoTypeInformation -Path (Join-Path $Folder "_all_flat.csv")
    }

    if ($errors.Count -gt 0) {
        $errors | Export-Csv -NoTypeInformation -Path (Join-Path $Folder "_errors.csv")
    }

    return [pscustomobject]@{
        RawCount    = $allRaw.Count
        FlatCount   = $flatRows.Count
        ErrorCount  = $errors.Count
    }
}


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