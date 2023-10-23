using module Microsoft.AVS.Management

<#
    .SYNOPSIS
     Creates a new vVol datastore and mounts to a VMware cluster.

    .PARAMETER ClusterName
     Cluster name

    .PARAMETER DatastoreName
     Datastore name

    .PARAMETER ScId
     Storage container ID of device used to create a new vVol datastore

    .EXAMPLE
     New-VVolDatastore -ClusterName "myCluster" -DatastoreName "myDatastore" -ScId $ScId

    .INPUTS
     vCenter cluster name, datastore name, and storage container ID

    .OUTPUTS
     None.
#>
function New-VvolDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Cluster name in vCenter')]
        [ValidateNotNull()]
        [String]
        $ClusterName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of vVol datastore to be created in vCenter')]
        [ValidateNotNull()]
        [String]
        $DatastoreName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Storage container ID of device used to create a new vVol datastore')]
        [ValidateNotNull()]
        [String]
        $ScId
    )

    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $ClusterName does not exist."
    }

    $Datastore = Get-Datastore -Name $DatastoreName -ErrorAction Ignore
    if ($Datastore) {
        throw "Unable to create a datastore. Datastore '$DatastoreName' already exists."
    }
    $VMHosts = $Cluster | Get-VMHost
    # We need to loop through Esxi to mount the datastore to all of hosts
    foreach ($Esxi in $VMHosts) {
        # Create a new vVol datastore with the specified size and rescan storage
        $datastoreSystem = Get-View -Id $Esxi.ExtensionData.ConfigManager.DatastoreSystem
        $spec = New-Object VMware.Vim.HostDatastoreSystemVvolDatastoreSpec
        $spec.Name = $datastoreName
        $spec.ScId = $scId
        $Datastore = $esxi | Get-Datastore | Where-Object { $_.Type -eq "VVol" } | Where-Object { $_.ExtensionData.Info.VVolds.Scid -eq $scId }
        Write-Host "Mounting datastore $DatastoreName to host $($Esxi.Name)..."
        $datastoreSystem.CreateVvolDatastore($spec)
    }
}


<#
    .SYNOPSIS
     Removes a vVol datastore from a VMware cluster.

    .PARAMETER ClusterName
     Cluster name

    .PARAMETER DatastoreName
     Datastore name

    .EXAMPLE
     Remove-VVolDatastore -ClusterName "myCluster" -DatastoreName "myDatastore"

    .INPUTS
     vCenter cluster name, datastore name

    .OUTPUTS
     None.
#>
function Remove-VvolDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Cluster name in vCenter')]
        [ValidateNotNull()]
        [String]
        $ClusterName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of vVol datastore to be created in vCenter')]
        [ValidateNotNull()]
        [String]
        $DatastoreName
    )

    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
    if (-not $Cluster) {
        throw "Cluster $ClusterName does not exist."
    }

    $Datastore = Get-Datastore -Name $DatastoreName -ErrorAction Ignore
    if (-not $Datastore) {
        throw "Unable to remove a datastore. Datastore '$DatastoreName' does not exist."
    }

    $VM = $Datastore | Get-VM
    if ($VM) {
        throw "Unable to remove a datastore. Datastore '$DatastoreName' is already in use. Please make sure that no Virtual Machines are using this datastore."
    }
    if ("VVOL" -ne $Datastore.Type) {
        throw "Datastore $DatastoreName is of type $($Datastore.Type). This cmdlet can only process VVol datastores"
    }

    $VMHosts = $Cluster | Get-VMHost
    # We need to loop through Esxi to unmount the datastore from all of hosts
    foreach ($Esxi in $VMHosts) {
        # Unmount the datastore from the host
        $datastoreSystem = Get-View -Id $Esxi.ExtensionData.ConfigManager.DatastoreSystem
        Write-Host "Unmounting datastore $DatastoreName from host $($Esxi.Name)..."
        $datastoreSystem.RemoveDatastore($Datastore.ExtensionData.MoRef)
    }
}


<#
    .SYNOPSIS
    Refresh certificates for all ESXi hosts

    .DESCRIPTION
    Refresh certificates for all ESXi hosts

    .EXAMPLE
    Update-VMHostCertificate

    .INPUTS
    None.

    .OUTPUTS
    None.

#>
function Update-VMHostCertificate {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param ()

    $service_instance = Get-View ServiceInstance
    $certMgr = Get-View -Id $service_instance.Content.CertificateManager

    Get-VMHost | ForEach-Object -Process {
        Write-Host "Refreshing certificates for $($_.Name).."
        $certMgr.CertMgrRefreshCACertificatesAndCRLs($_.Id) | Out-Null
    }

    Write-Host "Certificates refreshed successfully for all of ESXi hosts."
}

<#
    .SYNOPSIS
     Create a new VASA provider in vCenter

    .PARAMETER ProviderName
     Name of VASA provider to be created in vCenter

    .PARAMETER FlashArrayMgmtIP
     URL of the VASA provider service

    .PARAMETER ProviderCredential
     Credential of the VASA provider service

    .EXAMPLE
     New-VvolVasaProvider -ProviderName "myProvider" -FlashArrayMgmtIP "1.0.0.0" -ProviderCredential $ProviderCredential
#>
function New-VvolVasaProvider {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of VASA provider to be created in vCenter')]
        [ValidateNotNull()]
        [String]
        $ProviderName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'URL of the VASA provider service')]
        [ValidateNotNull()]
        [String]
        $ProviderUrl,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Credential of the VASA provider service')]
        [ValidateNotNull()]
        [PSCredential]
        $ProviderCredential
    )

    $VasaProvider = Get-VasaProvider -Name $ProviderName -ErrorAction Ignore
    if ($vasaProvider) {
        throw "Unable to create a VASA provider. Vasa provider '$ProviderName' already exists."
    }

    New-VasaProvider -Name $ProviderName -Credential $ProviderCredential -Url $ProviderUrl -Force -ErrorAction Stop | Out-Null

    Write-Host "VASA provider $ProviderName created successfully."
}

<#
    .SYNOPSIS
     Remove a VASA provider from vCenter

    .PARAMETER ProviderName
     Name of VASA provider to be removed from vCenter

    .EXAMPLE
     Remove-VvolVasaProvider -ProviderName "myProvider"

    .INPUTS
     vCenter VASA provider name

    .OUTPUTS
     None.
#>
function Remove-VvolVasaProvider {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of VASA provider to be created in vCenter')]
        [ValidateNotNull()]
        [String]
        $ProviderName
    )

    $VasaProvider = Get-VasaProvider -Name $ProviderName -ErrorAction Ignore
    if (-not $VasaProvider) {
        throw "Unable to remove a VASA provider '$ProviderName'. Vasa provider '$ProviderName' does not exist."
    }

    # Find datastores connected to the vasa provider
    $Datastore = Get-Datastore | Where-Object { $_.ExtensionData.Info.VVolDS.VasaProviderInfo.Provider.Name -eq $VasaProvider.Name }
    if ($Datastore) {
        throw "Unable to remove a VASA provider. Vasa provider '$ProviderName' is connected to one or more datastores. Please remove the connected datastores first."
    }

    Remove-VasaProvider -Provider $VasaProvider -Confirm:$false -ErrorAction Stop | Out-Null

    Write-Host "VASA provider $ProviderName removed successfully."
}


<#
    .SYNOPSIS
     Creates a new vVol Storage Policy

    .PARAMETER PolicyConfigJsonString
     Storage policy in Json string. The command will traverse through the SPBM rules and creat a storage policy containing all of the rules.

    .EXAMPLE
    $policyConfigJsonString = @"
    {
        "SchemaVersion": "1.0.0",
        "Vendor": "Pure Storage",
        "PolicyName": "",
        "PolicyDescription": "",
        "SpbmRules": {
            "com.purestorage.storage.policy.FlashArrayGroup":["fa1","fa2"],
            "com.purestorage.storage.replication.LocalSnapshotPolicyCapable": true,
            "com.purestorage.storage.replication.LocalSnapshotInterval":"00:00:00"
        }
    "@"
     New-VvolStoragePolicy -PolicyConfigJsonString $policyConfigJsonString

    .INPUTS
     vCenter storage policy in Json string

    .OUTPUTS
     None.
#>
function New-VvolStoragePolicy {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Storage policy in Json string')]
        [ValidateNotNull()]
        [String]$PolicyConfigJsonString
    )
    # Convert JSON to PowerShell object
    $PolicyConfig = ConvertFrom-Json $PolicyConfigJsonString
    # Extract values from the object
    $Vendor = $PolicyConfig.Vendor
    $PolicyName = $PolicyConfig.PolicyName
    if (-not $PolicyName) {
        throw "Unable to create a storage policy. Policy name is not specified."
    }
    $PolicyDescription = $PolicyConfig.PolicyDescription
    $SchemaVersion = $PolicyConfig.SchemaVersion

    if ($SchemaVersion -gt "1.0.0") {
        throw "Unable to create a storage policy. Schema version $SchemaVersion is not supported."
    }

    # Create SPBM rules dictionary
    $rules = @()
    $PolicyConfig.SpbmRules.PSObject.Properties | ForEach-Object {
        $RuleName = $_.Name
        $RuleValue = $_.Value
        if ($Vendor -eq "Pure Storage") {
            $ValueType = (Get-SpbmCapability -Name $RuleName).ValueType.Name
            if ($RuleValue -is [int64] -and $ValueType -eq "int32") {
                $RuleValue = [int]$RuleValue
            }
            if ($ValueType -eq "TimeSpan") {
                $RuleValue = [TimeSpan]::Parse($RuleValue)
            }
        }
        $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $RuleName) -Value $RuleValue
    }

    Write-Host "Creating policy $PolicyName for vendor $Vendor..."
    $Ruleset = New-SpbmRuleSet -AllOfRules $rules
    New-SpbmStoragePolicy -Name $PolicyName -Description $PolicyDescription -AnyOfRuleSets $Ruleset -ErrorAction Stop | Out-Null
}

<#
    .SYNOPSIS
    Removes a vVol Storage Policy

    .PARAMETER PolicyName
    Name of the storage policy to be removed

    .EXAMPLE
    Remove-VvolStoragePolicy -PolicyName "myPolicy"

    .INPUTS
    vCenter storage policy name

    .OUTPUTS
    None.
#>
function Remove-VvolStoragePolicy {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Storage policy name')]
        [ValidateNotNull()]
        [String]$PolicyName
    )

    $Policy = Get-SpbmStoragePolicy -Name $PolicyName -ErrorAction Ignore
    if (-not $Policy) {
        throw "Unable to remove a storage policy. Storage policy '$PolicyName' does not exist."
    }

    Write-Host "Removing policy $PolicyName..."
    Remove-SpbmStoragePolicy -StoragePolicy $Policy -Confirm:$false -ErrorAction Stop | Out-Null
}

<#
    .SYNOPSIS
    Start a Replication Group failover or test failover

    .PARAMETER ReplicationGroupID
    Replication group ID

    .PARAMETER TestFailover
    Optional. Indicates whether to actually perform a failover(false) or to only perform a test failover(true). If not provided will only perform failover test.

    .PARAMETER PointInTimeReplicaName
    Optional. Point-in-time replica name. If not provided, the latest point-in-time replica will be used.

    .EXAMPLE
    Start-ReplicationFailover -ReplicationGroupID "myRepGroupID" -TestFailover $true

    .INPUTS
    Replication Group ID

    .OUTPUTS
    Replicated Virtual Machine names.
#>
function Start-ReplicationFailover {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param(
        [Parameter(
                Mandatory = $true,
                HelpMessage = 'Replication group ID')]
        [ValidateNotNull()]
        [String] $ReplicationGroupID,

        [Parameter(
                mandatory = $false,
                HelpMessage = 'Point-in-time replica name')]
        [String] $PointInTimeReplicaName,

        [Parameter(
                mandatory = $false,
                HelpMessage = 'Whether to perform a test failover or not')]
        [bool] $TestFailover
    )
    $repGroup = Get-SpbmReplicationGroup -ID $ReplicationGroupID

    if (-not $repGroup) {
        throw "Could not find replication group '$ReplicationGroupID'."
    }
    elseif ($repGroup.State -ne "Target") {
        throw "Replication group '$ReplicationGroupID' need to be a replication group in 'Target' state."
    }

    if ($PointInTimeReplicaName) {
        $replica = Get-SpbmPointInTimeReplica -Name $PointInTimeReplicaName -ErrorAction Ignore
        if (-not $replica) {
            throw "Could not find point-in-time replica '$PointInTimeReplicaName'."
        }
    }

    ## Failing over the replication group for the VMs and setting the operations to a variable ##
    if ($TestFailover) {
        # does test failover, rep group status become InTest
        Write-Host "Starting test failover for replication group $ReplicationGroupID..."
        if ($PointInTimeReplicaName) {
            $replicatedVMFiles = Start-SpbmReplicationTestFailover -ReplicationGroup $repGroup -PointInTimeReplica $replica -Confirm:$false
        }
        else {
            $replicatedVMFiles = Start-SpbmReplicationTestFailover -ReplicationGroup $repGroup -Confirm:$false
        }
    }
    else {
        # does actual failover, rep group status become FailedOver
        Write-Host "Starting failover for replication group $ReplicationGroupID..."
        if ($PointInTimeReplicaName) {
            $replicatedVMFiles = Start-SpbmReplicationFailover -ReplicationGroup $repGroup -PointInTimeReplica $replica -Confirm:$false
        }
        else {
            $replicatedVMFiles = Start-SpbmReplicationFailover -ReplicationGroup $repGroup -Confirm:$false
        }
    }

    $NamedOutputs = @{}
    $i = 0
    foreach ($VMFile in $replicatedVMFiles) {
        $NamedOutputs["vm_$i"] = $VMFile
    }

    Set-Variable -Name NamedOutputs -Value $NamedOutputs -Scope Global
}

<#
    .SYNOPSIS
    Stop a Replication Group test failover

    .PARAMETER ReplicationGroupID
    Replication group ID

    .EXAMPLE
    Stop-ReplicationTestFailover -ReplicationGroupID "myRepGroupID"

    .INPUTS
    Replication Group ID

    .OUTPUTS
    None.
#>
function Stop-ReplicationTestFailover {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param(
        [Parameter(
                Mandatory = $true,
                HelpMessage = 'Replication group ID')]
        [ValidateNotNull()]
        [String]$ReplicationGroupID
    )
    $repGroup = Get-SpbmReplicationGroup -ID $ReplicationGroupID

    if (-not $repGroup) {
        throw "Could not find replication group '$ReplicationGroupID'."
    }
    elseif ($repGroup.State -ne "InTest") {
        throw "Replication group '$ReplicationGroupID' need to be a replication group in 'InTest' state."
    }

    Write-Host "Stopping test failover for replication group $ReplicationGroupID..."
    Stop-SpbmReplicationTestFailover -ReplicationGroup $repGroup -Confirm:$false
}

<#
    .SYNOPSIS
    Start a Replication Group reverse

    .PARAMETER ReplicationGroupID
    Replication group ID

    .EXAMPLE
    Start-ReplicationReverse -ReplicationGroupID "myRepGroupID"

    .INPUTS
    Replication Group ID

    .OUTPUTS
    Reversed Replication Group Name.
#>
function Start-ReplicationReverse {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param(
        [Parameter(
                Mandatory = $true,
                HelpMessage = 'Replication group ID')]
        [ValidateNotNull()]
        [String]$ReplicationGroupID
    )
    $repGroup = Get-SpbmReplicationGroup -ID $ReplicationGroupID

    if (-not $repGroup) {
        throw "Could not find replication group '$ReplicationGroupID'."
    }
    elseif ($repGroup.State -ne "FailedOver") {
        throw "Replication group '$ReplicationGroupID' need to be a replication group in 'FailedOver' state."
    }

    Write-Host "Starting reverse replication for replication group $ReplicationGroupID..."
    $newSourceGroup = Start-SpbmReplicationReverse -ReplicationGroup $repGroup.Name

    $NamedOutputs = @{}
    $NamedOutputs["new_source_group"] = $newSourceGroup.Name
    Set-Variable -Name NamedOutputs -Value $NamedOutputs -Scope Global
}

<#
    .SYNOPSIS
    Synchronize a replication group. Must be run on a "Target" Replication Group.

    .PARAMETER ReplicationGroupID
    Replication group ID

    .PARAMETER PointInTimeReplicaName
    Point-in-time replica name. If not provided, the latest point-in-time replica will be used.

    .EXAMPLE
    Sync-ReplicationGroup -ReplicationGroupID "myRepGroupID" -PointInTimeReplicaName "myReplica"

    .INPUTS
    Replication Group ID

    .OUTPUTS
    None.
#>
function Sync-ReplicationGroup {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param(
        [Parameter(
                Mandatory = $true,
                HelpMessage = 'Replication group ID')]
        [ValidateNotNull()]
        [String]$ReplicationGroupID,

        [Parameter(
                Mandatory = $true,
                HelpMessage = 'Point-in-time replica name')]
        [ValidateNotNull()]
        [String]$PointInTimeReplicaName
    )

    $repGroup = Get-SpbmReplicationGroup -ID $ReplicationGroupID
    if (-not $repGroup) {
        throw "Could not find replication group '$ReplicationGroupID'."
    }
    elseif ($repGroup.State -ne "Target") {
        throw "Replication group '$ReplicationGroupID' need to be a replication group in 'Target' state."
    }

    Write-Host "Starting replication sync for replication group $ReplicationGroupID..."
    Sync-SpbmReplicationGroup -ReplicationGroup $repGroup -PointInTimeReplicaName $PointInTimeReplicaName
}