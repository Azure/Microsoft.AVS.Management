<#
    .SYNOPSIS
     This function expands an ElasticSAN datastore capacity in AVS vCenter.

    .PARAMETER DatastoreName
     Name of the ElasticSAN datastore to be expanded.

    .EXAMPLE
     Expand-ElasticSanDatastore -ClusterName Cluster-1 -DatastoreName MyElasticSanDatastore

    .INPUTS
     vCenter cluster name, Name of the ElasticSAN datastore.

    .OUTPUTS
     None.
#>
function Expand-ElasticSanDatastore {
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false, AutomationOnly = $false)]
    Param (
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'Name of the ElasticSAN based datastore as seen on vCenter')]
        [ValidateNotNull()]
        [String]
        $DatastoreName
    )

    if (-not $DatastoreName) {
        throw "Invalid datastore name $DatastoreName provided."
    }

    Write-Host "Expand-ElasticSanDatastore command issued. Retrieving datastores to search for $DatastoreName"
    $Datastores = Get-Datastore -Name $DatastoreName -ErrorAction stop
    Write-Host "Retrieved list of datastores. Searching for the desired datastore for expand operation."

    foreach ($Datastore in $Datastores) {
        $CurrentDatastoreName = $Datastore.Name

        if ($CurrentDatastoreName -eq $DatastoreName) {
            Write-Host "Found the datastore to expand."
            $DatastoreToResize = $Datastore
            break
        }
    }

    if (-not $DatastoreToResize) {
        throw "Input datastore $DatastoreName was not found."
    }

    foreach ($DatastoreHost in $DatastoreToResize.ExtensionData.Host.Key) {
      Get-VMHost -id "HostSystem-$($DatastoreHost.value)" | Get-VMHostStorage -RescanAllHba -RescanVmfs -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    }

    Write-Host "Rescanned all HBAs. Getting expansion options."
    $Esxi = Get-View -Id ($DatastoreToResize.ExtensionData.Host | Select-Object -last 1 | Select-Object -ExpandProperty Key)
    $DatastoreSystem = Get-View -Id $Esxi.ConfigManager.DatastoreSystem
    $ExpandOptions = $DatastoreSystem.QueryVmfsDatastoreExpandOptions($DatastoreToResize.ExtensionData.MoRef)

    Write-Host "Expanding the size of the VMFS datastore."
    $DatastoreSystem.ExpandVmfsDatastore($DatastoreToResize.ExtensionData.MoRef, $ExpandOptions[0].spec)
}