<#
    .SYNOPSIS
    Deploys the Azure Migrate appliance VM from its OVA template into the SDDC.

    .DESCRIPTION
    Downloads the Azure Migrate appliance OVA, imports it as a VM into the specified
    cluster, maps its network to the specified NSX segment, and powers it on.

    .PARAMETER VmName
    Name of VM

    .PARAMETER ClusterName
    Name of cluster to deploy the VM in

    .PARAMETER NetworkName
    Name of nsx segment

    .PARAMETER OvaUrl
    URL of the OVA template to deploy

    .EXAMPLE
    Deploy-MigrateApplianceVM -VmName "AzMigrateAppliance" -NetworkName "TestSegment"
#>
function Deploy-MigrateApplianceVM {
    [CmdletBinding()]
    [AVSAttribute(60, UpdatesSDDC = $true)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Name of VM")]
        [ValidateNotNull()]
        [string]$VmName,

        [Parameter(Mandatory = $false, HelpMessage = "Name of cluster to deploy the VM in")]
        [ValidateNotNull()]
        [string]$ClusterName = "Cluster-1",

        [Parameter(Mandatory = $true, HelpMessage = "Name of nsx segment")]
        [ValidateNotNull()]
        [string]$NetworkName,

        [Parameter(Mandatory = $false, HelpMessage = "URL of the OVA template to deploy")]
        [ValidateNotNull()]
        [string]$OvaUrl = "https://go.microsoft.com/fwlink/?linkid=2191954"
    )

    if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
        throw "A VM named '$VmName' already exists. Choose a different -VmName or remove the existing VM first."
    }

    $selectedCluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    # Any host in the cluster is acceptable - pick the first one available.
    $vmHost = Get-VMHost -Location $selectedCluster -ErrorAction Stop | Select-Object -First 1
    if (-not $vmHost) {
        throw "No hosts found in cluster '$ClusterName'"
    }

    # Get-OvfConfiguration/Import-VApp do not support HTTP(S) URLs directly - they bind
    # the string as a filesystem path - so the OVA must be downloaded locally first.
    $ovaFileName = Join-Path ([System.IO.Path]::GetTempPath()) (Split-Path -Leaf $OvaUrl)
    try {
        Write-Output "Downloading OVA from '$OvaUrl' to '$ovaFileName'..."
        Invoke-WebRequest -Uri $OvaUrl -OutFile $ovaFileName -ErrorAction Stop

        $ovfConfig = Get-OvfConfiguration -Ovf $ovaFileName -ErrorAction Stop
        if ($ovfConfig.NetworkMapping) {
            # NetworkMapping exposes each OVF network as a dynamic CodeProperty (not a plain
            # .NET Property) - filtering on -MemberType Properties matches unrelated base
            # object members instead, so the mapping never actually gets applied and
            # Import-VApp falls back to the host's (nonexistent, DVS-only) local vSwitch,
            # failing with "Host did not have any virtual network defined."
            $networkMapping = $ovfConfig.NetworkMapping | Get-Member -MemberType CodeProperty | Select-Object -First 1 -ExpandProperty Name
            if ($networkMapping) {
                $ovfConfig.NetworkMapping.$networkMapping.Value = $NetworkName
                Write-Output "Mapping OVF network '$networkMapping' to '$NetworkName'"
            }
        }

        Import-VApp -Source $ovaFileName -OvfConfiguration $ovfConfig -VMHost $vmHost -Name $VmName -Location $selectedCluster -Force -ErrorAction Stop
    } finally {
        if (Test-Path $ovaFileName) {
            Remove-Item -Path $ovaFileName -Force -ErrorAction SilentlyContinue
        }
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    Start-VM -VM $vm -Confirm:$false -ErrorAction Stop
    Write-Output "VM $VmName created and powered on successfully"
}
