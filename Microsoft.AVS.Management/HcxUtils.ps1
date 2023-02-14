<#PSScriptInfo
    .VERSION 1.0

    .GUID 953d76b2-f8ef-4a8c-9754-44fef24ecb93

    .AUTHOR Frantz Prinvil

    .COMPANYNAME Microsoft

    .COPYRIGHT (c) Microsoft. All rights reserved.

    .DESCRIPTION PowerShell Cmdlets for Managing Hybrid Cloud Extension (HCX) on VMware Cloud on AWS
#>

<#
    .Synopsis
    Get the authorization token found in the response headers under the name of 'x-hm-authorization'

    .Parameter Credential
    Specifies a PSCredential object that contains credentials for authenticating with the server.
    For more information about the server authentication logic of PowerCLI, run "help about_server_authentication".

    .Parameter HcxServer
    Specifies the IP or DNS addresses of the HCX servers to connect to.

    .Example
    Get-AuthorizationToken -Credential <UserCreds> -HcxServer "10.40.0.9"
#>
function Get-AuthorizationToken {
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Credential of the vSphere User/Group that has authorized access to HCX")]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX Server Name')]
        [ValidateNotNull()]
        [string]
        $HcxServer
    )

    $networkCred = (New-Object System.Management.Automation.PSCredential $Credential.UserName, $Credential.Password).GetNetworkCredential()
    $JsonBody = @{'username' = $networkCred.UserName; 'password' = $networkCred.Password } | ConvertTo-Json

    Write-Host "Create Hybridity Session:"
    $elapsed = Measure-Command -Expression `
    { Invoke-RestMethod -Method 'POST' `
            -Uri https://${HcxServer}/hybridity/api/sessions `
            -ContentType 'application/json' -Body $JsonBody `
            -Verbose -SkipCertificateCheck `
            -ResponseHeadersVariable SessionHeaders -ErrorAction Stop }

    Write-Host "Created Hybridity Session: elapsed=${elapsed}"
    return $SessionHeaders['x-hm-authorization']
}

<#
    .Synopsis
    Get and return Hcx Metadata Blob

    .Parameter XHmAuthorization
    Valid authorization token obtained by performing a POST to https://<HCX-Server>/hybridity/api/sessions

    .Parameter HcxServer
    Specifies the IP or DNS addresses of the HCX servers you want to connect to.

    .Example
    Get-HcxMetaData -XHmAuthorization <authToken> -HcxServer "10.40.0.9"
#>
function Get-HcxMetaData {
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX Hybridity Session')]
        [ValidateNotNull()]
        [string]
        $XHmAuthorization,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX Server Name')]
        [ValidateNotNull()]
        [string]
        $HcxServer
    )

    $headers = @{
        "x-hm-authorization"="$XHmAuthorization"
        "Content-Type"="application/json"
        "Accept"="application/json"
    }
    $body = "{filter={},options={}}"

    Write-Host "Retrieving HCX Manager Meta Data"
    $elapsed = Measure-Command -Expression { $response = Invoke-RestMethod -Uri "https://${HcxServer}/hybridity/api/metainfo/context/support" -Method 'GET' -Headers $headers -Body $body -Verbose -SkipCertificateCheck -ErrorAction Stop }

    if ($response.success -eq 'True') {
        Write-Host "Retrieved HCX Manager Meta Data: elapsed=${elapsed}"
        return $response.data.localEndpoints
    }

    throw "Unable To Retrieve HCX Manager Meta Data"
}
<#
    .Synopsis
    Get and return HCX Virtual machine
    .Example
    Get-HcxManagerVM
#>
function Get-HcxManagerVM {
    Write-Host "Identifying HCX VM"
    $HcxVm = $null
    $VmsList = Get-VM

    foreach ($Vm in $VmsList) {
        if($Vm.Name.Contains("HCX-MGR")) {
            $HcxVm = $Vm
            break
        }
    }
    return $HcxVm
}

<#
    .Synopsis
    Get and return the utilization percentage of a specified disk

    .Parameter DiskName
    Disk name

    .Parameter Disks
    List of disks and metadata

    .Example
    Get-DiskUtilizationPercentage -Disks <List of Disks> -DiskName "/"
#>
function Get-DiskUtilizationPercentage {
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the name of the desired disk')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DiskName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'List of disks')]
        [ValidateNotNullOrEmpty()]
        [array]
        $Disks
    )

        $DiskData = $Disks | Where-Object Path -eq $DiskName

        if($DiskData) {
            $UsagePercentage = [math]::round((1 - ($DiskData.FreeSpaceGB / $DiskData.CapacityGB)) * 100,2)

            return $UsagePercentage
        }
        throw "Disk: $DiskName was not found in the list provided"
}

<#
    .Synopsis
    Test the connection to the HCX server

    .Parameter RefreshInterval
    Seconds delay in between each retry

    .Parameter Count
    The amount of connection retrys per function call

    .Parameter Server
    The server to which the connection is being established

    .Parameter Port
    Connection port

    .Parameter Credential
    Credential used to connect to Server

    .Parameter HcxVm
    HCX Vm

    .Example
    Test-HcxConnection -Server 'HcxServer' -Count 5 -Port '443' -Credential <PsCredential> -HcxVm 'HcxVm'
#>
function Test-HcxConnection {
    Param (
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Seconds delay in between each retry')]
        [ValidateNotNullOrEmpty()]
        [int]
        $RefreshInterval = 60,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Number of connection retrys')]
        [ValidateNotNullOrEmpty()]
        [int]
        $Count,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX Server Name')]
        [ValidateNotNull()]
        [string]
        $Server,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Port number')]
        [ValidateNotNullOrEmpty()]
        [int]
        $Port,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Credential used to connect to Server')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX VM')]
        [ValidateNotNullOrEmpty()]
        [string]
        $HcxVm
    )
    Write-Host "Reconnecting to HCX Server..."
    do {
        $Count -= 1
        if ($Count -lt 0) {
            throw "Timed out reconnecting to HCX Server."
        }
        Write-Host "Retrys remaining: $Count..."
        Start-Sleep -Seconds $RefreshInterval

        $hcxConnection = Connect-HCXServer -Server $Server -Port $Port -Credential $Credential -ErrorAction:SilentlyContinue
    }
    until ($hcxConnection)

    Write-Host "HCX Appliance on $($HcxVm.name) is now available."
    return $hcxConnection
}

<#
    .Synopsis
    Provide a list of disks and a specific set of disk, this cmdlet will alert if the utilization has surpassed the threshold

    .Parameter DiskUtilizationTreshold
    Threshold value

    .Parameter MonitoredDisks
    Disks to be checked

    .Parameter Disks
    List of disks and metadata

    .Example
    Get-DiskUtilizationPercentage -Disks <List of Disks> -DiskName "/"
#>
function Invoke-DiskUtilizationThresholdCheck {
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Timeout for connection to HCX Server')]
        [ValidateNotNull()]
        [int]
        $DiskUtilizationTreshold,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Timeout for connection to HCX Server')]
        [ValidateNotNull()]
        [array]
        $MonitoredDisks,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Timeout for connection to HCX Server')]
        [ValidateNotNull()]
        [array]
        $Disks
    )
    foreach ($MonitoredDisk in $MonitoredDisks) {
        Write-Host "Retrieving Disk: $MonitoredDisk Percentage"
        $DiskUtilizationPercentage = Get-DiskUtilizationPercentage -Disks $Disks -DiskName $MonitoredDisk

        if ($DiskUtilizationPercentage -gt $DiskUtilizationTreshold) {
            throw "Disk: $MonitoredDisk Percentage: $DiskUtilizationPercentage is greater than the allowed treshold: $DiskUtilizationTreshold"
        }

        Write-Host "Retrieved Disk: $MonitoredDisk Percentage: $DiskUtilizationPercentage %"
    }
}

<#
    .Synopsis
    A boolean parameter that ensures customer understands that HCX will be rebooted. Default value is false

    .Parameter AgreeToRestartHCX
    Agree to restarting HCX

    .Example
    Assert-CustomerRestartAwareness -AgreeToRestartHCX $true
#>
function Assert-CustomerRestartAwareness {
    Param(
        [parameter(
            Mandatory = $false,
            HelpMessage = "Customer acknowledging HCX reboot.")]
        [switch]
        $AgreeToRestartHCX = $false
    )

    if(!$AgreeToRestartHCX) {
        throw "Please confirm awareness that HCX will be rebooted by this cmdlet."
    }
}