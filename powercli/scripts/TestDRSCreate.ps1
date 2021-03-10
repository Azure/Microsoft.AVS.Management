#Requires -Modules PowerShellGet
#Requires -Version 5.0
<#
    ========================================================================================
===============
    AUTHOR:  David Becher
    DATE:    2/1/2021
    Version: 1.0
    Comment: Add an external identity source to tenant vCenter. Requires powershell to have VMware.PowerCLI, AzurePowershell, and VMware.vSphere.SsoAdminModule installed
    ========================================================================================
===============
#>

[CmdletBinding(PositionalBinding = $false)]
Param
(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $DRSRuleName,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $DRSGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Cluster,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $VMList,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $VMHostList
)

function Get-SecretFromKV {
Param
    (
      [Parameter(Mandatory = $true)]
      [string]
      $KeyvaultName,

      [Parameter(Mandatory = $true)]
      [string]
      $SecretName
      )
    Write-Host "The key vault is $KeyvaultName and the secret is $SecretName"
    $secret = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $SecretName)
    return $secret
}


function Set-TestEnvironmentVariables {
    Connect-AzAccount
    Set-AzContext -Subscription "23995e3f-96a0-4b7a-95a0-c77f91054b52"
    $env:KeyvaultName = "kv-4febfd10-f5c89d1442f7"
    $env:ServerSecretName = "tntnmanagementserver"
    $env:PasswordSecretName = "vcsa"
    $env:tntMgmtNetwork = '10.0.0.0/22'
}


function Connect-vCenterServer
{

   #$env:PSModulePath = Join-Path -Path $PSHOME -ChildPath 'Modules'al' -Password $env:ServiceUserPassword
   #$env:PSModulePath = "$env:PSModulePath;$(Split-Path -Path $PSModuleInfo.ModuleBase -Pare
   # The $env:ServiceUserPassword must be set on the container at start up (adminstrator password to tenant vCenter)
   $vCenterIP = $env:tntMgmtNetwork -replace $env:tntMgmtNetwork.split('.')[-1], '2' 
   $ServiceUserPassword = (Get-SecretFromKV $env:KeyvaultName $env:PasswordSecretName).SecretValue
   Write-Host $ServiceUserPassword
   #Set-PowerCLIConfiguration -InvalidCertificateAction Ignore
   $connectedServer = Connect-VIServer -Server 


   return $connectedServer
}

function Set-DRSRoleElevation
{

    [CmdletBinding(PositionalBinding = $false)]
    Param
    (
      [Parameter(Mandatory = $true)]
      [string]
      $DRSRuleName,

      [Parameter(Mandatory = $true)]
      [string]
      $DRSGroupName,

      [Parameter(Mandatory = $true)]
      [string]
      $Cluster,

      [Parameter(Mandatory = $true)]
      [string[]]
      $VMList,

      [Parameter(Mandatory = $true)]
      [string[]]
      $VMHostList
    )
    $DrsVmHostGroupName = $DRSGroupName + "Host"
    Write-Host ($DRSRuleName + $DRSGroupName + $Cluster +  $VMList + $VMHostList)
    New-DrsClusterGroup -Name $DRSGroupName -VM $VMList -Cluster $Cluster
    New-DrsClusterGroup -Name $DrsVmHostGroupName -VMHost $VMHostList -Cluster $Cluster
    $result = New-DrsVMHostRule -Name $DRSRuleName -Cluster $Cluster -VMGroup $DRSGroupName -VMHostGroup $DrsVmHostGroupName -Type "ShouldRunOn"
    return $result

}

Set-TestEnvironmentVariables
Connect-vCenterServer
$result = Set-DRSRoleElevation -DRSRuleName $DRSRuleName -DRSGroupName $DRSGroupName -Cluster $Cluster -VMList $VMList -VMHostList $VMHostList
Write-Host "Result: " $result 
