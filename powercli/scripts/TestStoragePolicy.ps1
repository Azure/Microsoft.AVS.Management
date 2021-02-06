# Helper Functions
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
    $secret = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $SecretName).SecretValue
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

function Connect-SsoServer
{

   #$env:PSModulePath = Join-Path -Path $PSHOME -ChildPath 'Modules'al' -Password $env:ServiceUserPassword
   #$env:PSModulePath = "$env:PSModulePath;$(Split-Path -Path $PSModuleInfo.ModuleBase -Pare
   # The $env:ServiceUserPassword must be set on the container at start up (adminstrator password to tenant vCenter)
   $vCenterIP = $env:tntMgmtNetwork -replace $env:tntMgmtNetwork.split('.')[-1], '2' 
   $ServiceUserPassword = Get-SecretFromKV $env:KeyvaultName $env:PasswordSecretName
   
   $connectedServer= Connect-SsoAdminServer -Server $vCenterIP -User 'administrator@vsphere.local' -Password $ServiceUserPassword -SkipCertificateCheck

  return $connectedServer
}


function Connect-vCenterServer
{

   #$env:PSModulePath = Join-Path -Path $PSHOME -ChildPath 'Modules'al' -Password $env:ServiceUserPassword
   #$env:PSModulePath = "$env:PSModulePath;$(Split-Path -Path $PSModuleInfo.ModuleBase -Pare
   # The $env:ServiceUserPassword must be set on the container at start up (adminstrator password to tenant vCenter)
   $vCenterIP = $env:tntMgmtNetwork -replace $env:tntMgmtNetwork.split('.')[-1], '2' 
   #Set-PowerCLIConfiguration -InvalidCertificateAction Ignore
   $connectedServer = Connect-VIServer -Server $vCenterIP -User 'administrator@vsphere.local' 

   return $connectedServer
}

function Set-AvsStoragePolicy {
[CmdletBinding(PositionalBinding = $false)]
Param
(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $StoragePolicyName,
    
    [Parameter(Mandatory = $false)]
    [string]
    $VMName,

    [Parameter(Mandatory = $false)]
    [string]
    $Cluster
)
    Set-TestEnvironmentVariables
    Connect-vCenterServer
                
    if ($VMName -And $Cluster) {
      $result = "Only can update one VM or a cluster at a time. Please try again with just -VMName or -Cluster"
      return $result
    } ElseIf ($VMName -ne $null) {
      $storagepolicy = Get-SpbmStoragePolicy -Name $StoragePolicyName
      $result = Set-VM $VMName -StoragePolicy $storagepolicy -SkipHardDisks
    } Else {
      $result = "Placeholder for cluster editing"
      return $result
    }
}

$result = Set-AvsStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -VMName "TNT79-EVM02"
Write-Host $result
