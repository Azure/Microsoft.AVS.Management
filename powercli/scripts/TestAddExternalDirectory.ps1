#Requires -Modules PowerShellGet
#Requires -Version 5.0

[CmdletBinding(PositionalBinding = $false)]
Param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $Name,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $DomainName,

  [Parameter(Mandatory = $true)]
  [string]
  $DomainAlias,

  [Parameter(Mandatory = $true)]
  [ValidateScript({
  $_ -like '*ldap*'
  })]
  [string]
  $PrimaryURL,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $BaseDNUsers,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $BaseDNGroups,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $Username,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $Password,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $PathToCertificate
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

Set-TestEnvironmentVariables
Connect-SsoServer
New-AvsLDAPIdentitySource -Name $Name -DomainName $DomainName -DomainAlias $DomainAlias -PrimaryURL $PrimaryURL -BaseDNUsers $BaseDNUsers -BaseDNGroups $BaseDNGroups -Username $Username -Password $Password -CertificateSAS $PathToCertificate