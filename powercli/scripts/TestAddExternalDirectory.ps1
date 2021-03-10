#Requires -Modules PowerShellGet
#Requires -Version 5.0
<#
    ========================================================================================
===============
    AUTHOR:  David Becher
    DATE:    1/29/2021
    Version: 1.0
    Comment: Add an external identity source to tenant vCenter. Requires powershell to have VMware.PowerCLI, AzurePowershell, and VMware.vSphere.SsoAdminModule installed
    Callouts: This script will require the powershell session running it to be able to authenticate to azure to pull secrets from key vault, will need service principal? Also make sure we don't allow code injections  
 ========================================================================================
===============
#>
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

  [Parameter(
    Mandatory = $true),
    HelpMessage='User name you want to use for authenticating with the server')]
  [ValidateNotNull()]
  [string]
  $Username,

  [Parameter(
    Mandatory = $true)
    HelpMessage='Password you want to use for authenticating with the server')]
  [ValidateNotNull()]
  [string]
  $Password
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

function Add-ExternalIdentitySource
{

    [CmdletBinding(PositionalBinding = $false)]
    Param
    (
      [Parameter(Mandatory = $true)]
      [string]
      $Name,

      [Parameter(Mandatory = $true)]
      [string]
      $DomainName,

      [Parameter(Mandatory = $true)]
      [string]
      $DomainAlias,

      [Parameter(Mandatory = $true)]
      [string]
      $PrimaryURL,

      [Parameter(Mandatory = $true)]
      [string]
      $BaseDNUsers,

      [Parameter(Mandatory = $true)]
      [string]
      $BaseDNGroups,

      [Parameter(Mandatory = $true)]
      [string]
      $Username,

      [Parameter(Mandatory = $true)]
      [string]
      $Password
    )

    $ExternalSource = Add-ActiveDirectoryIdentitySource -Name $Name -DomainName $DomainName -DomainAlias $DomainAlias -PrimaryUrl $PrimaryURL -BaseDNUsers $BaseDNUsers -BaseDNGroups $BaseDNGroups -Username $Username -Password $Password
    Write-Output $ExternalSource
    return $ExternalSource
}

Set-TestEnvironmentVariables
Connect-SsoServer
Add-ExternalIdentitySource -Name $Name -DomainName $DomainName -DomainAlias $DomainAlias -PrimaryURL $PrimaryURL -BaseDNUsers $BaseDNUsers -BaseDNGroups $BaseDNGroups -Username $Username -Password $Password
