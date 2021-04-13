#Requires -Modules PowerShellGet
#Requires -Version 5.0

<#
=======================================================================================================
    AUTHOR:  David Becher
    DATE:    1/29/2021
    Version: 1.0
    Comment: Add an external identity source to tenant vCenter. Requires powershell to have VMware.PowerCLI, AzurePowershell, and VMware.vSphere.SsoAdminModule installed
    Callouts: This script will require the powershell session running it to be able to authenticate to azure to pull secrets from key vault, will need service principal? Also make sure we don't allow code injections  
========================================================================================================
#>

# Helper Functions
function Get-SecretFromKV 
{
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


function Set-TestEnvironmentVariables 
{
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
   $connectedServer = Connect-VIServer -Server $vCenterIP 


   return $connectedServer
}

# Exported Functions

<#
    .Synopsis
     Allow customers to add an external identity source (Active Directory over LDAP) for use with single sign on to vCenter.

    .Example 
    # Add the domain server named "dabecher.local" to vCenter
    Add-ActiveDirectoryIdentitySource -Name 'dabecher' -DomainName 'dabecher.local' -DomainAlias 'dabecher' -PrimaryUrl 'ldap://10.40.0.5:389' -BaseDNUsers 'dc=dabecher, dc=local' -BaseDNGroups 'dc=dabecher, dc=local' -Username 'dabecher@dabecher.local' -Password 'PlaceholderPassword'
#>
function New-AvsLDAPIdentitySource {
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
  $PrimaryUrl,

  [Parameter(Mandatory = $false)]
  [ValidateScript({
  $_ -like '*ldap*'
  })]
  [string]
  $SecondaryUrl,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $BaseDNUsers,

  [Parameter(Mandatory = $true)]
  [ValidateNotNull()]
  [string]
  $BaseDNGroups,

  [Parameter(
    Mandatory = $true,
    HelpMessage='User name you want to use for authenticating with the server')]
  [ValidateNotNull()]
  [string]
  $Username,

  [Parameter(
    Mandatory = $true,
    HelpMessage='Password you want to use for authenticating with the server')]
  [ValidateNotNull()]
  [securestring]
  $Password,

  [Parameter(
    Mandatory = $true,
    HelpMessage='Certificate for authentication')]
  [ValidateNotNull()]
  [securestring]
  $Certificates
)
    Set-TestEnvironmentVariables
    Connect-SsoServer
    $Password = ConvertFrom-SecureString $Password
    $ExternalSource

    if ($SecondaryUrl) {
        $ExternalSource = 
            Add-LDAPIdentitySource 
                -Name $Name 
                -DomainName $DomainName 
                -DomainAlias $DomainAlias 
                -PrimaryUrl $PrimaryUrl 
                -SecondaryUrl $SecondaryUrl
                -BaseDNUsers $BaseDNUsers 
                -BaseDNGroups $BaseDNGroups 
                -Username $Username 
                -Password $Password
                -ServerType 'ActiveDirectory'
                -Certificates $Certificates
        Write-Output $ExternalSource
    } Else {
        $ExternalSource = 
            Add-LDAPIdentitySource 
                -Name $Name 
                -DomainName $DomainName 
                -DomainAlias $DomainAlias 
                -PrimaryUrl $PrimaryUrl
                -BaseDNUsers $BaseDNUsers 
                -BaseDNGroups $BaseDNGroups 
                -Username $Username 
                -Password $Password
                -ServerType 'ActiveDirectory'
                -Certificates $Certificates
        Write-Output $ExternalSource
    }
    return $ExternalSource
}

<#
    .Synopsis
     Creates a Drs Cluster Host Group, a Drs Cluster VM Group, and a Drs Cluster Virtual Machine to Host Rule between the two

    .Example 
    # Create a should run rule named MyDrsRule on Cluster-1 Hosts using the listed VM's and VMHosts
    New-DrsElevationRule -DrsGroupName "MyDrsGroup" -DrsRuleName "MyDrsRule" -Cluster "Cluster-1" -VMList "vm1", "vm2" -VMHostList "esx01", "esx02"
#>
function New-AvsDrsElevationRule {
[CmdletBinding(PositionalBinding = $false)]
Param
(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $DrsRuleName,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $DrsGroupName,

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
    Set-TestEnvironmentVariables
    Connect-vCenterServer
    
    $DrsVmHostGroupName = $DrsGroupName + "Host"
    Write-Host ($DrsRuleName + $DrsGroupName + $Cluster +  $VMList + $VMHostList)
    New-DrsClusterGroup -Name $DrsGroupName -VM $VMList -Cluster $Cluster
    New-DrsClusterGroup -Name $DrsVmHostGroupName -VMHost $VMHostList -Cluster $Cluster
    $result = New-DrsVMHostRule -Name $DrsRuleName -Cluster $Cluster -VMGroup $DrsGroupName -VMHostGroup $DrsVmHostGroupName -Type "ShouldRunOn"
    return $result
}

<#
    .Synopsis
     Edits a Drs Cluster Group

    .Example 
    # Create a should run rule named MyDrsRule on Cluster-1 Hosts using the listed VM's and VMHosts
    Set-AvsDrsClusterGroup -DrsGroupName "MyDrsGroup" -Cluster "Cluster-1" -VMList "vm1", "vm2" 
#>
function Set-AvsDrsClusterGroup {
  [CmdletBinding(PositionalBinding = $false)]
  Param
  (   
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]
      $DrsGroupName,
  
      [Parameter(Mandatory = $false)]
      [ValidateNotNullOrEmpty()]
      [string[]]
      $VMList,
  
      [Parameter(Mandatory = $false)]
      [ValidateNotNullOrEmpty()]
      [string[]]
      $VMHostList,

      [switch] $Add = $false,
      [switch] $Remove = $false

  )

      if ($Add -And $Remove) {
        $result = "You can't add and remove at the same time. Try again with just one flag"
        return $result
      } elseif ($Add -eq $false -and $Remove -eq $false) {
        $result = "Nothing was done. Please select with either -Add or -Remove"
      }

      Set-TestEnvironmentVariables
      Connect-vCenterServer

      if ($VMList -And $VMHostList) {
        $result = "Only update the parameter for your Drs Group. Either VM or Host. Nothing done."
        return $result
      } ElseIf ($VMList) {
        If ($Add) {
          $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Add -Confirm
          return $result
        } ElseIf ($Remove) {
          $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Add -Confirm
          return $result
        }
      } ElseIf ($VMHostList) {
        If ($Add) {
          $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Add -Confirm
          return $result
        } ElseIf ($Remove) {
          $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Add -Confirm
          return $result
        }
      }
      Else {
        $result = "Please select to add or remove either VMs or VMHosts from the Drs Group"
      }
}

<#
    .Synopsis
     Edits a Drs Cluster Group

    .Example 
    # Create a should run rule named MyDrsRule on Cluster-1 Hosts using the listed VM's and VMHosts
    Set-AvsDrsClusterGroup -DrsGroupName "MyDrsGroup" -Cluster "Cluster-1" -VMList "vm1", "vm2" 
#>
function Set-AvsDrsElevationRule {
  [CmdletBinding(PositionalBinding = $false)]
  Param
  (   
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]
      $DrsRuleName,
  
      [Parameter(Mandatory = $false)]
      [Nullable[boolean]]
      $Enabled,
  
      [Parameter(Mandatory = $false)]
      [ValidateNotNullOrEmpty()]
      [string]
      $Name
  )
      Write-Host "Enabled: $Enabled"

      Write-Host "Enabled is ne null:" + ($Enabled -ne $null) 
      #Set-TestEnvironmentVariables
      #Connect-vCenterServer
  
      if (($Enabled -ne $null) -And $Name) {
        Write-Host "Enabled $Enabled and Name: $Name"
        $result = Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $true -Name $Name
        return $result
      } ElseIf ($Enabled -ne $null) {
        $result = Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $true 
        Write-Host "Enabled $enabled "
        return $result
      } ElseIf ($Name) {
        $result = Set-DrsVMHostRule -Rule $DrsRuleName -Name $Name
        Write-Host "no Enabled $enabled just Name $Name "
        return $result
      } Else {
        $result = Get-DrsVMHostRule -Name $DrsRuleName
        Write-Host "Nothing done  "
        return $result
      }
  
  }
  

<#
    .Synopsis
     Edit the storage policy on the VM to a predefined storage policy

    .Example 
    # Create a should run rule named MyDrsRule on Cluster-1 Hosts using the listed VM's and VMHosts
    Set-AvsStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -VMName "EVM02-TNT79"
#>
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
      return $result
    } Else {
      $result = "Placeholder for cluster editing, currently not supported"
      return $result
    }
}

Export-ModuleMember -Function *