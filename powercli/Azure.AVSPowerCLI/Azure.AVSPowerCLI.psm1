#Requires -Modules PowerShellGet
#Requires -Version 5.0

<#
=======================================================================================================
    AUTHOR:  David Becher
    DATE:    4/22/2021
    Version: 1.0.0
    Comment: Cmdlets for various administrative functions of Azure VMWare Solution products
    Callouts: This script will require the powershell session running it to be able to authenticate to azure to pull secrets from key vault, will need service principal? Also make sure we don't allow code injections  
========================================================================================================
#>

# Exported Functions
<#
    .Synopsis
     Allow customers to add an external identity source (Active Directory over LDAP) for use with single sign on to vCenter. Prefaced by Connect-SsoAdminServer

    .Example 
    # Add the domain server named "dabecher.local" to vCenter
    Add-ActiveDirectoryIdentitySource -Name 'dabecher' -DomainName 'dabecher.local' -DomainAlias 'dabecher' -PrimaryUrl 'ldaps://10.40.0.5:636' -BaseDNUsers 'dc=dabecher, dc=local' -BaseDNGroups 'dc=dabecher, dc=local' -Username 'dabecher@dabecher.local' -Password 'PlaceholderPassword' -Credential './path/to/certificate/cert.cer'
#>
function New-AvsLDAPIdentitySource {
[CmdletBinding(PositionalBinding = $false)]
Param
(
  [Parameter(
    Mandatory = $true,
    HelpMessage='User-Friendly name to store in vCenter')]
  [ValidateNotNull()]
  [string]
  $Name,

  [Parameter(
    Mandatory = $true,
    HelpMessage='Full DomainName: adserver.local')]
  [ValidateNotNull()]
  [string]
  $DomainName,

  [Parameter(
    Mandatory = $true,
    HelpMessage='DomainAlias: adserver')]
  [string]
  $DomainAlias,

  [Parameter(
    Mandatory = $true,
    HelpMessage='URL of your AD Servier: ldaps://yourserver:636')]
  [ValidateScript({
    $_ -like '*ldaps://*636'
  })]
  [string]
  $PrimaryUrl,

  [Parameter(
    Mandatory = $false,
    HelpMessage='Optional: URL of a backup server')]
  [ValidateScript({
    $_ -like '*ldaps://*636'
  })]
  [string]
  $SecondaryUrl,

  [Parameter(
    Mandatory = $true,
    HelpMessage='BaseDNGroups, "DC=name, DC=name"')]
  [ValidateNotNull()]
  [string]
  $BaseDNUsers,

  [Parameter(
    Mandatory = $true,
    HelpMessage='BaseDNGroups, "DC=name, DC=name"')]
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
  [string]
  $Password,

  [Parameter(
    Mandatory = $true,
    HelpMessage='SAS path URI to Certificate for authentication. Ensure permissions to read included. For how to generate see <Insert Helpful Link>')]
  [ValidateNotNull()]
  [string]
  $CertificateSAS
  )

    $Destination="./cert.cer"
    $Source=$CertificateSAS
    try
    {
        Write-Host "Downloading Certificate........."
        $Response = Invoke-WebRequest -Uri $Source -OutFile $Destination
        # This will only execute if the Invoke-WebRequest is successful.
        $StatusCode = $Response.StatusCode
        Write-Host("Certificate downloaded: " + $StatusCode)
    }
    catch
    {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return ("Failed to download: " + $StatusCode)
    }
    
    Write-Host "Adding the LDAP Identity Source..."
    if ($SecondaryUrl) {
        $ExternalSource = 
            Add-LDAPIdentitySource `
                -Name $Name `
                -DomainName $DomainName `
                -DomainAlias $DomainAlias `
                -PrimaryUrl $PrimaryUrl `
                -SecondaryUrl $SecondaryUrl`
                -BaseDNUsers $BaseDNUsers `
                -BaseDNGroups $BaseDNGroups `
                -Username $Username `
                -Password $Password`
                -ServerType 'ActiveDirectory'`
                -Certificates $Destination
    } Else {
        $ExternalSource = 
            Add-LDAPIdentitySource `
                -Name $Name `
                -DomainName $DomainName `
                -DomainAlias $DomainAlias `
                -PrimaryUrl $PrimaryUrl`
                -BaseDNUsers $BaseDNUsers `
                -BaseDNGroups $BaseDNGroups `
                -Username $Username `
                -Password $Password `
                -ServerType 'ActiveDirectory'`
                -Certificates $Destination
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
    [Parameter(
      Mandatory = $true,
      HelpMessage='User-Friendly name of the Drs rule to create')]
    [ValidateNotNullOrEmpty()]
    [string]
    $DrsRuleName,
    
    [Parameter(
      Mandatory = $true,
      HelpMessage='User-Friendly name of the Drs group to create')]
    [ValidateNotNullOrEmpty()]
    [string]
    $DrsGroupName,

    [Parameter(
      Mandatory = $true,
      HelpMessage='Cluster to create the rule and group on')]
    [ValidateNotNullOrEmpty()]
    [string]
    $Cluster,

    [Parameter(
      Mandatory = $true,
      HelpMessage='List of the VMs to add to the VM group')]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $VMList,

    [Parameter(
      Mandatory = $true,
      HelpMessage='List of the VMHosts to add to the VMHost group')]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $VMHostList
)   
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
    [Parameter(
      Mandatory = $true,
      HelpMessage='Name of the Drs group to edit')]
    [ValidateNotNullOrEmpty()]
    [string]
    $DrsGroupName,

    [Parameter(
      Mandatory = $true,
      HelpMessage='List of the VMs to add to the VM group')]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $VMList,

    [Parameter(
      Mandatory = $true,
      HelpMessage='List of the VMHosts to add to the VMHost group')]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $VMHostList,

    [switch] $Add = $false,
    [switch] $Remove = $false

  )

  If ($Add -And $Remove) {
    $result = "You can't add and remove at the same time. Try again with just one flag"
    return $result
  } ElseIf ($Add -eq $false -and $Remove -eq $false) {
    $result = "Nothing was done. Please select with either -Add or -Remove"
  } Else {
    If ($VMList -And $VMHostList) {
    $result = "Nothing done. Please select with either -VMHostList or -VMHost."
    return $result
    } ElseIf ($VMList) {
      If ($Add) {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Add -Confirm
        return $result
      } ElseIf ($Remove) {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Remove -Confirm
        return $result
      }
    } ElseIf ($VMHostList) {
      If ($Add) {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Add -Confirm
        return $result
      } ElseIf ($Remove) {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Remove -Confirm
        return $result
      }
    }
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
      [Parameter(
        Mandatory = $true,
        HelpMessage='Name of the Drs rule to edit')]
      [ValidateNotNullOrEmpty()]
      [string]
      $DrsRuleName,
  
      [Parameter(
        Mandatory = $false,
        HelpMessage='Enabled switch: $true or $false')]
      [Nullable[boolean]]
      $Enabled,
  
      [Parameter(
        Mandatory = $false,
        HelpMessage='New name for the Drs rule')]
      [ValidateNotNullOrEmpty()]
      [string]
      $Name
  )
      Write-Host "Enabled: $Enabled"

      Write-Host "Enabled is ne null:" + ($Enabled -ne $null) 
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
        Write-Host "Not Enabled $enabled just Name $Name "
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

    [Parameter(
      Mandatory = $true,
      HelpMessage='Name of the storage policy to set')]
    [ValidateNotNullOrEmpty()]
    [string]
    $StoragePolicyName,
    
    [Parameter(
      Mandatory = $false,
      HelpMessage='Name of the VM to set the storage policy on')]
    [string]
    $VMName,

    [Parameter(
      Mandatory = $false,
      HelpMessage='Name of the Cluster to set the storage policy on')]
    [string]
    $Cluster
)
    if ($VMName -And $Cluster) {
      $result = "Only can update one VM or a cluster at a time. Please try again with just -VMName or -Cluster"
      return $result
    } ElseIf ($VMName -ne $null) {
      $storagepolicy = Get-SpbmStoragePolicy -Name $StoragePolicyName
      $result = Set-VM $VMName -StoragePolicy $storagepolicy -SkipHardDisks
      return $result
    } Else {
      $result = "Placeholder for cluster editing, currently not supported. Nothing done"
      return $result
    }
}

Export-ModuleMember -Function *