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
    HelpMessage='URL of your AD Server: ldaps://yourserver:636')]
  [ValidateScript({
    $_ -match 'ldap.*:.*((389)|(636)|(3268)(3269))'
  })]
  [string]
  $PrimaryUrl,

  [Parameter(
    Mandatory = $false,
    HelpMessage='Optional: URL of a backup server')]
  [ValidateScript({
    $_ -match 'ldap.*:.*((389)|(636)|(3268)(3269))'
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
    Mandatory = $false,
    HelpMessage='Array of SAS path URI to Certificates for authentication. Ensure permissions to read included. For how to generate see <Insert Helpful Link>')]
  [string[]]
  $CertificatesSAS,

  [Parameter(
    Mandatory = $true,
    HelpMessage='Protocol to use when configuring the AD. LDAPS or LDAP')]
  [string]
  $Protocol
  )
    $ErrorActionPreference="Stop"

    if ($Protocol.ToLower() -eq "ldap") {
      Write-Host "Adding the LDAP Identity Source..."
      try {
        $ExternalSource = 
          Add-LDAPIdentitySource `
              -Name $Name `
              -DomainName $DomainName `
              -DomainAlias $DomainAlias `
              -PrimaryUrl $PrimaryUrl `
              -SecondaryUrl $SecondaryUrl `
              -BaseDNUsers $BaseDNUsers `
              -BaseDNGroups $BaseDNGroups `
              -Username $Username `
              -Password $Password `
              -ServerType 'ActiveDirectory'
      } catch {
        Write-Error "Error adding LDAP IdentitySource: " + $_.Exception
        return $_.Exception
      }
  } elseif ($Protocol.ToLower() -eq "ldaps") {
    if ($CertificatesSAS.count -eq 0) {
      Write-Error "If adding an LDAPS identity source, please ensure you pass in at least one certificate"
      return "Failed to add LDAPS source"
    }
    $DestinationFileArray=@()
    $Index = 1
    foreach ($CertSas in $CertificatesSAS) {
      Write-Host "Downloading Cert $Index"
      $CertLocation = "./cert" + $Index + ".cer"
      $Index = $Index + 1
      try
      {
          $Response = Invoke-WebRequest -Uri $CertSas -OutFile $CertLocation
          # This will only execute if the Invoke-WebRequest is successful.
          $StatusCode = $Response.StatusCode
          Write-Host("Certificate downloaded. $StatusCode")
          $DestinationFileArray += $CertLocation
      }
      catch
      {
          $StatusCode = $_.Exception.Response.StatusCode.value__
          return ("Failed to download: " + $_.Exception)
      }
    }
    Write-Host $DestinationFileArray
    Write-Host "Adding the LDAPS Identity Source..."
    try {
    $ExternalSource = 
        Add-LDAPIdentitySource `
            -Name $Name `
            -DomainName $DomainName `
            -DomainAlias $DomainAlias `
            -PrimaryUrl $PrimaryUrl `
            -SecondaryUrl $SecondaryUrl `
            -BaseDNUsers $BaseDNUsers `
            -BaseDNGroups $BaseDNGroups `
            -Username $Username `
            -Password $Password `
            -ServerType 'ActiveDirectory' `
            -Certificates $DestinationFileArray
    } catch {
      Write-Error "Error adding LDAPS Identity Source: " + $_.Exception
      return $_.Exception
    }
  } Else {
    return 'Please select either LDAP or LDAPS with "-Protocol LDAP" or "-Protocol LDAPS"'
  }
  Write-Host $ExternalSource
  return (Get-IdentitySource -External -ErrorAction Continue)
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
    $ErrorActionPreference="Stop"

    $DrsVmHostGroupName = $DrsGroupName + "Host"
    Write-Host "Creating DRS Cluster group " + $DrsGroupName + " for the VMs: " $VMList
    New-DrsClusterGroup -Name $DrsGroupName -VM $VMList -Cluster $Cluster
    Write-Host "Creating DRS Cluster group " + $DrsVmHostGroupName + " for the VMHosts: " $VMHostList
    New-DrsClusterGroup -Name $DrsVmHostGroupName -VMHost $VMHostList -Cluster $Cluster
    Write-Host "Creating ShouldRunOn DRS Rule " + $DrsRuleName + " on cluster " $Cluster
    $result = New-DrsVMHostRule -Name $DrsRuleName -Cluster $Cluster -VMGroup $DrsGroupName -VMHostGroup $DrsVmHostGroupName -Type "ShouldRunOn"
    Get-DrsVMHostRule -Type "ShouldRunOn" -ErrorAction Continue
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
      Mandatory = $false,
      HelpMessage='List of the VMs to add to the VM group')]
    [string[]]
    $VMList,

    [Parameter(
      Mandatory = $false,
      HelpMessage='List of the VMHosts to add to the VMHost group')]
    [string[]]
    $VMHostList,

    [Parameter(
      Mandatory = $true,
      HelpMessage='Action to perform: Either "add" or "remove"')]
    [ValidateNotNullOrEmpty()]
    [string]
    $Action
  )
    $ErrorActionPreference="Stop"

    If ($VMList -And $VMHostList) {
      $result = Write-Output "Nothing done. Please select with either -VMHostList or -VMHost, not both."
      return $result
    } ElseIf ($VMList) {
      If ($Action.ToLower() -eq "add") {
        Write-Host "Adding VMs to the DrsClusterGroup..."
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Add -Confirm
      } ElseIf ($Action.ToLower() -eq "remove") {
        Write-Host "Removing VMs from the DrsClusterGroup..."
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Remove -Confirm
      } Else {
        $result = Write-Output "Nothing done. Please select with either -Action Add or -Action Remove"
      }
      Write-Output (Get-DrsClusterGroup -Type "VMGroup")
      return $result
    } ElseIf ($VMHostList) {
      If ($Action.ToLower() -eq "add") {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Add -Confirm
      } ElseIf ($Action.ToLower() -eq "remove") {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Remove -Confirm
      }
      Write-Output (Get-DrsClusterGroup -Type "VMHostGroup")
      return $result
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
      $ErrorActionPreference="Stop"
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

    Get-DrsVMHostRule -Type "ShouldRunOn"
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
    $ErrorActionPreference="Stop"
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