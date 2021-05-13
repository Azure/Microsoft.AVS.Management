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

    .Parameter Name
     The user-friendly name the external AD will be given in vCenter

    .Parameter DomainName
     Domain name of the external active directory, e.g. myactivedirectory.local

    .Parameter DomainAlias 
     Domain alias of the external active directory, e.g. myactivedirectory

    .Parameter Protocol
     Which protocol to use to connect to the active directory, either LDAP or LDAPS.

    .Parameter CertificatesSAS
     An array of Shared Access Signature strings to the certificates required to connect to the external active directory, if using LDAPS

    .Example 
    # Add the domain server named "myserver.local" to vCenter
    Add-AvsLDAPIdentitySource -Name 'myserver' -DomainName 'myserver.local' -DomainAlias 'myserver' -PrimaryUrl 'ldaps://10.40.0.5:636' -BaseDNUsers 'dc=myserver, dc=local' -BaseDNGroups 'dc=myserver, dc=local' -Username 'myserver@myserver.local' -Password 'PlaceholderPassword' -CertificatesSAS 'https://sharedaccessstring.path/accesskey' -Protocol LDAPS
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
    if ($Protocol -eq "ldap") {
      Write-Host "Adding the LDAP Identity Source"
      if ($CertificatesSAS.count -ne 0) {
        Write-Warning "Ignoring certificates because selected protocol was LDAP"
      }
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
            -ServerType 'ActiveDirectory' -ErrorAction Stop
    } elseif ($Protocol -eq "ldaps") {
    if ($CertificatesSAS.count -eq 0) {
      Write-Error "If adding an LDAPS identity source, please ensure you pass in at least one certificate" -ErrorAction Stop
      return "Failed to add LDAPS source"
    }
    $DestinationFileArray=@()
    $Index = 1
    foreach ($CertSas in $CertificatesSAS) {
      Write-Host "Downloading Cert $Index"
      $CertDir = $pwd.Path
      $CertLocation = "$CertDir/cert$Index.cer"
      $Index = $Index + 1
      try
      {
          $Response = Invoke-WebRequest -Uri $CertSas -OutFile $CertLocation
          Write-Verbose -Message "Following lines will only execute if the download was successful"
          $StatusCode = $Response.StatusCode
          Write-Host("Certificate downloaded. $StatusCode")
          $DestinationFileArray += $CertLocation
      }
      catch
      {
          Write-Verbose "Stack Trace: $($PSItem.Exception.StackTrace)"
          Write-Verbose "InnerException: $($PSItem.Exception.InnerException)" 
          Write-Error $PSItem.Exception.Message -ErrorAction Stop
          return "Failed to download certificate ($Index-1)"
      }
    }
    Write-Verbose "Certificates: $DestinationFileArray"
    Write-Host "Adding the LDAPS Identity Source..."
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
            -Certificates $DestinationFileArray -ErrorAction Stop
  } Else {
    return 'Please select either LDAP or LDAPS with "-Protocol LDAP" or "-Protocol LDAPS"'
  }
  Write-Verbose "PowerCLI Result: $ExternalSource"
  return (Get-IdentitySource -External -ErrorAction Continue)
}

<#
    .Synopsis
     Creates a Drs Cluster Host Group, a Drs Cluster VM Group, and a Drs Cluster Virtual Machine to Host Rule between the two

    .Example 
    # Create a should run rule named MyDrsRule on Cluster-1 Hosts using the listed VM's and VMHosts
    New-AvsDrsElevationRule -DrsGroupName "MyDrsGroup" -DrsRuleName "MyDrsRule" -Cluster "Cluster-1" -VMList "vm1", "vm2" -VMHostList "esx01", "esx02"
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
    Write-Host "Creating DRS Cluster group $DrsGroupName for the VMs $VMList"
    New-DrsClusterGroup -Name $DrsGroupName -VM $VMList -Cluster $Cluster -ErrorAction Stop
    Write-Host "Creating DRS Cluster group $DrsVmHostGroupName for the VMHosts: $VMHostList"
    New-DrsClusterGroup -Name $DrsVmHostGroupName -VMHost $VMHostList -Cluster $Cluster -ErrorAction Stop
    Write-Host "Creating ShouldRunOn DRS Rule $DrsRuleName on cluster $Cluster"
    Write-Verbose "New-DrsVMHostRule -Name $DrsRuleName -Cluster $Cluster -VMGroup $DrsGroupName -VMHostGroup $DrsVmHostGroupName -Type 'ShouldRunOn'"
    $result = New-DrsVMHostRule -Name $DrsRuleName -Cluster $Cluster -VMGroup $DrsGroupName -VMHostGroup $DrsVmHostGroupName -Type "ShouldRunOn" -ErrorAction Stop
    $currentRule = Get-DrsVMHostRule -Type "ShouldRunOn" -ErrorAction Continue
    Write-Output $currentRule
    return $result 
}

<#
    .Synopsis
     Edits a Drs Cluster Group

    .Example 
    # Edit an existing drs group named "MyDrsGroup" on Cluster-1 Hosts adding the listed VM's '
    Set-AvsDrsClusterGroup -DrsGroupName "MyDrsGroup" -Cluster "Cluster-1" -VMList "vm1", "vm2"  -Action "add"
    # Edit an existing drs group named "MyDrsGroup" on Cluster-1 Hosts removing the listed VM Hosts '
    Set-AvsDrsClusterGroup -DrsGroupName "MyDrsGroup" -Cluster "Cluster-1" -VMHostList "vmHost1", "vmHost2"  -Action "remove"
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

    If ($VMList -And $VMHostList) {
      $result = Write-Output "Nothing done. Please select with either -VMHostList or -VMHost, not both."
      return $result
    } ElseIf ($VMList) {
      If ($Action -eq "add") {
        Write-Host "Adding VMs to the DrsClusterGroup..."
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Add -Confirm -ErrorAction Stop
      } ElseIf ($Action -eq "remove") {
        Write-Host "Removing VMs from the DrsClusterGroup..."
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Remove -Confirm -ErrorAction Stop
      } Else {
        $result = Write-Output "Nothing done. Please select with either -Action Add or -Action Remove"
      }
      Write-Output (Get-DrsClusterGroup -Type "VMGroup")
      return $result
    } ElseIf ($VMHostList) {
      If ($Action -eq "add") {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Add -Confirm -ErrorAction Stop
      } ElseIf ($Action -eq "remove") {
        $result = Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Remove -Confirm -ErrorAction Stop
      } Else {
        $result = Write-Output "Nothing done. Please select with either -Action Add or -Action Remove"
      }
      Write-Output (Get-DrsClusterGroup -Type "VMHostGroup")
      return $result
    } Else {
      $result = Write-Output "Nothing done. Please select with either -VMHostList or -VMHost."
      return $result
    }
}

<#
    .Synopsis
     Edits a Drs Elevation Rule. Allowed operations are enable/disable and renaming.

    .Example 
    # Enable and change the name of a drs rule named "myDrsRule"
    Set-AvsDrsElevationRule -DrsRuleName "myDrsRule"  -Enabled $true -NewName "mynewDrsRule"
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
      $NewName
  )
      Write-Verbose "Enabled is ne null: ($Enabled -ne $null)"
      if (($Enabled -ne $null) -And $NewName) {
        Write-Host "Changing enabled flag to $Enabled and Name to $NewName"
        Write-Verbose "$result = Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $true -Name $NewName"
        Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $true -Name $NewName -ErrorAction Stop
      } ElseIf ($Enabled -ne $null) {
        Write-Host "Changing the enabled flag for $DrsRuleName to $Enabled"
        Write-Verbose "$result = Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $true"
        Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $Enabled -ErrorAction Stop
      } ElseIf ($Name) {
        Write-Host "Renaming $DrsRuleName to $NewName"
        Write-Verbose "Set-DrsVMHostRule -Rule $DrsRuleName -Name $NewName"
        Set-DrsVMHostRule -Rule $DrsRuleName -Name $NewName -ErrorAction Stop
      } Else {
        Write-Output "Nothing done."
      }

    $result = Get-DrsVMHostRule -Type "ShouldRunOn"
    Write-Output $result
    return $result
    
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
      Write-Output $result
    } ElseIf ($VMName -ne $null) {
      Write-Verbose (Get-SbpmStoragePolicy)
      $storagepolicy = Get-SpbmStoragePolicy -Name $StoragePolicyName -ErrorAction Stop
      $result = Set-VM $VMName -StoragePolicy $storagepolicy -SkipHardDisks -ErrorAction Stop
      return $result
    } Else {
      $result = "Cluster editing currently not supported"
      Write-Output $result
    }
    return $result
}

Export-ModuleMember -Function *