#Requires -Modules PowerShellGet
#Requires -Version 5.0

<#
=======================================================================================================
    AUTHOR:  David Becher
    DATE:    4/22/2021
    Version: 1.0
    Comment: Add an external identity source to tenant vCenter. Requires powershell to have VMware.PowerCLI, AzurePowershell, and VMware.vSphere.SsoAdminModule installed
    Callouts: This script will require the powershell session running it to be able to authenticate to azure to pull secrets from key vault, will need service principal? Also make sure we don't allow code injections  
========================================================================================================
#>

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
  [string]
  $PrimaryUrl,

  [Parameter(
    Mandatory = $false,
    HelpMessage='Optional: URL of a backup server')]
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
  $Password
  )

    $Destination="$pwd\cert.cer"
    $webRequest = [System.Net.HttpWebRequest]::Create("https://www.bing.com")
    try
    {
        #Make the request but ignore (dispose it) the response, since we only care about the service point
        $webRequest.GetResponse().Dispose()
    }
    catch [System.Net.WebException]
    {
        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure)
        {
            #We ignore trust failures, since we only want the certificate, and the service point is still populated at this point
        }
        else
        {
            #Let other exceptions bubble up, or write-error the exception and return from this method
            throw
        }
    }
    Write-Output "ServicePoint: " $webRequest.ServicePoint
    $cert = $webRequest.ServicePoint.Certificate
    Write-Output $cert
    if ($cert) {
      $bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      Set-Content -Value $bytes -AsByteStream -Path $Destination
      $ExternalSource
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
                  -Certificates $bytes
          Write-Output $ExternalSource
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
                  -Password $Password`
                  -ServerType 'ActiveDirectory'`
                  -Certificates $bytes
          Write-Output $ExternalSource
      }
      return $ExternalSource
    } else {
      Write-Output "Couldn't pull certificate from the website"
      return "Please validate the primary URL"
    }
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