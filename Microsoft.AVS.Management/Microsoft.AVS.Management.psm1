#Requires -Modules PowerShellGet
#Requires -Version 5.0

<#
AVSAttribute applied to a commandlet function indicates:
- whether the SDDC should be marked as Building while the function executes.
- default timeout for the commandlet, maximum: 3h.
AVS SDDC in Building state prevents other changes from being made to the SDDC until the function completes/fails. 
#>
class AVSAttribute : Attribute {
    [bool]$UpdatesSDDC = $false
    [TimeSpan]$Timeout
    AVSAttribute($timeoutMinutes) { $this.Timeout = New-TimeSpan -Minutes $timeoutMinutes }
}

<#
=======================================================================================================
    AUTHOR:  David Becher
    DATE:    4/22/2021
    Version: 1.0.0
    Comment: Cmdlets for various administrative functions of Azure VMWare Solution products
    Callouts: This script will require the powershell session running it to be able to authenticate to azure to pull secrets from key vault, will need service principal? Also make sure we don't allow code injections  
========================================================================================================
#>

<#
    .Synopsis
     (NOT RECOMMENDED -> Use New-AvsLDAPSIdentitySource) Allow customers to add an external identity source (Active Directory over LDAP) for use with single sign on to vCenter. Prefaced by Connect-SsoAdminServer

    .Parameter Name
     The user-friendly name the external AD will be given in vCenter

    .Parameter DomainName
     Domain name of the external active directory, e.g. myactivedirectory.local

    .Parameter DomainAlias 
     Domain alias of the external active directory, e.g. myactivedirectory

    .Parameter PrimaryUrl
     Url of the primary ldap server to attempt to connect to, e.g. ldap://myadserver.local:389
    
    .Parameter SecondaryUrl 
     Url of the fallback ldap server to attempt to connect to, e.g. ldap://myadserver.local:389

    .Parameter BaseDNUsers 
     Base Distinguished Name for users, e.g. "dc=myadserver,dc=local"

    .Parameter BaseDNGroups
     Base Distinguished Name for groups, e.g. "dc=myadserver,dc=local"

    .Parameter Credential 
     Credential to login to the LDAP server (NOT cloudAdmin) in the form of a username/password credential

    .Parameter GroupName
     A group in the external identity source to give CloudAdmins access to

    .Example 
    # Add the domain server named "myserver.local" to vCenter
    Add-AvsLDAPIdentitySource -Name 'myserver' -DomainName 'myserver.local' -DomainAlias 'myserver' -PrimaryUrl 'ldap://10.40.0.5:389' -BaseDNUsers 'dc=myserver, dc=local' -BaseDNGroups 'dc=myserver, dc=local'
#>
function New-AvsLDAPIdentitySource {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User-Friendly name to store in vCenter')]
        [ValidateNotNull()]
        [string]
        $Name,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Full DomainName: adserver.local')]
        [ValidateNotNull()]
        [string]
        $DomainName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'DomainAlias: adserver')]
        [string]
        $DomainAlias,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'URL of your AD Server: ldaps://yourserver:636')]
        [ValidateScript( {
                if ($_ -match 'ldap:.*((389)|(636)|(3268)(3269))') {
                    $true
                }
                else {
                    Write-Error "$_ is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldap:" -ErrorAction Stop
                }
            })]
        [string]
        $PrimaryUrl,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Optional: URL of a backup server')]
        [ValidateScript( {
                if ($_ -match 'ldap:.*((389)|(636)|(3268)(3269))') {
                    $true
                }
                else {
                    Write-Error "$_ is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldap:" -ErrorAction Stop
                }
            })]
        [string]
        $SecondaryUrl,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'BaseDNGroups, "DC=name, DC=name"')]
        [ValidateNotNull()]
        [string]
        $BaseDNUsers,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'BaseDNGroups, "DC=name, DC=name"')]
        [ValidateNotNull()]
        [string]
        $BaseDNGroups,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "Credential for the LDAP server")]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter (
            Mandatory = $false,
            HelpMessage = 'A group in the external identity source to give CloudAdmins access')]
        [string]
        $GroupName
    )
    $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Continue
    if ($null -ne $ExternalIdentitySources) {
        Write-Host "Checking to see if identity source already exists..."
        if ($DomainName -eq $($ExternalIdentitySource.Name)) {
            Write-Error "Already have an external identity source with the same name: $($ExternalIdentitySources.Name). If only trying to add a group to this Identity Source, use Add-GroupToCloudAdmins" -ErrorAction Continue
            Write-Error $($ExternalIdentitySources | Format-List | Out-String) -ErrorAction Stop
        }
        else {
            Write-Warning "Identity source already exists, but has a different name. Continuing..."
            Write-Warning "$($ExternalIdentitySources | Format-List | Out-String)"
        }
    }
    else {
        Write-Host "No existing external identity sources found."
    }

    $Password = $Credential.GetNetworkCredential().Password
    Add-LDAPIdentitySource `
        -Name $Name `
        -DomainName $DomainName `
        -DomainAlias $DomainAlias `
        -PrimaryUrl $PrimaryUrl `
        -SecondaryUrl $SecondaryUrl `
        -BaseDNUsers $BaseDNUsers `
        -BaseDNGroups $BaseDNGroups `
        -Username $Credential.UserName `
        -Password $Password `
        -ServerType 'ActiveDirectory' -ErrorAction Stop
    $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Continue
    $ExternalIdentitySources | Format-List | Out-String

    if ($PSBoundParameters.ContainsKey('GroupName')) {
        Write-Host "GroupName passed in: $GroupName"
        Write-Host "Attempting to add group $GroupName to CloudAdmins..."
        Add-GroupToCloudAdmins -GroupName $GroupName -ErrorAction Stop
    }
}

<#
    .Synopsis
     Allow customers to add an LDAPS Secure external identity source (Active Directory over LDAP) for use with single sign on to vCenter. Prefaced by Connect-SsoAdminServer

    .Parameter Name
     The user-friendly name the external AD will be given in vCenter

    .Parameter DomainName
     Domain name of the external active directory, e.g. myactivedirectory.local

    .Parameter DomainAlias 
     Domain alias of the external active directory, e.g. myactivedirectory

    .Parameter PrimaryUrl
     Url of the primary ldap server to attempt to connect to, e.g. ldap://myadserver.local:389
    
    .Parameter SecondaryUrl 
     Url of the fallback ldap server to attempt to connect to, e.g. ldap://myadserver.local:389

    .Parameter BaseDNUsers 
     Base Distinguished Name for users, e.g. "dc=myadserver,dc=local"

    .Parameter BaseDNGroups
     Base Distinguished Name for groups, e.g. "dc=myadserver,dc=local"

    .Parameter Credential 
     Credential to login to the LDAP server (NOT cloudAdmin) in the form of a username/password credential

    .Parameter CertificatesSAS
     An array of Shared Access Signature strings to the certificates required to connect to the external active directory, if using LDAPS

    .Parameter GroupName
     A group in the external identity source to give CloudAdmins access to

    .Example 
    # Add the domain server named "myserver.local" to vCenter
    Add-AvsLDAPSIdentitySource -Name 'myserver' -DomainName 'myserver.local' -DomainAlias 'myserver' -PrimaryUrl 'ldaps://10.40.0.5:636' -BaseDNUsers 'dc=myserver, dc=local' -BaseDNGroups 'dc=myserver, dc=local' -Username 'myserver@myserver.local' -Password 'PlaceholderPassword' -CertificatesSAS 'https://sharedaccessstring.path/accesskey' -Protocol LDAPS
#>
function New-AvsLDAPSIdentitySource {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User-Friendly name to store in vCenter')]
        [ValidateNotNull()]
        [string]
        $Name,
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Full DomainName: adserver.local')]
        [ValidateNotNull()]
        [string]
        $DomainName,
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'DomainAlias: adserver')]
        [string]
        $DomainAlias,
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'URL of your AD Server: ldaps://yourserver:636')]
        [ValidateScript( {
                if ($_ -match 'ldaps:.*((389)|(636)|(3268)(3269))') {
                    $true
                }
                else {
                    Write-Error "$_ is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldaps:" -ErrorAction Stop
                }
            })]
        [string]
        $PrimaryUrl,
  
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Optional: URL of a backup server')]
        [ValidateScript( {
                if ($_ -match 'ldaps:.*((389)|(636)|(3268)(3269))') {
                    $true
                }
                else {
                    Write-Error "$_ is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldaps:" -ErrorAction Stop
                }
            })]
        [string]
        $SecondaryUrl,
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'BaseDNGroups, "DC=name, DC=name"')]
        [ValidateNotNull()]
        [string]
        $BaseDNUsers,
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'BaseDNGroups, "DC=name, DC=name"')]
        [ValidateNotNull()]
        [string]
        $BaseDNGroups,
  
        [Parameter(Mandatory = $true,
            HelpMessage = "Credential for the LDAP server")]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'A comma-delimited list of SAS path URI to Certificates for authentication. Ensure permissions to read included. To generate, place the certificates in any storage account blob and then right click the cert and generate SAS')]
        [System.Security.SecureString]
        $CertificatesSAS,

        [Parameter (
            Mandatory = $false,
            HelpMessage = 'A group in the external identity source to give CloudAdmins access')]
        [string]
        $GroupName
        
    )
    $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Continue
    if ($null -ne $ExternalIdentitySources) {
        Write-Host "Checking to see if identity source already exists..."
        if ($DomainName -eq $($ExternalIdentitySource.Name)) {
            Write-Error "Already have an external identity source with the same name: $($ExternalIdentitySources.Name). If only trying to add a group to this Identity Source, use Add-GroupToCloudAdmins" -ErrorAction Continue
            Write-Error $($ExternalIdentitySources | Format-List | Out-String) -ErrorAction Stop
        }
        else {
            Write-Warning "Identity source already exists, but has a different name. Continuing..."
            Write-Warning "$($ExternalIdentitySources | Format-List | Out-String)"
        }
    }
    else {
        Write-Host "No existing external identity sources found."
    }

    $Password = $Credential.GetNetworkCredential().Password
    [string] $CertificatesSASPlainString = ConvertFrom-SecureString -SecureString $CertificatesSAS -AsPlainText
    [System.StringSplitOptions] $options = [System.StringSplitOptions]::RemoveEmptyEntries -bor [System.StringSplitOptions]::TrimEntries
    [string[]] $CertificatesSASList = $CertificatesSASPlainString.Split(",", $options)
    Write-Host "Number of Certs passed $($CertificatesSASList.count)"
    if ($CertificatesSASList.count -eq 0) {
        Write-Error "If adding an LDAPS identity source, please ensure you pass in at least one certificate" -ErrorAction Stop
    }
    $DestinationFileArray = @()
    $Index = 1
    foreach ($CertSas in $CertificatesSASList) {
        Write-Host "Downloading Cert $Index from $CertSas"
        $CertDir = $pwd.Path
        $CertLocation = "$CertDir/cert$Index.cer"
        $Index = $Index + 1
        try {
            $Response = Invoke-WebRequest -Uri $CertSas -OutFile $CertLocation
            $StatusCode = $Response.StatusCode
            Write-Host("Certificate downloaded. $StatusCode")
            $DestinationFileArray += $CertLocation
        }
        catch {
            Write-Error "Ensure the SAS string [$CertSAS] is still valid" -ErrorAction Continue
            Write-Error $PSItem.Exception.Message -ErrorAction Continue
            Write-Error "Failed to download certificate ($Index-1)" -ErrorAction Stop
        }
    }
    Write-Host "Number of certificates downloaded: $($DestinationFileArray.count)"
    Write-Host "Adding the LDAPS Identity Source..."
    Add-LDAPIdentitySource `
        -Name $Name `
        -DomainName $DomainName `
        -DomainAlias $DomainAlias `
        -PrimaryUrl $PrimaryUrl `
        -SecondaryUrl $SecondaryUrl `
        -BaseDNUsers $BaseDNUsers `
        -BaseDNGroups $BaseDNGroups `
        -Username $Credential.UserName `
        -Password $Password `
        -ServerType 'ActiveDirectory' `
        -Certificates $DestinationFileArray -ErrorAction Stop
    $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Continue
    $ExternalIdentitySources | Format-List | Out-String

    if ($PSBoundParameters.ContainsKey('GroupName')) {
        Write-Host "GroupName passed in: $GroupName"
        Write-Host "Attempting to add group $GroupName to CloudAdmins..."
        Add-GroupToCloudAdmins -GroupName $GroupName -ErrorAction Stop
    }
}

<#
    .Synopsis
     Removes all external identity sources 
#>
function Get-ExternalIdentitySources {
    [AVSAttribute(3, UpdatesSDDC = $false)]

    $ExternalSource = Get-IdentitySource -External
    if ($null -eq $ExternalSource) {
        Write-Output "No external identity sources found."
        return
    }
    else {
        $ExternalSource | Format-List | Out-String 
    }
}

<#
    .Synopsis
     Removes all external identity sources 
#>
function Remove-ExternalIdentitySources {
    [AVSAttribute(5, UpdatesSDDC = $false)]

    $ExternalSource = Get-IdentitySource -External
    if ($null -eq $ExternalSource) {
        Write-Output "No external identity sources found to remove. Nothing done"
        return
    }
    else {
        Remove-IdentitySource -IdentitySource $ExternalSource -ErrorAction Stop
        Write-Output "Identity source $($ExternalSource.Name) removed."
    }
}

<#
    .Synopsis
     Add an external identity group from the external identity to the CloudAdmins group

    .Parameter GroupName
     Name of the group to be added to CloudAdmins. 

    .Example 
    # Add the group named vsphere-admins to CloudAdmins
     Add-GroupToCloudAdmins -GroupName 'vpshere-admins'
#>
function Add-GroupToCloudAdmins {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the group to add to CloudAdmin')]
        [ValidateNotNull()]
        [string]
        $GroupName
    )
    $ExternalSource
    $Domain 
    $GroupToAdd

    try {
        $ExternalSource = Get-IdentitySource -External -ErrorAction Stop
        $Domain = $ExternalSource.Name
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get external identity source" -ErrorAction Stop
    }
    
    if ($null -eq $ExternalSource -or $null -eq $Domain) {
        Write-Error "No external identity source found $Domain. Please run New-AvsLDAPSIdentitySource first" -ErrorAction Stop
    }
    else {
        Write-Host "Searching $($ExternalSource.Name) for $GroupName...."
    }
    
    try {
        $GroupToAdd = Get-SsoGroup -Name $GroupName -Domain $Domain -ErrorAction Stop 
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get group $GroupName from $Domain" -ErrorAction Stop
    }

    if ($null -eq $GroupToAdd) {
        Write-Error "$GroupName was not found in $Domain. Please ensure that the group is spelled correctly" -ErrorAction Stop
    }
    else {
        Write-Host "Adding $GroupToAdd to CloudAdmins...."
    }

    $CloudAdmins = Get-SsoGroup -Name 'CloudAdmins' -Domain 'vsphere.local'
    if ($null -eq $CloudAdmins) {
        Write-Error "Internal Error fetching CloudAdmins group. Contact support" -ErrorAction Stop
    }

    try {
        Write-Host "Adding group $GroupName to CloudAdmins..."
        Add-GroupToSsoGroup -Group $GroupToAdd -TargetGroup $CloudAdmins -ErrorAction Stop
    }
    catch {
        $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
        Write-Error "Cloud Admin Members: $CloudAdminMembers" -ErrorAction Continue
        Write-Error "Unable to add group to CloudAdmins. It may already have been added. Error: $($PSItem.Exception.Message)" -ErrorAction Stop
    }
   
    Write-Host "Successfully added $GroupName to CloudAdmins."
    $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
    Write-Output "Cloud Admin Members: $CloudAdminMembers"
}

<#
    .Synopsis
     Remove a previously added external identity group from the cloud admin group

    .Parameter GroupName
     Name of the group to be removed from CloudAdmins. 

    .Example 
    # Remove the group named vsphere-admins from CloudAdmins
     Remove-GroupFromCloudAdmins -GroupName 'vpshere-admins'
#>
function Remove-GroupFromCloudAdmins {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the group to remove from CloudAdmin')]
        [ValidateNotNull()]
        [string]
        $GroupName
    )
    $ExternalSource
    $Domain 
    $GroupToRemove

    try {
        $ExternalSource = Get-IdentitySource -External -ErrorAction Stop
        $Domain = $ExternalSource.Name
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get external identity source" -ErrorAction Stop
    }
    
    if ($null -eq $ExternalSource -or $null -eq $Domain) {
        Write-Error "No external identity source found: $Domain. Please run New-AvsLDAPSIdentitySource first" -ErrorAction Stop
    }
    else {
        Write-Host "Searching $($ExternalSource.Name) for $GroupName...."
    }
    
    try {
        $GroupToRemove = Get-SsoGroup -Name $GroupName -Domain $Domain -ErrorAction Stop 
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get group $GroupName from $Domain" -ErrorAction Stop
    }

    if ($null -eq $GroupToRemove) {
        Write-Error "$GroupName was not found in $Domain. Please ensure that the group is spelled correctly" -ErrorAction Stop
    }
    else {
        Write-Host "Removing $GroupToRemove from CloudAdmins...."
    }

    $CloudAdmins = Get-SsoGroup -Name 'CloudAdmins' -Domain 'vsphere.local'
    if ($null -eq $CloudAdmins) {
        Write-Error "Internal Error fetching CloudAdmins group. Contact support" -ErrorAction Stop
    }

    try {
        Remove-GroupFromSsoGroup -Group $GroupToRemove -TargetGroup $CloudAdmins -ErrorAction Stop
    }
    catch {
        $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
        Write-Error "Current Cloud Admin Members: $CloudAdminMembers" -ErrorAction Continue
        Write-Error "Unable to remove group from CloudAdmins. Is it already there? Error: $($PSItem.Exception.Message)" -ErrorAction Stop
    }
    
    Write-Information "Group $GroupName successfully removed from CloudAdmins."
    $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
    Write-Output "Current Cloud Admin Members: $CloudAdminMembers"
}


<#
    .Synopsis
     Creates a Drs Cluster Host Group, a Drs Cluster VM Group, and a Drs Cluster Virtual Machine to Host Rule between the two

    .Parameter DrsRuleName
     User-Friendly Name of the Drs VMHost Rule to be created. 
    
    .Parameter DrsGroupName
     User-Friendly prefix of the two Drs Cluster Groups to be created. For example, -DrsGroupName "mygroup" will create a VM group called "mygroup" and a VMHost group called "mygrouphost" 

    .Parameter Cluster
     Name of the cluster to create the two groups and rule on. The VMs and VMHosts' must be on this cluster

    .Parameter VMList
     A comma delimited list with the names of the VMs to put in the Drs group 

    .Parameter VMHostList
     A comma delimited list with the names of the VMHosts' to put in the Drs group 

    .Example 
    # Create a should run rule named MyDrsRule on Cluster-1 Hosts using the listed VM's and VMHosts
    New-AvsDrsElevationRule -DrsGroupName "MyDrsGroup" -DrsRuleName "MyDrsRule" -Cluster "Cluster-1" -VMList "vm1", "vm2" -VMHostList "esx01", "esx02"
#>
function New-AvsDrsElevationRule {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User-Friendly name of the Drs rule to create')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DrsRuleName,
    
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User-Friendly name of the Drs group to create')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DrsGroupName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Cluster to create the rule and group on')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Cluster,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'A comma-delimited list to add to the VM group')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMList,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'A comma-delimited list of the VMHosts to add to the VMHost group')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMHostList
    )

    [System.StringSplitOptions] $options = [System.StringSplitOptions]::RemoveEmptyEntries -bor [System.StringSplitOptions]::TrimEntries
    [string[]] $VMList = $VMList.Split(",", $options)
    [string[]] $VMHostList = $VMHostList.Split(",", $options)
    $DrsVmHostGroupName = $DrsGroupName + "Host"
    Write-Host "VMs Passed in: $($VMList.count)"
    Write-Host "Creating DRS Cluster group $DrsGroupName for the $($VMList.count) VMs $VMList"
    New-DrsClusterGroup -Name $DrsGroupName -VM $VMList -Cluster $Cluster -ErrorAction Stop
    Write-Host "VMHosts Passed in: $($VMHostList.count)"
    Write-Host "Creating DRS Cluster group $DrsVmHostGroupName for the $($VMHostList.count) VMHosts: $VMHostList"
    New-DrsClusterGroup -Name $DrsVmHostGroupName -VMHost $VMHostList -Cluster $Cluster -ErrorAction Stop
    Write-Host "Creating ShouldRunOn DRS Rule $DrsRuleName on cluster $Cluster"
    New-DrsVMHostRule -Name $DrsRuleName -Cluster $Cluster -VMGroup $DrsGroupName -VMHostGroup $DrsVmHostGroupName -Type "ShouldRunOn" -ErrorAction Stop
    $currentRule = Get-DrsVMHostRule -Type "ShouldRunOn" -ErrorAction Continue
    Write-Output $currentRule
}

<#
    .Synopsis
     Edits a VM Drs Cluster Group by adding or removing VMs to or from the group

    .Parameter DrsGroupName
     Existing VM Drs Cluster Group to edit

    .Parameter VMList
     A comma delimited list with the names of the VMs to add or remove to/from the Drs group 

    .Parameter Action
     The action to perform, either "add" or "remove" the VMHosts specified to/from the DrsGroup

    .Example 
    # Edit an existing drs group named "MyDrsGroup" on Cluster-1 Hosts adding the listed VM's '
    Set-AvsDrsVMClusterGroup -DrsGroupName "MyDrsGroup" -Cluster "Cluster-1" -VMList "vm1", "vm2"  -Action "add"
#>
function Set-AvsDrsVMClusterGroup {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (   
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the Drs group to edit')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DrsGroupName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'A comma-delimited list of the VMs to add to the VM group')]
        [string]
        $VMList,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Action to perform: Either "add" or "remove"')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Action
    )
    [System.StringSplitOptions] $options = [System.StringSplitOptions]::RemoveEmptyEntries -bor [System.StringSplitOptions]::TrimEntries
    [string[]] $VMList = $VMList.Split(",", $options)
    [string] $groupType = (Get-DrsClusterGroup -Name $DrsGroupName).GroupType.ToString()
    Write-Host "The group type for $DrsGroupName is $groupType"
    If ($groupType -eq "VMHostGroup") {
        Get-DrsClusterGroup
        Write-Warning "$DrsGroupName is a $groupType and cannot be modified with VMs. Please validate that you're using the correct cmdlet. Did you mean Set-AvsDrsVMHostClusterGroup?"
        return 
    }

    If ($Action -eq "add") {
        Write-Host "Adding VMs to the DrsClusterGroup..."
        Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Add -ErrorAction Stop
        Write-Output $(Get-DrsClusterGroup -Name $DrsGroupName)
    }
    ElseIf ($Action -eq "remove") {
        Write-Host "Removing VMs from the DrsClusterGroup..."
        Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VM $VMList -Remove -ErrorAction Stop
        Write-Output $(Get-DrsClusterGroup -Name $DrsGroupName)
    }
    Else {
        Write-Warning "Nothing done. Please select with either -Action Add or -Action Remove"
    }
}

<#
    .Synopsis
     Edits a VMHost Drs Cluster Group by adding or removing VMHosts to or from the group

    .Parameter DrsGroupName
     Existing VMHost Drs Cluster Group to edit

    .Parameter VMHostList
     A comma delimited list with the names of the VMHosts' to add or remove to/from the Drs group 

    .Parameter Action
     The action to perform, either "add" or "remove" the VMHosts' specified to/from the DrsGroup

    .Example 
    # Edit an existing drs group named "MyDrsGroup" on Cluster-1 Hosts removing the listed VM Hosts '
    Set-AvsDrsVMHostClusterGroup -DrsGroupName "MyDrsGroup" -Cluster "Cluster-1" -VMHostList "vmHost1", "vmHost2"  -Action "remove"
#>
function Set-AvsDrsVMHostClusterGroup {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (   
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the Drs group to edit')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DrsGroupName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'A comma-delimited list of the VMHosts to add to the VMHost group')]
        [string]
        $VMHostList,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Action to perform: Either "add" or "remove"')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Action
    )

    [System.StringSplitOptions] $options = [System.StringSplitOptions]::RemoveEmptyEntries -bor [System.StringSplitOptions]::TrimEntries
    [string[]] $VMHostList = $VMHostList.Split(",", $options)
    [string] $groupType = (Get-DrsClusterGroup -Name $DrsGroupName).GroupType.ToString()
    Write-Host "The group type for $DrsGroupName is $groupType"
    If ($groupType -eq "VMGroup") {
        Get-DrsClusterGroup
        Write-Warning "$DrsGroupName is a $groupType and cannot be modified with VMHosts. Please validate that you're using the correct cmdlet. Did you mean Set-AvsDrsVMClusterGroup?"
        return 
    }

    If ($Action -eq "add") {
        Write-Host "Adding VMHosts to the DrsClusterGroup..."
        Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Add -ErrorAction Stop
        Write-Output $(Get-DrsClusterGroup -Name $DrsGroupName)
    }
    ElseIf ($Action -eq "remove") {
        Write-Host "Removing VMHosts from the DrsClusterGroup..."
        Set-DrsClusterGroup -DrsClusterGroup $DrsGroupName -VMHost $VMHostList -Remove -ErrorAction Stop
        Write-Output $(Get-DrsClusterGroup -Name $DrsGroupName)
    }
    Else {
        Write-Warning "Nothing done. Please select with either -Action Add or -Action Remove"
    }
}

<#
    .Synopsis
     Edits a Drs Elevation Rule. Allowed operations are enable/disable and renaming.

    .Parameter DrsRuleName
     Name of an exisitng Drs Rule to edit

    .Parameter Enabled
     Set to $true to enable the Drs Rule, $false to disable it

    .Parameter NewName
     If specified, the name to change the DrsRule to

    .Example 
    # Enable and change the name of a drs rule named "myDrsRule"
    Set-AvsDrsElevationRule -DrsRuleName "myDrsRule"  -Enabled $true -NewName "mynewDrsRule"
#>
function Set-AvsDrsElevationRule {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (   
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the Drs rule to edit')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DrsRuleName,
  
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Enabled switch: $true or $false')]
        [Nullable[boolean]]
        $Enabled,
  
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'New name for the Drs rule')]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewName
    )
    if ($PSBoundParameters.ContainsKey('Enabled') -And $PSBoundParameters.ContainsKey('NewName')) {
        Write-Host "Changing enabled flag to $Enabled and Name to $NewName"
        Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $Enabled -Name $NewName -ErrorAction Stop
    }
    ElseIf ($PSBoundParameters.ContainsKey('Enabled')) {
        Write-Host "Changing the enabled flag for $DrsRuleName to $Enabled"
        Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $Enabled -ErrorAction Stop
    }
    ElseIf ($PSBoundParameters.ContainsKey('NewName')) {
        Write-Host "Renaming $DrsRuleName to $NewName"
        Set-DrsVMHostRule -Rule $DrsRuleName -Name $NewName -ErrorAction Stop
    }
    Else {
        Write-Output "No parameters passed. Nothing done. Possible configuration parameters include -Enabled and -NewName"
    }
}

<#
    .Synopsis
     Gets all the storage policies available to set on a VM 
#>
function Get-StoragePolicies {
    [AVSAttribute(3, UpdatesSDDC = $False)]
    
    $StoragePolicies
    try {
        $StoragePolicies = Get-SpbmStoragePolicy -ErrorAction Stop
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get storage policies" -ErrorAction Stop
    }
    if ($null -eq $StoragePolicies) {
        Write-Host "Could not find any storage policies." 
    }
    else {
        Write-Output "Available Storage Policies:"
        $StoragePolicies | Format-List | Out-String
    }
}
  
<#
    .Synopsis
     Sets the storage policy on the VM to a predefined storage policy

    .Parameter StoragePolicyName
     Name of a storage policy to set on the specified VM. Options can be seen in vCenter.

    .Parameter VMName
     Name of the VM to set the storage policy on.

    .Example 
    # Set the storage policy on EVM02-TNT79 to RAID-1 FTT-1
    Set-AvsVMStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -VMName "EVM02-TNT79"
#>
function Set-AvsVMStoragePolicy {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $True)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the storage policy to set')]
        [ValidateNotNullOrEmpty()]
        [string]
        $StoragePolicyName,
  
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the VM to set the storage policy on')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName
    )
    Write-Host "Getting Storage Policy $StoragePolicyName"
    $StoragePolicy = Get-SpbmStoragePolicy -Name $StoragePolicyName -ErrorAction Stop
    if ($null -eq $StoragePolicy) {
        Write-Error "Could not find Storage Policy with the name $StoragePolicyName" -ErrorAction Stop 
    } 
    $VM = Get-VM $VMName
    if ($null -eq $VM) {
        Write-Error "Was not able to set the storage policy on the VM. Could not find VM with the name: $VMName" -ErrorAction Stop
    }
    Write-Host "Setting VM $VMName storage policy to $StoragePolicyName..."
    try {
        Set-VM -VM $VM -StoragePolicy $StoragePolicy -SkipHardDisks -ErrorAction Stop -Confirm:$false
    } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidVmConfig] {
        Write-Error "The selected storage policy $($StoragePolicy.Name) is not compatible with this VM. You may need more hosts: $($PSItem.Exception.Message)" -ErrorAction Stop
    } catch {
        Write-Error "Was not able to set the storage policy on the VM: $($PSItem.Exception.Message)" -ErrorAction Stop
    }
    Write-Output "Successfully set the storage policy on VM $VMName to $StoragePolicyName"
}

Export-ModuleMember -Function *