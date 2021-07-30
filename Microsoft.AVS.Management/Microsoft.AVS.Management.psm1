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

<# List of internal AVS management VMs that should not be touched by customer-facing scripts #>
function Get-ProtectedVMs {
    $ParentPool =  Get-ResourcePool -Name Resources | Where-Object {$_.ParentId -match 'ClusterComputeResource.+'}
    $MGMTPool = Get-ResourcePool -Name MGMT-ResourcePool | Where-Object {$_.Parent -eq $ParentPool}
    $ProtectedVMs = $MGMTPool | Get-VM | Where-Object {$_.Name -match "^TNT.+"}
    return $ProtectedVMs
}

<# List of internal AVS management networks that should not be touched by customer-facing scripts #>
function Get-ProtectedNetworks {
    Get-VirtualNetwork | Where-Object {$_.Name -imatch "^((TNT.+?)|((HCX_|ESX_)?Mgmt)|(Replication)|(vMotion)|(vSAN))$"}
}

<#
    .Synopsis
     Not Recommended (use New-AvsLDAPSIdentitySource): Add a not secure external identity source (Active Directory over LDAP) for use with vCenter Single Sign-On.

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
     A group in the external identity source to give CloudAdmins access to formatted in the short version - i.e. group-to-give-access

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
        if ($DomainName.trim() -eq $($ExternalIdentitySources.Name.trim())) {
            Write-Error "Already have an external identity source with the same name: $($ExternalIdentitySources.Name). If only trying to add a group to this Identity Source, use Add-GroupToCloudAdmins" -ErrorAction Continue
            Write-Error $($ExternalIdentitySources | Format-List | Out-String) -ErrorAction Stop
        }
        else {
            Write-Warning "$($ExternalIdentitySources | Format-List | Out-String)"
            Write-Warning "Identity source already exists, but has a different name. Continuing..."
        }
    }
    else {
        Write-Host "No existing external identity sources found."
    }

    $Password = $Credential.GetNetworkCredential().Password
    Write-Host "Adding $DomainName..."
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
        Add-GroupToCloudAdmins -GroupName $GroupName -Domain $DomainName -ErrorAction Stop
    }
}

<#
    .Synopsis
     Recommended: Add a secure external identity source (Active Directory over LDAPS) for use with vCenter Single Sign-On.

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
     A group in the external identity source to give CloudAdmins access to formatted in the short version - i.e. group-to-give-access

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
        if ($DomainName.trim() -eq $($ExternalIdentitySources.Name.trim())) {
            Write-Error "Already have an external identity source with the same name: $($ExternalIdentitySources.Name). If only trying to add a group to this Identity Source, use Add-GroupToCloudAdmins" -ErrorAction Continue
            Write-Error $($ExternalIdentitySources | Format-List | Out-String) -ErrorAction Stop
        }
        else {
            Write-Warning "$($ExternalIdentitySources | Format-List | Out-String)"
            Write-Warning "Identity source already exists, but has a different name. Continuing..."
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
    if ($PSBoundParameters.ContainsKey('SecondaryUrl') -and $CertificatesSASList.count -lt 2) {
        Write-Error "If passing in a secondary/fallback URL, ensure that at least two certificates are passed." -ErrorAction Stop
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
        Add-GroupToCloudAdmins -GroupName $GroupName -Domain $DomainName -ErrorAction Stop
    }
}

<#
    .Synopsis
     Gets all external identity sources 
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
    
    .Parameter Name
     The name of the external identity source to remove. If none provided, will attempt to remove all external identity sources.
#>
function Remove-ExternalIdentitySources {
    [AVSAttribute(5, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]
        $Name
    )

    $ExternalSource = Get-IdentitySource -External
    if ($null -eq $ExternalSource) {
        Write-Output "No external identity sources found to remove. Nothing done"
        return
    }
    else {
        if (-Not ($PSBoundParameters.ContainsKey('Name'))) {
            foreach ($AD in $ExternalSource) {
                Remove-IdentitySource -IdentitySource $AD -ErrorAction Stop
                Write-Output "Identity source $($AD.Name) removed."
            }
        }
        else {
            $FoundMatch = $false
            foreach ($AD in $ExternalSource) {
                if ($AD.Name -eq $Name) {
                    Remove-IdentitySource -IdentitySource $AD -ErrorAction Stop
                    Write-Output "Identity source $($AD.Name) removed."
                    $FoundMatch = $true
                }
            }
            if (-Not $FoundMatch) { Write-Output "No external identity source found that matches $Name. Nothing done." }
        }
    }
}

<#
    .Synopsis
     Add a group from the external identity to the CloudAdmins group

    .Parameter GroupName
     Name of the group to be added to the CloudAdmins group. For example, `vsphere-admins`, without the domain appended

    .Parameter Domain
     Name of the domain that GroupName is in. If not provided, will attempt to locate the group in all the configured active directories

    .Example 
    # Add the group named vsphere-admins to CloudAdmins
     Add-GroupToCloudAdmins -GroupName 'vsphere-admins'
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
        $GroupName,

        [Parameter(Mandatory = $false)]
        [string]
        $Domain
    )

    $ExternalSources
    $GroupToAdd
    $Domain

    try {
        $ExternalSources = Get-IdentitySource -External -ErrorAction Stop
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get external identity source" -ErrorAction Stop
    }

    # Searching the external identities for the domain
    if ($null -eq $ExternalSources -or 0 -eq $ExternalSources.count) {
        Write-Error "No external identity source found. Please run New-AvsLDAPSIdentitySource first" -ErrorAction Stop
    }
    elseif ($ExternalSources.count -eq 1) {
        if ($PSBoundParameters.ContainsKey('Domain')) {
            if ($Domain -ne $ExternalSources.Name) {
                Write-Error "The Domain passed in ($Domain) does not match the external directory: $($ExternalSources.Name)" -ErrorAction Stop
            } 
        }
    }
    elseif ($ExternalSources.count -gt 1) {
        if (-Not ($PSBoundParameters.ContainsKey('Domain'))) {
            Write-Host "Multiple external identites exist and domain not suplied. Will attempt to search all ADs attached for $GroupName"
        }
        else {
            $FoundDomainMatch = $false
            foreach ($AD in $ExternalSources) {
                if ($AD.Name -eq $Domain) {
                    $FoundDomainMatch = $true
                    break
                }
            }
            if (-Not $FoundDomainMatch) {
                Write-Warning "Searched the External Directories: $($ExternalSources | Format-List | Out-String) for $Domain and did not find a match"
                Write-Error "Was not able to find $Domain in any of the External Directories" -ErrorAction Stop
            }
        }
    }
    
    # Searching for the group in the specified domain, if provided, or all domains, if none provided
    if ($null -eq $Domain -or -Not ($PSBoundParameters.ContainsKey('Domain'))) {
        $FoundMatch = $false
        foreach ($AD in $ExternalSources) {
            Write-Host "Searching $($AD.Name) for $GroupName"
            try {
                $GroupFound = Get-SsoGroup -Name $GroupName -Domain $AD.Name -ErrorAction Stop 
            } catch {
                Write-Host "Could not find $GroupName in $($AD.Name). Continuing.."
            }
            if ($null -ne $GroupFound -and -Not $FoundMatch) { 
                Write-Host "Found $GroupName in $($AD.Name)." 
                $Domain = $AD.Name
                $GroupToAdd = $GroupFound
                $FoundMatch = $true
            }
            elseif ($null -ne $GroupFound -and $FoundMatch) { 
                Write-Host "Found $GroupName in $($AD.Name) as well."
                Write-Error "Group $GroupName exists in multiple domains . Please re-run and specify domain" -ErrorAction Stop
                return
            }
            elseif ($null -eq $GroupFound) {
                Write-Host "$GroupName not found in $($AD.Name)"
            }
        }
        if ($null -eq $GroupToAdd) {
            Write-Error "$GroupName was not found in any external identity that has been configured. Please ensure that the group name is typed correctly." -ErrorAction Stop
        }
    }
    else {
        try {
            Write-Host "Searching $Domain for $GroupName..."
            $GroupToAdd = Get-SsoGroup -Name $GroupName -Domain $Domain -ErrorAction Stop 
        }
        catch {
            Write-Error "Exception $($PSItem.Exception.Message): Unable to get group $GroupName from $Domain" -ErrorAction Stop
        }
    }

    if ($null -eq $GroupToAdd) {
        Write-Error "$GroupName was not found in the domain. Please ensure that the group is spelled correctly" -ErrorAction Stop
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
        Write-Warning "Cloud Admin Members: $CloudAdminMembers" -ErrorAction Continue
        Write-Error "Unable to add group to CloudAdmins. It may already have been added. Error: $($PSItem.Exception.Message)" -ErrorAction Stop
    }
   
    Write-Host "Successfully added $GroupName to CloudAdmins."
    $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
    Write-Output "Cloud Admin Members: $CloudAdminMembers"
}

<#
    .Synopsis
     Remove a previously added group from an external identity from the CloudAdmins group

    .Parameter GroupName
     Short name of the external identity group to be removed from the CloudAdmins group. For example, vsphere-admins, without the domain appended

    .Parameter Domain
     Name of the domain that GroupName is in. If not provided, will attempt to locate the group in all the configured active directories

    .Example 
    # Remove the group named vsphere-admins from CloudAdmins
     Remove-GroupFromCloudAdmins -GroupName 'vsphere-admins'
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
        $GroupName,

        [Parameter(Mandatory = $false)]
        [string]
        $Domain
    )

    $ExternalSources
    $GroupToRemove
    $Domain

    try {
        $ExternalSources = Get-IdentitySource -External -ErrorAction Stop
    }
    catch {
        Write-Error $PSItem.Exception.Message -ErrorAction Continue
        Write-Error "Unable to get external identity source" -ErrorAction Stop
    }

    # Searching the external identities for the domain
    if ($null -eq $ExternalSources -or 0 -eq $ExternalSources.count) {
        Write-Error "No external identity source found. Please run New-AvsLDAPSIdentitySource first" -ErrorAction Stop
    }
    elseif ($ExternalSources.count -eq 1) {
        if ($PSBoundParameters.ContainsKey('Domain')) {
            if ($Domain -ne $ExternalSources.Name) {
                Write-Error "The Domain passed in ($Domain) does not match the external directory: $($ExternalSources.Name)" -ErrorAction Stop
            } 
        }
    }
    elseif ($ExternalSources.count -gt 1) {
        if (-Not ($PSBoundParameters.ContainsKey('Domain'))) {
            Write-Host "Multiple external identites exist and domain not suplied. Will attempt to search all ADs attached for $GroupName"
        }
        else {
            $FoundDomainMatch = $false
            foreach ($AD in $ExternalSources) {
                if ($AD.Name -eq $Domain) {
                    $FoundDomainMatch = $true
                    break
                }
            }
            if (-Not $FoundDomainMatch) {
                Write-Warning "Searched the External Directories: $($ExternalSources | Format-List | Out-String) for $Domain and did not find a match"
                Write-Error "Was not able to find $Domain in any of the External Directories" -ErrorAction Stop
            }
        }
    }
    
    # Searching for the group in the specified domain, if provided, or all domains, if none provided
    if ($null -eq $Domain -or -Not ($PSBoundParameters.ContainsKey('Domain'))) {
        $FoundMatch = $false
        foreach ($AD in $ExternalSources) {
            Write-Host "Searching $($AD.Name) for $GroupName"
            try {
                $GroupFound = Get-SsoGroup -Name $GroupName -Domain $AD.Name -ErrorAction Stop 
            } catch {
                Write-Host "Could not find $GroupName in $($AD.Name). Continuing.."
            }
            if ($null -ne $GroupFound -and -Not $FoundMatch) { 
                Write-Host "Found $GroupName in $($AD.Name)." 
                $Domain = $AD.Name
                $GroupToRemove = $GroupFound
                $FoundMatch = $true
            }
            elseif ($null -ne $GroupFound -and $FoundMatch) { 
                Write-Host "Found $GroupName in $($AD.Name) as well."
                Write-Error "Group $GroupName exists in multiple domains . Please re-run and specify domain" -ErrorAction Stop
                return
            }
            elseif ($null -eq $GroupFound) {
                Write-Host "$GroupName not found in $($AD.Name)"
            }
        }
        if ($null -eq $GroupToRemove) {
            Write-Error "$GroupName was not found in any external identity that has been configured. Please ensure that the group name is typed correctly." -ErrorAction Stop
        }
    }
    else {
        try {
            Write-Host "Searching $Domain for $GroupName..."
            $GroupToRemove = Get-SsoGroup -Name $GroupName -Domain $Domain -ErrorAction Stop 
        }
        catch {
            Write-Error "Exception $($PSItem.Exception.Message): Unable to get group $GroupName from $Domain" -ErrorAction Stop
        }
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
        Write-Error "Unable to remove group from CloudAdmins. Is it there at all? Error: $($PSItem.Exception.Message)" -ErrorAction Stop
    }
    
    Write-Information "Group $GroupName successfully removed from CloudAdmins."
    $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
    Write-Output "Current Cloud Admin Members: $CloudAdminMembers"
}

<#
    .Synopsis
     Get all users added to the cloud admin group

    .Example 
    # Get all users in CloudAdmins
     Get-CloudAdminUsers
#>
function Get-CloudAdminUsers {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(3, UpdatesSDDC = $false)]

    $CloudAdmins = Get-SsoGroup -Name 'CloudAdmins' -Domain 'vsphere.local'
    if ($null -eq $CloudAdmins) {
        Write-Error "Internal Error fetching CloudAdmins group. Contact support" -ErrorAction Stop
    }

    $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Stop 
    $CloudAdminMembers | Format-List | Out-String
}

<#
    .Synopsis
     Gets all the vSAN based storage policies available to set on a VM.
#>
function Get-StoragePolicies {
    [AVSAttribute(3, UpdatesSDDC = $False)]
    
    $StoragePolicies
    try {
        $StoragePolicies = Get-SpbmStoragePolicy -Namespace "VSAN" -ErrorAction Stop | Select-Object Name, AnyOfRuleSets
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
     Modify vSAN based storage policies on an individual VM

    .Parameter StoragePolicyName
     Name of a vSAN based storage policy to set on the specified VM. Options can be seen in vCenter or using the Get-StoragePolicies command.

    .Parameter VMName
     Name of the VM to set the vSAN based storage policy on.

    .Example 
    # Set the vSAN based storage policy on MyVM to RAID-1 FTT-1
    Set-AvsVMStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -VMName "MyVM"
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
    $StoragePolicy =  Get-SpbmStoragePolicy -Namespace "VSAN" -ErrorAction Stop | Where-Object {$_.Name -eq $StoragePolicyName}
    if ($null -eq $StoragePolicy) {
        Write-Error "Could not find Storage Policy with the name $StoragePolicyName. It either does not exist or is not available." -ErrorAction Continue
        Write-Error "Available storage policies: $(Get-SpbmStoragePolicy -Namespace "VSAN")" -ErrorAction Stop
    } 

    $ProtectedVMs = Get-ProtectedVMs 
    if ($ProtectedVMs.Name.Contains($VMName)) {
        Write-Error "Access denied to this VM." -ErrorAction Stop
    }
    $VM = Get-VM $VMName
    if ($null -eq $VM) {
        Write-Error "Was not able to set the storage policy on the VM. Could not find VM with the name: $VMName" -ErrorAction Stop
    }
    Write-Host "Setting VM $VMName storage policy to $StoragePolicyName..."
    try {
        Set-VM -VM $VM -StoragePolicy $StoragePolicy -SkipHardDisks -ErrorAction Stop -Confirm:$false
    }
    catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidVmConfig] {
        Write-Error "The selected storage policy $($StoragePolicy.Name) is not compatible with this VM. You may need more hosts: $($PSItem.Exception.Message)" -ErrorAction Stop
    }
    catch {
        Write-Error "Was not able to set the storage policy on the VM: $($PSItem.Exception.Message)" -ErrorAction Stop
    }
    Write-Output "Successfully set the storage policy on VM $VMName to $StoragePolicyName"
}

Export-ModuleMember -Function *