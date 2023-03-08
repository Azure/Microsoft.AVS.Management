. $PSScriptRoot\Classes.ps1
. $PSScriptRoot\UserUtils.ps1
. $PSScriptRoot\HcxUtils.ps1

<# Download certificate from SAS token url #>
function Get-Certificates {
    Param
    (
        [Parameter(
            Mandatory = $true)]
        [System.Security.SecureString]
        $SSLCertificatesSasUrl
    )

    [string] $CertificatesSASPlainString = ConvertFrom-SecureString -SecureString $SSLCertificatesSasUrl -AsPlainText
    [System.StringSplitOptions] $options = [System.StringSplitOptions]::RemoveEmptyEntries -bor [System.StringSplitOptions]::TrimEntries
    [string[]] $CertificatesSASList = $CertificatesSASPlainString.Split(",", $options)
    Write-Host "Number of Certs passed $($CertificatesSASList.count)"
    if ($CertificatesSASList.count -eq 0) {
        throw "If adding an LDAPS identity source, please ensure you pass in at least one certificate"
    }
    if ($PSBoundParameters.ContainsKey('SecondaryUrl') -and $CertificatesSASList.count -lt 2) {
        throw "If passing in a secondary/fallback URL, ensure that at least two certificates are passed."
    }
    $DestinationFileArray = @()
    $Index = 1
    foreach ($CertSas in $CertificatesSASList) {
        Write-Host "Downloading Cert $Index..."
        $CertDir = $pwd.Path
        $CertLocation = "$CertDir/cert$Index.cer"
        try {
            $Response = Invoke-WebRequest -Uri $CertSas -OutFile $CertLocation
            $StatusCode = $Response.StatusCode
            Write-Host("Certificate downloaded. $StatusCode")
            $DestinationFileArray += $CertLocation
        }
        catch {
            throw "Failed to download certificate #$($Index): $($PSItem.Exception.Message). Ensure the SAS string is still valid"
        }
        $Index = $Index + 1
    }
    Write-Host "Number of certificates downloaded: $($DestinationFileArray.count)"
    return $DestinationFileArray
}

function Get-StoragePolicyInternal {
    Param
    (
        [Parameter(
            Mandatory = $true)]
        $StoragePolicyName
    )
    Write-Host "Getting Storage Policy $StoragePolicyName"
    $VSANStoragePolicies = Get-SpbmStoragePolicy -Namespace "VSAN" -ErrorAction Stop
    $StoragePolicy = Get-SpbmStoragePolicy $StoragePolicyName -ErrorAction Stop
    if ($null -eq $StoragePolicy) {
        Write-Error "Could not find Storage Policy with the name $StoragePolicyName." -ErrorAction Continue
        Write-Error "Available storage policies: $(Get-SpbmStoragePolicy -Namespace "VSAN")" -ErrorAction Stop
    }
    elseif (-not ($StoragePolicy -in $VSANStoragePolicies)) {
        Write-Error "Storage policy $StoragePolicyName is not supported. Storage policies must be in the VSAN namespace" -ErrorAction Continue
        Write-Error "Available storage policies: $(Get-SpbmStoragePolicy -Namespace "VSAN")" -ErrorAction Stop
    }
    return $StoragePolicy, $VSANStoragePolicies
}

function Set-StoragePolicyOnVM {
    Param
    (
        [Parameter(
            Mandatory = $true)]
        $VM,
        [Parameter(
            Mandatory = $true)]
        $VSANStoragePolicies,
        [Parameter(
            Mandatory = $true)]
        $StoragePolicy
    )
    if (-not $(Get-SpbmEntityConfiguration $VM).StoragePolicy -in $VSANStoragePolicies) {
        Write-Error "Modifying storage policy on $($VM.Name) is not supported"
    }
    Write-Host "Setting VM $($VM.Name) storage policy to $($StoragePolicy.Name)..."
    try {
        Set-VM -VM $VM -StoragePolicy $StoragePolicy -ErrorAction Stop -Confirm:$false
        Write-Output "Successfully set the storage policy on VM $($VM.Name) to $($StoragePolicy.Name)"
    }
    catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidVmConfig] {
        Write-Error "The selected storage policy $($StoragePolicy.Name) is not compatible with $($VM.Name). You may need more hosts: $($PSItem.Exception.Message)"
    }
    catch {
        Write-Error "Was not able to set the storage policy on $($VM.Name): $($PSItem.Exception.Message)"
    }
}

<#
    .Synopsis
     Not Recommended (use New-LDAPSIdentitySource): Add a not secure external identity source (Active Directory over LDAP) for use with vCenter Server Single Sign-On.

    .Parameter Name
     The user-friendly name the external AD will be given in vCenter

    .Parameter DomainName
     Domain name of the external active directory, e.g. myactivedirectory.local

    .Parameter DomainAlias
     Domain alias of the external active directory, e.g. myactivedirectory

    .Parameter PrimaryUrl
     Url of the primary ldap server to attempt to connect to, e.g. ldap://myadserver.local:389

    .Parameter SecondaryUrl
     Optional: Url of the fallback ldap server to attempt to connect to, e.g. ldap://myadserver.local:389

    .Parameter BaseDNUsers
     Base Distinguished Name for users, e.g. "dc=myadserver,dc=local"

    .Parameter BaseDNGroups
     Base Distinguished Name for groups, e.g. "dc=myadserver,dc=local"

    .Parameter Credential
     Credential to login to the LDAP server (NOT cloudadmin) in the form of a username/password credential. Usernames often look like prodAdmins@domainname.com or if the AD is a Microsoft Active Directory server, usernames may need to be prefixed with the NetBIOS domain name, such as prod\AD_Admin

    .Parameter GroupName
     Optional: A group in the customer external identity source to be added to CloudAdmins. Users in this group will have CloudAdmin access. Group name should be formatted without the domain name, e.g. group-to-give-access

    .Example
    # Add the domain server named "myserver.local" to vCenter
    Add-LDAPIdentitySource -Name 'myserver' -DomainName 'myserver.local' -DomainAlias 'myserver' -PrimaryUrl 'ldap://10.40.0.5:389' -BaseDNUsers 'dc=myserver, dc=local' -BaseDNGroups 'dc=myserver, dc=local'
#>
function New-LDAPIdentitySource {
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
        [ValidateNotNullOrEmpty()]
        [string]
        $PrimaryUrl,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Optional: URL of a backup server')]
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

    if (-not ($PrimaryUrl -match '^(ldap:).+((:389)|(:636)|(:3268)|(:3269))$')) {
        Write-Error "PrimaryUrl $PrimaryUrl is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldap: and not ldaps:" -ErrorAction Stop
    }
    if (($PrimaryUrl -match '^(ldap:).+((:636)|(:3269))$')) {
        Write-Warning "PrimaryUrl $PrimaryUrl is nonstandard. Are you sure you meant to use the 636/3269 port and not the standard ports for LDAP, 389 or 3268? Continuing anyway.."
    }
    if ($PSBoundParameters.ContainsKey('SecondaryUrl') -and (-not ($SecondaryUrl -match '^(ldap:).+((:389)|(:636)|(:3268)|(:3269))$'))) {
        Write-Error "SecondaryUrl $SecondaryUrl is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldap: and not ldaps:" -ErrorAction Stop
    }
    if (($SecondaryUrl -match '^(ldap:).+((:636)|(:3269))$')) {
        Write-Warning "SecondaryUrl $SecondaryUrl is nonstandard. Are you sure you meant to use the 636/3269 port and not the standard ports for LDAP, 389 or 3268? Continuing anyway.."
    }

    $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Continue
    if ($null -ne $ExternalIdentitySources) {
        Write-Host "Checking to see if identity source already exists..."
        if ($DomainName.trim() -eq $($ExternalIdentitySources.Name.trim())) {
            Write-Error $($ExternalIdentitySources | Format-List | Out-String) -ErrorAction Continue
            Write-Error "Already have an external identity source with the same name: $($ExternalIdentitySources.Name). If only trying to add a group to this Identity Source, use Add-GroupToCloudAdmins" -ErrorAction Stop
        }
        else {
            Write-Information "$($ExternalIdentitySources | Format-List | Out-String)"
            Write-Information "An identity source already exists, but not for this domain. Continuing to add this one..."
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
     Download the certificate from a domain controller
#>
function Get-CertificateFromDomainController {
    param (
        [Parameter(
            Mandatory = $true)]
        [ValidateNotNull()]
        [System.Uri]
        $ParsedUrl,

        [Parameter(
            Mandatory = $true)]
        [ValidateNotNull()]
        [string]
        $computerUrl
    )

    try {
        $Command = 'nslookup ' + $ParsedUrl.Host + ' -type=soa'
        $SSHRes = Invoke-SSHCommand -Command $Command -SSHSession $SSH_Sessions['VC'].Value
        if ($SSHRes.ExitStatus -ne 0) {
            throw "The FQDN $($ParsedUrl.Host) cannot be resolved to an IP address. Make sure DNS is configured."
        }

        $Command = 'nc -vz ' + $ParsedUrl.Host + ' ' + $ParsedUrl.Port
        $SSHRes = Invoke-SSHCommand -Command $Command -SSHSession $SSH_Sessions['VC'].Value
        if ($SSHRes.ExitStatus -ne 0) {
            throw "The connection cannot be established. Please check the address, routing and/or firewall and make sure port $($ParsedUrl.Port) is open."
        }

        Write-Host ("Starting to Download Cert from " + $computerUrl)
        $Command = 'echo "1" | openssl s_client -connect ' + $ParsedUrl.Host + ':' + $ParsedUrl.Port + ' -showcerts'
        $SSHRes = Invoke-SSHCommand -Command $Command -SSHSession $SSH_Sessions['VC'].Value
        $SSHOutput = $SSHRes.Output | out-string
    } catch {
        throw "Failure to download the certificate from $computerUrl. $_"
    }
    return $SSHOutput
}

<#
    .Synopsis
     Recommended: Add a secure external identity source (Active Directory over LDAPS) for use with vCenter Server Single Sign-On.

    .Parameter Name
     The user-friendly name the external AD will be given in vCenter

    .Parameter DomainName
     Domain name of the external active directory, e.g. myactivedirectory.local

    .Parameter DomainAlias
     Domain alias of the external active directory, e.g. myactivedirectory

    .Parameter PrimaryUrl
     Url of the primary ldaps server to attempt to connect to, e.g. ldaps://myadserver.local:636

    .Parameter SecondaryUrl
     Optional: Url of the fallback ldaps server to attempt to connect to, e.g. ldaps://myadserver.local:636

    .Parameter BaseDNUsers
     Base Distinguished Name for users, e.g. "dc=myadserver,dc=local"

    .Parameter BaseDNGroups
     Base Distinguished Name for groups, e.g. "dc=myadserver,dc=local"

    .Parameter Credential
     Credential to login to the LDAP server (NOT cloudadmin) in the form of a username/password credential. Usernames often look like prodAdmins@domainname.com or if the AD is a Microsoft Active Directory server, usernames may need to be prefixed with the NetBIOS domain name, such as prod\AD_Admin

    .Parameter SSLCertificatesSasUrl
     An comma-delimeted list of Blob Shared Access Signature strings to the certificates required to connect to the external active directory

    .Parameter GroupName
     Optional: A group in the customer external identity source to be added to CloudAdmins. Users in this group will have CloudAdmin access. Group name should be formatted without the domain name, e.g. group-to-give-access

    .Example
    # Add the domain server named "myserver.local" to vCenter
    Add-LDAPSIdentitySource -Name 'myserver' -DomainName 'myserver.local' -DomainAlias 'myserver' -PrimaryUrl 'ldaps://10.40.0.5:636' -BaseDNUsers 'dc=myserver, dc=local' -BaseDNGroups 'dc=myserver, dc=local' -Username 'myserver@myserver.local' -Password 'PlaceholderPassword' -CertificatesSAS 'https://sharedaccessstring.path/accesskey' -Protocol LDAPS
#>
function New-LDAPSIdentitySource {
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
        [ValidateNotNullOrEmpty()]
        [string]
        $PrimaryUrl,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Optional: URL of a backup server')]
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
            Mandatory = $false,
            HelpMessage = 'Optional: The certs will be installed from domain controllers if not specified. A comma-delimited list of SAS path URI to Certificates for authentication. Ensure permissions to read included. To generate, place the certificates in any storage account blob and then right click the cert and generate SAS')]
        [System.Security.SecureString]
        $SSLCertificatesSasUrl,

        [Parameter (
            Mandatory = $false,
            HelpMessage = 'A group in the external identity source to give CloudAdmins access')]
        [string]
        $GroupName
    )

    if (-not ($PrimaryUrl -match '^(ldaps:).+((:389)|(:636)|(:3268)|(:3269))$')) {
        Write-Error "PrimaryUrl $PrimaryUrl is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldaps: and not ldap:" -ErrorAction Stop
    }
    if (($PrimaryUrl -match '^(ldaps:).+((:389)|(:3268))$')) {
        Write-Warning "PrimaryUrl $PrimaryUrl is nonstandard. Are you sure you meant to use the 389/3268 port and not the standard ports for LDAPS, 636 or 3269? Continuing anyway.."
    }
    if ($PSBoundParameters.ContainsKey('SecondaryUrl') -and (-not ($SecondaryUrl -match '^(ldaps:).+((:389)|(:636)|(:3268)|(:3269))$'))) {
        Write-Error "SecondaryUrl $SecondaryUrl is invalid. Ensure the port number is 389, 636, 3268, or 3269 and that the url begins with ldaps: and not ldap:" -ErrorAction Stop
    }
    if (($SecondaryUrl -match '^(ldaps:).+((:389)|(:3268))$')) {
        Write-Warning "SecondaryUrl $SecondaryUrl is nonstandard. Are you sure you meant to use the 389/3268 port and not the standard ports for LDAPS, 636 or 3269? Continuing anyway.."
    }

    $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Continue
    if ($null -ne $ExternalIdentitySources) {
        Write-Host "Checking to see if identity source already exists..."
        if ($DomainName.trim() -eq $($ExternalIdentitySources.Name.trim())) {
            Write-Error $($ExternalIdentitySources | Format-List | Out-String) -ErrorAction Continue
            Write-Error "Already have an external identity source with the same name: $($ExternalIdentitySources.Name). If only trying to add a group to this Identity Source, use Add-GroupToCloudAdmins" -ErrorAction Stop
        }
        else {
            Write-Information "$($ExternalIdentitySources | Format-List | Out-String)"
            Write-Information "An identity source already exists, but not for this domain. Continuing to add this one..."
        }
    }
    else {
        Write-Host "No existing external identity sources found."
    }
    
    $Password = $Credential.GetNetworkCredential().Password
    $DestinationFileArray = @()
    if ($PSBoundParameters.ContainsKey('SSLCertificatesSasUrl')) {
        $DestinationFileArray = Get-Certificates -SSLCertificatesSasUrl $SSLCertificatesSasUrl -ErrorAction Stop
    } else {
        $exportFolder = "$home/"
        $remoteComputers = ,$PrimaryUrl
        if ($PSBoundParameters.ContainsKey('SecondaryUrl')) {
            $remoteComputers += $SecondaryUrl
        }

        foreach ($computerUrl in $remoteComputers) {
            try {
                if (![uri]::IsWellFormedUriString($computerUrl, 'Absolute')) { throw }
                $ParsedUrl = [System.Uri]$computerUrl
            }
            catch {
                throw "Incorrect Url format entered from: $computerUrl"
            }
            if ($ParsedUrl.Host -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [bool]($ParsedUrl.Host -as [ipaddress])) {
                throw "Incorrect Url format. $computerUrl is an IP address. Consider using hostname exactly as specified on the issued certificate."
            }

            $SSHOutput = Get-CertificateFromDomainController -ParsedUrl $ParsedUrl -computerUrl $computerUrl

            if ($SSHOutput -notmatch '(?s)(?<cert>-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)') {
                throw "The certificate from $computerUrl has an incorrect format"
            } else {
                $certs = select-string -inputobject $SSHOutput -pattern "(?s)(?<cert>-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)" -allmatches
                $cert = $certs.matches[0]
                $exportPath = $exportFolder+($ParsedUrl.Host.split(".")[0])+".cer"
                $cert.Value | Out-File $exportPath -Encoding ascii
                $DestinationFileArray += $exportPath
            }
        }
    }

    [System.Array]$Certificates =
    foreach($CertFile in $DestinationFileArray) {
        try {
            [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($certfile)
        } catch {
            Write-Error "Failure to convert file $certfile to a certificate $($PSItem.Exception.Message)"
            throw "File to certificate conversion failed. See error message for more details"
        }
    }

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
        -Certificates $Certificates -ErrorAction Stop
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
     Update the SSL Certificates used for authenticating to an Active Directory over LDAPS

    .Parameter DomainName
     Domain name of the external active directory, e.g. myactivedirectory.local

    .Parameter SSLCertificatesSasUrl
     A comma-delimeted string of the shared access signature (SAS) URLs linking to the certificates required to connect to the external active directory. If more than one, separate each SAS URL by a comma `,`.
#>
function Update-IdentitySourceCertificates {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the Identity source')]
        [ValidateNotNull()]
        [string]
        $DomainName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'A comma-delimited list of SAS path URI to Certificates for authentication. Ensure permissions to read included. To generate, place the certificates in any storage account blob and then right click the cert and generate SAS')]
        [System.Security.SecureString]
        $SSLCertificatesSasUrl
    )

    $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Stop
    if ($null -ne $ExternalIdentitySources) {
        $IdentitySource = $ExternalIdentitySources | Where-Object { $_.Name -eq $DomainName }
        if ($null -ne $IdentitySource) {
            $DestinationFileArray = Get-Certificates $SSLCertificatesSasUrl -ErrorAction Stop
            [System.Array]$Certificates =
            foreach ($CertFile in $DestinationFileArray) {
                try {
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($certfile)
                }
                catch {
                    Write-Error "Failure to convert file $certfile to a certificate $($PSItem.Exception.Message)"
                    throw "File to certificate conversion failed. See error message for more details"
                }
            }
            Write-Host "Updating the LDAPS Identity Source..."
            Set-LDAPIdentitySource -IdentitySource $IdentitySource -Certificates $Certificates -ErrorAction Stop
            $ExternalIdentitySources = Get-IdentitySource -External -ErrorAction Continue
            $ExternalIdentitySources | Format-List | Out-String
        }
        else {
            Write-Error "Could not find Identity Source with name: $DomainName." -ErrorAction Stop
        }
    }
    else {
        Write-Host "No existing external identity sources found."
    }
}

<#
    .Synopsis
     Gets all external identity sources
#>
function Get-ExternalIdentitySources {
    [AVSAttribute(3, UpdatesSDDC = $false)]
    Param()

    $ExternalSource = Get-IdentitySource -External
    if ($null -eq $ExternalSource) {
        Write-Output "No external identity sources found."
        return
    }
    else {
        Write-Output "LDAPs Certificate(s) valid until the [Not After] parameter"
        $ExternalSource | Format-List | Out-String
    }
}

<#
    .Synopsis
     Removes supplied identity source, or, if no specific identity source is provided, will remove all identity sources.

    .Parameter DomainName
     The domain name of the external identity source to remove i.e. `mydomain.com`. If none provided, will attempt to remove all external identity sources.
#>
function Remove-ExternalIdentitySources {
    [AVSAttribute(5, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]
        $DomainName
    )

    $ExternalSource = Get-IdentitySource -External
    if ($null -eq $ExternalSource) {
        Write-Output "No external identity sources found to remove. Nothing done"
        return
    }
    else {
        if (-Not ($PSBoundParameters.ContainsKey('DomainName'))) {
            foreach ($AD in $ExternalSource) {
                Remove-IdentitySource -IdentitySource $AD -ErrorAction Stop
                Write-Output "Identity source $($AD.Name) removed."
            }
        }
        else {
            $FoundMatch = $false
            foreach ($AD in $ExternalSource) {
                if ($AD.Name -eq $DomainName) {
                    Remove-IdentitySource -IdentitySource $AD -ErrorAction Stop
                    Write-Output "Identity source $($AD.Name) removed."
                    $FoundMatch = $true
                }
            }
            if (-Not $FoundMatch) { Write-Output "No external identity source found that matches $DomainName. Nothing done." }
        }
    }
}

<#
    .Synopsis
     Add a group from the external identity to the CloudAdmins group

    .Parameter GroupName
     The group in the customer external identity source to be added to CloudAdmins. Users in this group will have CloudAdmin access. Group name should be formatted without the domain name, e.g. group-to-give-access

    .Parameter Domain
     Name of the external domain that GroupName is in. If not provided, will attempt to locate the group in all the configured active directories. For example, MyActiveDirectory.Com

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
        Write-Error "No external identity source found. Please run New-LDAPSIdentitySource first" -ErrorAction Stop
    }
    elseif ($ExternalSources.count -eq 1) {
        if ($PSBoundParameters.ContainsKey('Domain')) {
            if ($Domain -ne $ExternalSources.Name) {
                Write-Error "The Domain passed in ($Domain) does not match the external directory: $($ExternalSources.Name). Try again with -Domain $($ExternalSources.Name)" -ErrorAction Stop
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
            }
            catch {
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

    $GroupToAddTuple = [System.Tuple]::Create("$($GroupToAdd.Name)","$($GroupToAdd.Domain)")
    $CloudAdminMembers = @()
    foreach ($a in $(Get-SsoGroup -Group $CloudAdmins)) { $tuple = [System.Tuple]::Create("$($a.Name)","$($a.Domain)"); $CloudAdminMembers += $tuple }
    if ($GroupToAddTuple -in $CloudAdminMembers) {
        Write-Host "Group $($GroupToAddTuple.Item1)@$($($GroupToAddTuple.Item2)) has already been added to CloudAdmins."
        return
    }

    try {
        Write-Host "Adding group $GroupName to CloudAdmins..."
        Add-GroupToSsoGroup -Group $GroupToAdd -TargetGroup $CloudAdmins -ErrorAction Stop
    }
    catch {
        $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
        Write-Warning "Cloud Admin Members: $CloudAdminMembers" -ErrorAction Continue
        Write-Error "Unable to add group to CloudAdmins. Error: $($PSItem.Exception.Message)" -ErrorAction Stop
    }

    Write-Host "Successfully added $GroupName to CloudAdmins."
    $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Continue
    Write-Output "Cloud Admin Members: $CloudAdminMembers"
}

<#
    .Synopsis
     Remove a previously added group from an external identity from the CloudAdmins group

    .Parameter GroupName
     The group in the customer external identity source to be removed from CloudAdmins. Group name should be formatted without the domain name, e.g. group-to-give-access

    .Parameter Domain
     Name of the external domain that GroupName is in. If not provided, will attempt to locate the group in all the configured active directories. For example, MyActiveDirectory.Com

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
        Write-Error "No external identity source found. Please run New-LDAPSIdentitySource first" -ErrorAction Stop
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
            }
            catch {
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
     Get all groups that have been added to the cloud admin group
    .Example
    # Get all users in CloudAdmins
     Get-CloudAdminGroups
#>
function Get-CloudAdminGroups {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(3, UpdatesSDDC = $false)]
    Param()

    $CloudAdmins = Get-SsoGroup -Name 'CloudAdmins' -Domain 'vsphere.local'
    if ($null -eq $CloudAdmins) {
        Write-Error "Internal Error fetching CloudAdmins group. Contact support" -ErrorAction Stop
    }

    $CloudAdminMembers = Get-SsoGroup -Group $CloudAdmins -ErrorAction Stop
    if ($null -eq $CloudAdminMembers) {
        Write-Output "No groups yet added to CloudAdmin."
    }
    else {
        $CloudAdminMembers | Format-List | Out-String
    }
}

<#
    .Synopsis
     Gets all the vSAN based storage policies available to set on a VM.
#>
function Get-StoragePolicies {
    [AVSAttribute(3, UpdatesSDDC = $False)]
    Param()

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
     Modify vSAN based storage policies on a VM(s)

    .Parameter StoragePolicyName
     Name of a vSAN based storage policy to set on the specified VM. Options can be seen in vCenter or using the Get-StoragePolicies command.

    .Parameter VMName
     Name of the VM to set the vSAN based storage policy on. This supports wildcards for bulk operations. For example, MyVM* would attempt to change the storage policy on MyVM1, MyVM2, MyVM3, etc.

    .Example
    # Set the vSAN based storage policy on MyVM to RAID-1 FTT-1
    Set-VMStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -VMName "MyVM"
#>
function Set-VMStoragePolicy {
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
    $StoragePolicy, $VSANStoragePolicies = Get-StoragePolicyInternal $StoragePolicyName -ErrorAction Stop
    $VMList = Get-VM $VMName

    if ($null -eq $VMList) {
        Write-Error "Was not able to set the storage policy on the VM. Could not find VM(s) with the name: $VMName" -ErrorAction Stop
    }
    elseif ($VMList.count -eq 1) {
        $VM = $VMList[0]
        Set-StoragePolicyOnVM -VM $VM -VSANStoragePolicies $VSANStoragePolicies -StoragePolicy $StoragePolicy -ErrorAction Stop
    }
    else {
        foreach ($VM in $VMList) {
            Set-StoragePolicyOnVM -VM $VM -VSANStoragePolicies $VSANStoragePolicies -StoragePolicy $StoragePolicy -ErrorAction Continue
        }
    }
}

<#
    .Synopsis
     Modify vSAN based storage policies on all VMs in a Container

    .Parameter StoragePolicyName
     Name of a vSAN based storage policy to set on the specified VM. Options can be seen in vCenter or using the Get-StoragePolicies command.

    .Parameter Location
     Name of the Folder, ResourcePool, or Cluster containing the VMs to set the storage policy on.
     For example, if you would like to change the storage policy of all the VMs in the cluster "Cluster-2", then supply "Cluster-2".
     Similarly, if you would like to change the storage policy of all the VMs in a folder called "MyFolder", supply "MyFolder"

    .Example
    # Set the vSAN based storage policy on all VMs in MyVMs to RAID-1 FTT-1
    Set-LocationStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -Location "MyVMs"
#>
function Set-LocationStoragePolicy {
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
            HelpMessage = 'Name of the Folder, ResourcePool, or Cluster containing the VMs to set the storage policy on.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Location
    )
    $StoragePolicy, $VSANStoragePolicies = Get-StoragePolicyInternal $StoragePolicyName -ErrorAction Stop
    $VMList = Get-VM -Location $Location

    if ($null -eq $VMList) {
        Write-Error "Was not able to set storage policies. Could not find VM(s) in the container: $Location" -ErrorAction Stop
    }
    else {
        foreach ($VM in $VMList) {
            Set-StoragePolicyOnVM -VM $VM -VSANStoragePolicies $VSANStoragePolicies -StoragePolicy $StoragePolicy -ErrorAction Continue
        }
    }
}

<#
    .Synopsis
     Specify default storage policy for a cluster(s)

    .Parameter StoragePolicyName
     Name of a vSAN based storage policy to set to be the default for VMs on this cluster. Options can be seen in vCenter or using the Get-StoragePolicies command.

    .Parameter ClusterName
     Name of the cluster to set the default on. This supports wildcards for bulk operations. For example, MyCluster* would attempt to change the storage policy on MyCluster1, MyCluster2, etc.

    .Example
    # Set the default vSAN based storage policy on MyCluster to RAID-1 FTT-1
    Set-ClusterDefaultStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -ClusterName "MyCluster"
#>
function Set-ClusterDefaultStoragePolicy {
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
            HelpMessage = 'Name of the Cluster to set the storage policy on')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ClusterName
    )
    $StoragePolicy, $VSANStoragePolicies = Get-StoragePolicyInternal $StoragePolicyName
    $CompatibleDatastores = Get-SpbmCompatibleStorage -StoragePolicy $StoragePolicy
    $ClusterList = Get-Cluster $ClusterName
    if ($null -eq $ClusterList) {
        Write-Error "Could not find Cluster with the name $ClusterName." -ErrorAction Stop
    }

    $ClusterDatastores = $ClusterList | Get-VMHost | Get-Datastore

    if ($null -eq $ClusterDatastores) {
        $hosts = $ClusterList | Get-VMHost
        if ($null -eq $hosts) {
            Write-Error "Was not able to set the Storage policy on $ClusterList. The Cluster does not appear to have VM Hosts. Please add VM Hosts before setting storage policy" -ErrorAction Stop
        }
        else {
            Write-Error "Setting the Storage Policy on this Cluster is not supported." -ErrorAction Stop
        }
    }
    elseif ($ClusterDatastores.count -eq 1) {
        if ($ClusterDatastores[0] -in $CompatibleDatastores) {
            try {
                Write-Host "Setting Storage Policy on $ClusterList to $StoragePolicyName..."
                Set-SpbmEntityConfiguration -Configuration (Get-SpbmEntityConfiguration $ClusterDatastores[0]) -storagePolicy $StoragePolicy -ErrorAction Stop -Confirm:$false
                Write-Output "Successfully set the Storage Policy on $ClusterList to $StoragePolicyName"
            }
            catch {
                Write-Error "Was not able to set the Storage Policy on the Cluster Datastore: $($PSItem.Exception.Message)" -ErrorAction Stop
            }
        }
        else {
            Write-Error "Modifying the default storage policy on this cluster: $($ClusterDatastores[0]) is not supported" -ErrorAction Stop
        }
    }
    else {
        foreach ($Datastore in $ClusterDatastores) {
            if ($Datastore -in $CompatibleDatastores) {
                try {
                    Write-Host "Setting Storage Policy on $Datastore to $StoragePolicyName..."
                    Set-SpbmEntityConfiguration -Configuration (Get-SpbmEntityConfiguration $Datastore) -storagePolicy $StoragePolicy -ErrorAction Stop -Confirm:$false
                    Write-Output "Successfully set the storage policy on $Datastore to $StoragePolicyName"
                }
                catch {
                    Write-Error "Was not able to set the storage policy on the Cluster Datastore: $($PSItem.Exception.Message)" -ErrorAction Stop
                }
            }
            else {
                Write-Error "Modifying the default storage policy on $Datastore is not supported" -ErrorAction Continue
                continue
            }
        }
    }
}
<#
    .Synopsis
    Verify a connection to VIServer with retries and a backoff timer in the case of unexpected exceptions.
    .Parameter Credential
    Specifies credential used to connect to VIServer
    .Example
    Confirm-ConnectVIServer -Credential -HcxAdminCredential
#>
function Confirm-ConnectVIServer {
    [CmdletBinding()]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Credential used to connect to VI Server')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )
    $Attempts = 3
    $Backoff = 5
    $IsConnected = $false
    while ($Attempts -gt 0) {
        try {
            $ViServer = Connect-VIServer -Server "vc" -Credential $Credential -Force
            if ($ViServer.IsConnected) {
                $IsConnected = $ViServer.IsConnected
                break
            }
        }
        catch {
            Write-Host $_.Exception
        }
        Write-Host "Sleeping for $Backoff seconds before trying again."
        Start-Sleep $Backoff
        $Attempts--
    }
    return $IsConnected
}

<#
    .Synopsis
    Restarts the HCX Manager VM
    .Parameter Force
    Flag to force the restart of the hcxmanager without checking for power state, migrations, or replications.
    For example, A stuck migration could be preventing the restart without this parameter.
    .Parameter HardReboot
    Warning: This Parameter should be used as a last ditch effort where a soft-reboot wouldn't work.
    Hard Reboots the VM instead of restarting the Guest OS.
    .Parameter Timeout
    Number of seconds the script is allowed to wait for sucessful connection to the hcx appliance before timing out.
    .Example
    # Skips Migrations and replications and hard reboots the system.
    Restart-HcxManager -Force -HardReboot
#>
function Restart-HCXManager {
    [AVSAttribute(30, UpdatesSDDC = $false)]
    Param(
        [parameter(
            Mandatory = $false,
            HelpMessage = "Force restart without checking for migrations and replications.")]
        [switch]
        $Force,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Reboot the Virtual Machine instead of restarting the Guest OS')]
        [ValidateNotNull()]
        [switch]
        $HardReboot
    )
    try {
        $DefaultViConnection = $DefaultVIServers
        $UserName = 'tempHcxAdmin'
        $UserRole = 'tempHcxAdminRole'
        $Group = 'Administrators'
        $Port = 443

        Write-Host "Creating new temp scripting user"
        $privileges = @("VirtualMachine.Interact.PowerOff",
            "VirtualMachine.Interact.PowerOn",
            "VirtualMachine.Interact.Reset"
        )
        $HcxAdminCredential = New-TempUser -privileges $privileges -userName $UserName -userRole $UserRole
        $VcenterConnection = Confirm-ConnectVIServer -Credential $HcxAdminCredential

        if (-not $VcenterConnection) {
            throw "Error Connecting to Vcenter with $($HcxAdminCredential.userName)"
        }

        Write-Host "INPUTS: HardReboot=$HardReboot, Force=$Force, Port=$Port, Timeout=$Timeout"

        $HcxServer = 'hcx'
        $hcxVm = Get-HcxManagerVM
        if (-not $hcxVm) {
            throw "HCX VM could not be found. Please check if the HCX addon is installed."
        }
        Add-UserToGroup -userName $UserName -group $Group

        if ($hcxVm.PowerState -ne "PoweredOn") {
            if (-not $Force) {
                throw "$($hcxVm.Name) must be powered on to restart. Current powerstate is $($hcxVm.PowerState)."
            }
            Write-Host "Forcing PowerOn PowerState=$($hcxVm.PowerState), Force=$Force"
            Start-VM $hcxVm | Out-Null
            $ForcedPowerOn = $true
        }

        if (-not $Force) {
            Write-Host "Connecting to HCX Server at port $Port..."
            $elapsed = Measure-Command -Expression { Connect-HCXServer -Server $HcxServer -Port $Port -Credential $HcxAdminCredential -ErrorAction Stop }
            Write-Host "Connected to HCX Server at port $Port elapsed=$elapsed."
            Write-Host "Checking for active migrations."

            $migratingVmsCount = (Get-HCXMigration -State MIGRATING -Server $HcxServer).Count

            if ($migratingVmsCount -gt 0) {
                throw "VM cannot restart while migrations are in progress. There are $migratingVmsCount active migrations."
            }

            Write-Host "$migratingVmsCount active migrations found."

            $XHmAuthorization = Get-AuthorizationToken -Credential $HcxAdminCredential -HcxServer $HcxServer
            $keysToLookFor = @("activeReplicationCnt", "configuringReplicationCnt", "recoveringReplicationCnt", "syncingReplicationCnt")
            $JsonBody = @{"type" = "summary" } | ConvertTo-Json

            Write-Host "Checking for Active Replications"

            $replicationSummary = Invoke-RestMethod -Method 'POST' `
                -Uri https://${hcxServer}/hybridity/api/replications?action=query `
                -Authentication Basic -SkipCertificateCheck -Credential $HcxAdminCredential `
                -ContentType 'application/json' -Body $JsonBody -Verbose `
                -Headers @{ 'x-hm-authorization' = "$xHmAuthorization" } `
            | ConvertTo-Json | ConvertFrom-Json -AsHashtable

            foreach ($key in $keysToLookFor) {
                if (!$replicationSummary.containsKey($key)) {
                    throw "$key not found in replication summary response."
                }

                $replicationType = $replicationSummary[$key]
                if ($replicationType.Count -eq 0) {
                    $runningReplicationCount = 0
                }
                else {
                    $runningReplicationCount = $replicationType["outgoing"]
                }
                if ($replicationType.containsKey("incoming")) {
                    $runningReplicationCount += $replicationType["incoming"]
                }
                if ($runningReplicationCount -gt 0) {
                    throw "VM cannot restart while replications are in progress. $key=$runningReplicationCount"
                }
                Write-Host "$key=$runningReplicationCount"
            }
            Write-Host "$runningReplicationCount total running replications found."
        }
        else {
            Write-Host "WARNING: Force option given, VM will restart regardless of migration and replication status."
        }
        if (-not $ForcedPowerOn) {
            if ($HardReboot) {
                Write-Host "Restarting $($hcxVm.Name)..."
                Restart-VM -VM $hcxVm -Confirm:$false | Out-Null
                Write-Host "$($hcxVm.Name)'s powerstate=$($hcxVm.PowerState)"
            }
            else {
                Write-Host "Restarting Guest OS..."
                Restart-VMGuest -VM $hcxVm | Out-Null
                Write-Host "$($hcxVm.Name)'s powerstate=$($hcxVm.PowerState)"
            }
        }
        $hcxConnection = Test-HcxConnection -Server $HcxServer -Port $Port -Count 12 -Credential $HcxAdminCredential -HcxVm $hcxVm
    }
    catch {
        Write-Error $_
    }
    finally {
        $global:DefaultVIServers = $DefaultViConnection
        if ($hcxConnection) {
            Write-Host "Disconnecting from HCX Server."
            Disconnect-HCXServer -Server $hcxConnection -Confirm:$false -Force
        }
        Remove-TempUser -userName $UserName -userRole $UserRole
    }
}

<#
    .Synopsis
    Scale the HCX manager vm to the new resource allocation of 8 vCPU and 24 GB RAM (Default 4 vCPU/12GB)
#>
function Set-HcxScaledCpuAndMemorySetting {
    [AVSAttribute(30, UpdatesSDDC = $false)]
    Param(
        [parameter(
            Mandatory = $false,
            HelpMessage = "HCX manager will be rebooted and will not be available during scaling.")]
        [bool]
        $AgreeToRestartHCX = $false
    )
    try {
        $DefaultViConnection = $DefaultVIServers
        $UserName = 'tempHcxAdmin'
        $UserRole = 'tempHcxAdminRole'
        $Group = 'Administrators'

        Assert-CustomerRestartAwareness -AgreeToRestartHCX $AgreeToRestartHCX

        Write-Host "Creating new temp scripting user"
        $privileges = @("VirtualMachine.Config.CPUCount",
            "VirtualMachine.Config.Memory",
            "VirtualMachine.Interact.PowerOff",
            "VirtualMachine.Interact.PowerOn")
        $HcxAdminCredential = New-TempUser -privileges $privileges -userName $UserName -userRole $UserRole
        $VcenterConnection = Confirm-ConnectVIServer -Credential $HcxAdminCredential
        if (-not $VcenterConnection) {
            throw "Error Connecting to Vcenter with $($HcxAdminCredential.userName)"
        }

        $Port = 443
        $HcxServer = 'hcx'
        $HcxPreferredVersion = '4.3.2'
        $DiskUtilizationTreshold = 90
        $HcxScaledtNumCpu = 8
        $HcxScaledMemoryGb = 24

        $HcxVm = Get-HcxManagerVM
        if (-not $HcxVm) {
            throw "HCX VM could not be found. Please check if the HCX addon is installed."
        }
        if ($HcxVm.PowerState -ne "PoweredOn") {
            throw "$($HcxVm.Name) must be powered on. Current powerstate is $($HcxVm.PowerState)."
        }
        if (($HcxVm.NumCpu -eq $HcxScaledtNumCpu) -and
        ($HcxVm.MemoryGb -eq $HcxScaledMemoryGb)) {
            throw "HCX VM: $($HcxVm.Name) is already scaled to $($HcxVm.NumCpu) CPUs and $($HcxVm.MemoryGb) Memory."
        }

        Write-Host "Connecting to HCX Server at port $Port..."
        Add-UserToGroup -userName $UserName -group $Group
        $elapsed = Measure-Command -Expression { Connect-HCXServer -Server $HcxServer -Port $Port -Credential $HcxAdminCredential -ErrorAction Stop }
        Write-Host "Connected to HCX Server at port $Port elapsed=$elapsed."

        Write-Host "Checking for active migrations."
        $migratingVmsCount = (Get-HCXMigration -State MIGRATING -Server $HcxServer).Count
        if ($migratingVmsCount -gt 0) {
            throw "There are $migratingVmsCount active migrations. Resume operation at a later time"
        }

        Write-Host "$migratingVmsCount active migrations found."

        $XHmAuthorization = Get-AuthorizationToken -Credential $HcxAdminCredential -HcxServer $HcxServer
        $HcxMetaData = Get-HcxMetaData -HcxServer $HcxServer -XHmAuthorization $XHmAuthorization
        $HcxCurrentVersion = $HcxMetaData.endpoint.version
        if ($HcxCurrentVersion -lt $HcxPreferredVersion) {
            throw "Current HCX version: $HcxCurrentVersion is less than the prefered version: $HcxPreferredVersion"
        }

        Write-Host "Current HCX Version: $HcxCurrentVersion"

        Write-Host "Retrieving Appliances"
        $Appliances = Get-HCXAppliance

        if ($Appliances.Count -gt 0) {
            $VersionPerAppliance = @{
                Interconnect   = $HcxPreferredVersion;
                L2Concentrator = $HcxPreferredVersion
            }

            foreach ($Appliance in $appliances) {
                if ($VersionPerAppliance.ContainsKey("$($Appliance."Type")") -and
                    $Appliance."CurrentVersion" -lt $VersionPerAppliance["$($Appliance."Type")"]) {
                    throw "Current Appliance: $($Appliance."Type") version: $($Appliance."CurrentVersion") is less than the prefered version: $HcxPreferredVersion"
                }
            }
        }
        Write-Host "$Appliances appliances found."

        Write-Host "Retrieving HCX Guest VM Data"
        $HcxVmGuest = Get-VMGuest -VM $HcxVM

        $MonitoredDisks = @("/common")
        Invoke-DiskUtilizationThresholdCheck -DiskUtilizationTreshold $DiskUtilizationTreshold -MonitoredDisks $MonitoredDisks -Disks $HcxVmGuest.Disks

        Write-Host "Shutting Down Guest OS"
        Stop-VMGuest -VM $HcxVm -Confirm:$false | Out-Null
        while ($(Get-VMGuest -VM $HcxVm).State -ne 'NotRunning') {
            Start-Sleep -Seconds 5
            Write-Host "$($HcxVm.Name)'s Guest OS powerstate=$($(Get-VMGuest -VM $HcxVm).State)"
        }
        Write-Host "Guest OS is shut down"

        Write-Host "Configuring memory and cpu settings"
        Set-VM -VM $HcxVm -MemoryGB $HcxScaledMemoryGb -NumCpu $HcxScaledtNumCpu -Confirm:$false | Out-Null

        Write-Host "Starting $($hcxVm.Name)..."
        Start-VM -VM $HcxVm -Confirm:$false | Out-Null
        Write-Host "$($hcxVm.Name)'s powerstate=$($hcxVm.PowerState)"

        Write-Host "Waiting for successful connection to HCX appliance..."
        $hcxConnection = Test-HcxConnection -Server $HcxServer -Count 12 -Port $Port -Credential $HcxAdminCredential -HcxVm $HcxVm

        $HcxVm = Get-VM -Name $HcxVm.Name
        Write-Host "$($hcxVm.Name)'s CPU: $($HcxVm.NumCpu) and Memory: $($HcxVm.MemoryGb) Gb Settings"
        Write-Host "Configuration complete"
    }
    catch {
        Write-Error $_
    }
    finally {
        $global:DefaultVIServers = $DefaultViConnection

        if ($hcxConnection) {
            Write-Host "Disconnecting from HCX Server."
            Disconnect-HCXServer -Server $hcxConnection -Confirm:$false -Force
        }
        Remove-TempUser -userName $UserName -userRole $UserRole
    }
}

<#
    .Synopsis
     This will create a folder on every datastore (/vmfs/volumes/datastore/tools-repo) and set the ESXi hosts to use that folder as the tools-repo.
     The customer is responsible for putting the VMware Tools zip file in a downloadable location.

     .EXAMPLE
     Once the function is imported, you simply need to run Set-ToolsRepo -ToolsURL <url to tools zip file>
#>

function Set-ToolsRepo
{
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $true,
        HelpMessage = "A URL to download the Tools zip file.")]
        [SecureString]
        $ToolsURL
    )

    # Tools repo folder
    $newFolder = 'tools-repo'

    # Get all datastores
    try
    {
        $datastores = Get-Datastore -ErrorAction Stop | Where-Object { $_.extensionData.Summary.Type -eq "vsan" }
    }
    catch
    {
        Write-Error -Message "Unable to get datastores. $($_.Exception.Message)"
    }

    # Download the new tools files
    Invoke-WebRequest -Uri $ToolsURL -OutFile "newtools.zip"
    Expand-Archive "./newtools.zip"

    # Make sure the new tools files exist
    If (!(Test-Path "./newtools/vmtools"))
    {
        Write-Error -Message "Unable to find new tools files"
        throw "Unable to find new tools files"
    }

    foreach ($datastore in $datastores)
    {
        # Get datastore name
        $ds_name = $datastore.Name

        # Get ID of the vsanDatastore requested
        $ds_id = Get-Datastore -Name $ds_name | Select-Object -Property Id

        # Create the PS drive
        New-PSDrive -Location $datastore -Name DS -PSProvider VimDatastore -Root "\" | Out-Null

        # Does repo folder exist?
        $Dsbrowser = Get-View -Id $Datastore.Extensiondata.Browser
        $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
        $spec.Query += New-Object VMware.Vim.FolderFileQuery
        $folderObj = ($dsBrowser.SearchDatastore("[$ds_name] \", $spec)).File | Where-Object { $_.FriendlyName -eq $newFolder }

        # If not, create it
        If ($nil -eq $folderObj)
        {
            New-Item -ItemType Directory -Path "DS:/$newFolder"
            # Recheck
            $folderObj = ($dsBrowser.SearchDatastore("[$ds_name] \", $spec)).File | Where-Object { $_.FriendlyName -eq $newFolder }
            If ($nil -eq $folderObj)
            {
                Write-Error -Message "Folder creation failed on $ds_name"
            }
            else
            {
                Write-Host "Folder creation successful on $ds_name"
            }
        }
        else {
            # Remove old tools files
            Remove-Item -Path "DS:/$newFolder/floppies" -Recurse -ErrorAction SilentlyContinue
            Remove-Item -Path "DS:/$newFolder/vmtools" -Recurse -ErrorAction SilentlyContinue
        }

        Copy-DatastoreItem -Item "./newtools/*" "DS:/$newFolder" -Recurse

        # Remove the PS drive
        Remove-PSDrive -Name DS -Confirm:$false

        # List of hosts attached to that datastore
        $vmhosts = Get-VMHost | Where-Object { $_.ExtensionData.Datastore.value -eq ($ds_id.Id).Split('-', 2)[1] }

        $repo_dir = "/vmfs/volumes/$ds_name/$newFolder"

        # Set the tools-repo
        foreach ($vmhost in $vmhosts)
        {
            $vmhost.ExtensionData.UpdateProductLockerLocation($repo_dir) | Out-Null
        }

        # Check the tools-repo
        $exist_repo = ($vmhosts | Get-AdvancedSetting -Name "UserVars.ProductLockerLocation" | Select-Object Entity, Value) | Select-Object -Unique
        If (($exist_repo.Value -ne $repo_dir) -or ($exist_repo.count -ne 1))
        {
            Write-Error -Message "Failed to set tools-repo on all hosts for datastore $ds_name"
        }
        else
        {
            Write-Host "Successfully set tools-repo on all hosts for datastore $ds_name"
        }
    }
}