<#
    .Synopsis
    Adds a user account to an existing group

    .Parameter userName
    Specifies the user name of the requested user account

    .Parameter group
    Specifies the group in which to add the user acount to

    .Example
    Add-UserToGroup -userName TempUser -group CloudAdmins
#>
function Add-UserToGroup {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User name of the a user account')]
        [ValidateNotNull()]
        [string]
        $userName,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Group instance to add a user account to')]
        [ValidateNotNull()]
        [string]
        $group
    )

    $domain = "vsphere.local"
    Write-Host "Adding $userName user to $group in $domain."

    $SsoGroup = Get-SsoGroup -Name $group -Domain $domain
    Get-SsoPersonUser -Name $userName -Domain $domain -ErrorAction Stop | Add-UserToSsoGroup -TargetGroup $SsoGroup -ErrorAction Stop | Out-Null
}

<#
    .Synopsis
    Creates a temporary user and role with required privileges.
    The user is used to pass credentials into vcenter rest api calls for functionalites unavailable to powercli

    .Parameter privileges
    Array of user privileges (default value is an empty array)

    .Parameter userName
    Specifies the user name of the requested user account

    .Parameter userRole
    Specifies the role of the requested user account

    .Parameter group
    Specifies the group in which to add the user acount to

    .Example
    New-TempUser -privileges @("VirtualMachine.Config.CPUCount","VirtualMachine.Config.Memory") -userName TempUser -userRole TempRole
#>
function New-TempUser {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Array of user privileges")]
        [array]
        $privileges = @(),

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User name of the new user account')]
        [ValidateNotNull()]
        [string]
        $userName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Role of the new user account')]
        [ValidateNotNull()]
        [string]
        $userRole,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Group instance to add the new user account to')]
        [ValidateNotNull()]
        [string]
        $group
    )

    if($privileges.Count -eq 0) { throw "If adding a temporary user, please ensure you pass in at least one privilege"}

    $domain = "vsphere.local"
    $userPrincipal = $domain + "\" +  $userName

    Write-Host "Checking for existing $userName."

    if(Assert-UserExists -userName $userName -domain $domain) {
        Write-Host "$userName already exists in domain: $domain. Removing old $userName."
        Remove-SsoPersonUser -User $(Get-SsoPersonUser -Name $userName -Domain $domain) -ErrorAction Stop
    }

    Write-Host "Creating $userName user in $domain."

    $userPassword = New-RandomPassword
    New-SsoPersonUser -UserName $userName -Password $userPassword -Description "TemporaryUser" -FirstName $userName -LastName $domain -ErrorAction Stop | Out-Null

    if($group) { Add-UserToGroup -userName $userName -group $group }

    if(Assert-RoleExists -userRole $userRole) {
        $joinedPrivileges = ($privileges -join ";")
        Write-Host "Role: $userRole already exists. Removing and recreating role with the following new privileges: $joinedPrivileges"

        Remove-VIRole -Role (Get-VIRole -Name $userRole) -Force:$true -Confirm:$false | Out-Null

        Write-Host "Removed $userRole. Creating new user role."
    }

    New-VIRole -name $userRole -Privilege (Get-VIPrivilege -Server $VC_ADDRESS -id $privileges) -Server $VC_ADDRESS -ErrorAction Stop | Out-Null
    Write-Host "Role $userRole created on $VC_ADDRESS"

    $rootFolder = Get-Folder -NoRecursion
    New-VIPermission -Entity $rootFolder -Principal $userPrincipal -Role $userRole -Propagate:$true -ErrorAction Stop | Out-Null

    if(Assert-UserExists -userName $userName -domain $domain) {
        Write-Host "Sucessfully created temporary User: $userName and assigned Role: $userRole"

        $fullUsername = $userName + "@" + $domain
        $secureUserPassword =  ConvertTo-SecureString $userPassword -AsPlainText -Force

        return New-Object System.Management.Automation.PSCredential ($fullUsername, $secureUserPassword)
    }
    else { throw "Temporary User: $userName was not created." }
}

<#
    .Synopsis
    Removes a temporary user and role account.

    .Parameter userName
    Specifies the user name of the requested user account

    .Parameter userRole
    Specifies the role of the requested user account

    .Example
    Remove-TempUser -userName TempUser -userRole TempRole
#>
function Remove-TempUser {
    [CmdletBinding()]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User name of the user account to be removed')]
        [ValidateNotNull()]
        [string]
        $userName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Role of the user account to be removed')]
        [ValidateNotNull()]
        [string]
        $userRole
    )

    $domain = "vsphere.local"

    Write-Host "Checking for existing User: $userName."

    if(Assert-UserExists -userName $userName -domain $domain) {
        Write-Host "Removing user: $userName."
        Remove-SsoPersonUser -User $(Get-SsoPersonUser -Name $userName -Domain $domain) -ErrorAction Stop
    }

    Write-Host "Checking for existing Role: $userRole."

    if(Assert-RoleExists -userRole $userRole) {
        Write-Host "Removing role: $userRole"
        Remove-VIRole -Role (Get-VIRole -Name $userRole) -Force:$true -Confirm:$false | Out-Null
    }
}

<#
    .Synopsis
    Provided a userName and a domain this cmdlet returns whether or not the user exists in the domain.

    .Parameter userName
    Specifies the user name to filter on when searching for user accounts

    .Parameter domain
    Specifies the domain in which search will be applied (default value is vsphere.local)

    .Example
    Assert-UserExists -userName TempUser -domain "vsphere.local"
#>
Function Assert-UserExists {
    [CmdletBinding()]
    param(
        [parameter(
            Mandatory = $true,
            HelpMessage = "User name filter to be applied when searching for user accounts")]
        [string]
        $userName,

        [parameter(
            Mandatory = $false,
            HelpMessage = 'Domain name to search in, default is "vsphere.local"')]
        [string]
        $domain = "vsphere.local"
    )

    Process {
        if(Get-SsoPersonUser -Name $userName -Domain $domain -ErrorAction SilentlyContinue) {
            Write-Host "$userName exists in $VC_ADDRESS, domain: $domain."
            return $true;
        }

        Write-Host "$userName doesn't exist in $VC_ADDRESS, domain: $domain."
        return $false;
    }
}

<#
    .Synopsis
    Provided a role this cmdlet returns true if the role exists, otherwise return false.

    .Parameter userRole
    Specifies role name to filter on when searching for user accounts

    .Example
    Assert-RoleExists -userRole <role>
#>
Function Assert-RoleExists {
    [CmdletBinding()]
    param(
        [parameter(
            Mandatory = $true,
            HelpMessage = "User role filter to be applied when searching for user accounts")]
        [string]
        $userRole
    )

    Process {
        if(Get-VIRole -Name $userRole -ErrorAction SilentlyContinue) {
            Write-Host "$userRole exists in $VC_ADDRESS"
            return $true
        }

        Write-Host "$userRole does not exist in $VC_ADDRESS"
        return $false;
    }
}

<#
    .Synopsis
    Generates a password with at least 2 uppercase, 4 lowercase, 4 digits & 2 special character (!@#$%^&*())
#>
Function New-RandomPassword {
    $upperChars = (65..90)
    $lowerChars = (97..122)
    $numerics = (48..57)
    $specialChars = @(33, 35, 36, 37, 38, 40, 41, 42, 45, 64, 94)

    $seedArray = ($upperChars | Get-Random -Count 2)
    $seedArray += ($lowerChars | Get-Random -Count 4)
    $seedArray += ($numerics | Get-Random -Count 4)
    $seedArray += ($specialChars | Get-Random -Count 2)

    Foreach ($a in $seedArray){
        $passwordAscii += , [char][byte]$a
    }

    $password = $passwordAscii -join ""

    return $password
}