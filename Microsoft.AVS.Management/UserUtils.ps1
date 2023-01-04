
<#
    .Synopsis
    Creates a temporary user and a role which includes required privileges.
    The user is used to pass credentials into vcenter rest api calls for functionalites unavailable to powercli

    .Parameter privileges
    Array of user privileges (default value is an empty array)

    .Parameter userName
    User-Friendly name for the user

    .Parameter userRole
    User-Friendly name for the role

    .Example
    New-TempUser -privileges @("VirtualMachine.Config.CPUCount","VirtualMachine.Config.Memory") -userName TempUser -userRole TempRole
#>
function New-TempUser {
    Param (
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Array of user privileges")]
        [array]
        $privileges = @(),

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User-Friendly name for the user')]
        [ValidateNotNull()]
        [string]
        $userName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'User-Friendly name for the role')]
        [ValidateNotNull()]
        [string]
        $userRole
    )

    if($privileges.Count -eq 0) { throw "If adding a temporary user, please ensure you pass in at least one privilege"}

    $domain = "vsphere.local"
    $group = "CloudAdmins"
    $userPrincipal = $domain + "\" +  $userName
    $SsoGroup = Get-SsoGroup -Name $group -Domain $domain

    Write-Host "Checking for existing $userName."

    if(Assert-UserExists -userName $userName -domain $domain) {
        Write-Host "$userName already exists in domain: $domain. Removing old $userName."
        Remove-SsoPersonUser -User $(Get-SsoPersonUser -Name $userName -Domain $domain) -ErrorAction Stop
    }

    Write-Host "Creating $userName user in $domain."

    $userPassword = New-RandomPassword
    New-SsoPersonUser -UserName $userName -Password $userPassword -Description "TemporaryUser" -FirstName $userName -LastName "TempUser" -ErrorAction Stop | Out-Null

    Write-Host "Adding $userName user to $group in $domain."

    $SsoGroup = Get-SsoGroup -Name $group -Domain $domain
    Get-SsoPersonUser -Name $userName -Domain $domain -ErrorAction Stop | Add-UserToSsoGroup -TargetGroup $SsoGroup -ErrorAction Stop | Out-Null

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

    Write-Host "Sucessfully created temporary User: $userName and assigned Role: $userRole"

    $fullUsername = $userName + "@" + $domain
    $secureUserPassword =  ConvertTo-SecureString $userPassword -AsPlainText -Force

    return New-Object System.Management.Automation.PSCredential ($fullUsername, $secureUserPassword)
}

<#
    .Synopsis
    Removes a temporary user and role.

    .Parameter userName
    Name of the user

    .Parameter userRole
    Name of the role

    .Example
    Remove-TempUser -userName TempUser -userRole TempRole
#>
function Remove-TempUser {
    [CmdletBinding(PositionalBinding = $false)]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    Param
    (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the user')]
        [ValidateNotNull()]
        [string]
        $userName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Name of the role')]
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
    Get a userName and a domain, and return whether or not the user exists in the domain.

    .Parameter userName
    User name (default value is TempUser)

    .Parameter domain
    Domain name (default value is vsphere.local)

    .Example
    Assert-UserExists -userName TempUser -domain "vsphere.local"
#>
Function Assert-UserExists {
    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [parameter(
            Mandatory=$false,
            HelpMessage = "User name")]
        [string]
        $userName = "TempUser",

        [parameter(
            Mandatory=$false,
            HelpMessage = "Domain to search the user at")]
        [string]
        $domain = "vsphere.local"
    )

    Process {
        Write-Host "Starting $($MyInvocation.MyCommand)..."

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
    Return true if role exists, otherwise return false.

    .Parameter userRole
    Role name (default value is TempRole)

    .Example
    Assert-RoleExists -userRole <role>
#>
Function Assert-RoleExists {
    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [parameter(Mandatory=$false,
            HelpMessage = "Role name")]
        [string]$userRole = "TempRole"
    )

    Process {
        Write-Host "Starting $($MyInvocation.MyCommand)..."

        If (Get-VIRole -Name $userRole -ErrorAction SilentlyContinue) {
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
    Write-Host "Starting $($MyInvocation.MyCommand)..."

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