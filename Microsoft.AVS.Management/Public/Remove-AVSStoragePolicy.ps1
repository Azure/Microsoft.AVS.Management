Function Remove-AVSStoragePolicy {
    <#
        .NOTES :
        --------------------------------------------------------
        Created by: K. Chris Nakagaki
        Organization    : Microsoft
        Copyright (c) Microsoft. All rights reserved.
        --------------------------------------------------------

    .DESCRIPTION
        This function removes a storage policy.
    .PARAMETER Name
        Name of Storage Policy
    .EXAMPLE
        Remove-AVSStoragePolicy -Name "Encryption"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    Begin {
        #Remove Wildcards characters from Name
        $Name = Limit-WildcardsandCodeInjectionCharacters $Name
        #Protected Policy Object Name Validation Check
        If (Test-AVSProtectedObjectName -Name $Name) {
            Write-Error "$Name is a protected policy name.  Please choose a different policy name."
            return
        }

        }
    Process {
        #Get Storage Policy
        $StoragePolicy = Get-SpbmStoragePolicy -Name $Name -ErrorAction SilentlyContinue
        #Remove Storage Policy
        If ([string]::IsNullOrEmpty($StoragePolicy)) {
            Write-Error "Storage Policy $Name does not exist."
            return
        }
        Else{Remove-SpbmStoragePolicy -StoragePolicy $StoragePolicy -Confirm:$false}

    }
}