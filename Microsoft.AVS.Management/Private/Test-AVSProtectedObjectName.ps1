Function Test-AVSProtectedObjectName {
    <#
        .NOTES :
        --------------------------------------------------------
        Created by: K. Chris Nakagaki
            Organization    : Microsoft
            Copyright (c) Microsoft. All rights reserved.
        --------------------------------------------------------

    .DESCRIPTION
        This function tests if an object name is valid.
    .PARAMETER Name
        Name of Object
    .EXAMPLE
        Test-AVSProtectedObjectName -Name "Encryption"
        Returns True if the name is protected.

    #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]
            $Name
        )
        Begin {
            #Protected Policy Object Name Validation Check
        $ProtectedNames = @(
            "Microsoft vSAN Management Storage Policy"
            "VMware_Horizon"
            "vSAN Default Storage Policy"
            "AVS POST IO Encryption"
            "AVS PRE IO Encryption"
            "RAID-1 FTT-1"
            "RAID-1 FTT-1 Dual Site"
            "RAID-1 FTT-1 Preferred"
            "RAID-1 FTT-1 Secondary"
            "RAID-1 FTT-2"
            "RAID-1 FTT-2 Dual Site"
            "RAID-1 FTT-2 Preferred"
            "RAID-1 FTT-2 Secondary"
            "RAID-1 FTT-3"
            "RAID-1 FTT-3 Dual Site"
            "RAID-1 FTT-3 Preferred"
            "RAID-1 FTT-3 Secondary"
            "RAID-5 FTT-1"
            "RAID-5 FTT-1 Dual Site"
            "RAID-5 FTT-1 Preferred"
            "RAID-5 FTT-1 Secondary"
            "RAID-6 FTT-2"
            "RAID-6 FTT-2 Dual Site"
            "RAID-6 FTT-2 Preferred"
            "RAID-6 FTT-2 Secondary")
            $Name = Limit-WildcardsandCodeInjectionCharacters -String $Name
        }
        Process {
            ForEach ($ProtectedName in $ProtectedNames) {
                if ($ProtectedName -eq $Name) {
                    Write-Error "$ProtectedName is protected a name.  Please use a different name."
                    Return $true
                    return
                }
            }
                Write-Host -ForegroundColor Green "$Name is not a protected name."
                Return $false
        }
    }