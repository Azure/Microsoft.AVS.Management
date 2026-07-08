<#PSScriptInfo

.VERSION 2.0

.GUID ce8e0201-4bcd-4e42-9918-1f81d110f520

.AUTHOR K. Chris Nakagaki

.COMPANYNAME Microsoft

.COPYRIGHT (c) Microsoft. All rights reserved.

.DESCRIPTION Powershell generic private functions for general manipulation or validation of strings.

#>

function Test-AVSProtectedObjectName {
    <#
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
    begin {
        #Protected Policy Object Name Validation Check
        $ProtectedNames = @(
            "Microsoft vSAN Management Storage Policy"
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
            "RAID-6 FTT-2 Secondary"
            "NsxViAdministrator"
            "HMSCloudAdmin"
            "HmsReplicationUser"
            "HmsView"
            "jea-ro-role"
            "HmsAdmin"
            "jea-admin-role"
            "HmsDatastoreUser"
            "vStatsAdmin"
            "HmsCloudAdmin"
            "jea-ca-role"
            "VirtualMachinePowerUser"
            "VirtualMachineUser"
            "ResourcePoolAdministrator"
            "VMwareConsolidatedBackupUser"
            "DatastoreConsumer"
            "NetworkConsumer"
            "VirtualMachineConsoleUser"
            "AutoUpdateUser"
            "InventoryService.Tagging.TaggingAdmin"
            "SyncUsers"
            "vSphere Client Solution User"
            "WorkloadStorageManagement"
            "vSphereKubernetesManager"
            "com.vmware.Content.Registry.Admin"
            "SupervisorServiceCluster"
            "SupervisorServiceRootFolder"
            "SupervisorServiceGlobal"
            "VMOperatorController"
            "VMOperatorControllerGlobal"
            "NSOperatorController"
            "SrmAdministrator"
            "SrmProtectionGroupsAdministrator"
            "SrmRecoveryPlansAdministrator"
            "SrmTestAdministrator"
            "SrmRecoveryAdministrator"
            "SrmRemoteUser"
            "HmsDiagnostics"
            "vCLSAdmin"
            "vStatsUser"
            "HmsRecoveryUser"
            "VMServicesAdministrator"
            "NSX Administrator"
            "com.vmware.Content.Admin"
            "CloudAdmin"
            "HmsRemoteUser"
            "NsxAuditor"
        )
        $Name = Limit-WildcardsandCodeInjectionCharacters -String $Name
    }
    process {
        # Check if the name is in the protected names list
        # If it is a protected name 'throw' and don't continue
        if ($ProtectedNames -contains $Name) {
            throw "$Name is a protected name.  Please use a different name."
        }
        # If not a protected name, return false
        Write-Information "$Name is not a protected name."
        return $false
    }
}

Function Limit-WildcardsandCodeInjectionCharacters {
    <#
        .DESCRIPTION
            This function removes wildcards and code injection characters from a string.
        .PARAMETER String
            String to remove wildcards and code injection characters from.
        .EXAMPLE
            Limit-WildcardsandCodeInjectionCharacters -String "Encryption*"
            Returns "Encryption"
        .EXAMPLE
            Limit-WildcardsandCodeInjectionCharacters -String "|Encryption?*"
            Returns "Encryption"

        #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )
    Begin {
        #Remove Wildcards characters from string
        $String = $String.Replace("*", "").Replace("?", "").Replace("[", "").Replace("]", "").Replace(";", "").Replace("|", "").Replace("\", "").Replace('$_', "").Replace("{", "").Replace("}", "")
    }
    Process {
        Return $String
    }

}

function Normalize-VCBannerText {
    <#
        .DESCRIPTION
            This function normalizes vCenter login banner text by replacing smart quotes,
            cleaning unsupported characters, and preserving paragraph line breaks.
        .PARAMETER String
            Banner text to normalize.
        .EXAMPLE
            Normalize-VCBannerText -String "Welcome to \"AVS\""
            Returns normalized text that is safe to pass to banner commands.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )
    begin {
        # Normalize smart single and double quotes to ASCII quotes.
        $String = $String.Replace([char]0x2018, "'").Replace([char]0x2019, "'")
        $String = $String.Replace([char]0x201C, '"').Replace([char]0x201D, '"')

        # Normalize non-breaking space to regular space.
        $String = $String.Replace([char]0x00A0, ' ')

        # Remove shell-sensitive special characters.
        $String = $String.Replace("&", "").Replace("$", "")
        $String = $String.Replace([string][char]0x0060, "")
        $String = $String.Replace("(", "").Replace(")", "")
        $String = $String.Replace("<", "").Replace(">", "")

        # Remove emojis and unsupported symbols, while preserving letters, numbers,
        # punctuation, spaces, and new lines.
        $String = $String -replace '[^\p{L}\p{N}\p{P}\p{Zs}\t\r\n]', ''

        # Collapse repeated spaces and tabs per line, preserving line breaks.
        $lines = $String -split "(\r?\n)"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch '^\r?\n$') {
                $lines[$i] = ($lines[$i] -replace '[ \t]{2,}', ' ').TrimEnd()
            }
        }
        $String = $lines -join ''
    }
    process {
        return $String
    }
}
