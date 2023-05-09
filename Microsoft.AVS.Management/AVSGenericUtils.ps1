<#PSScriptInfo

.VERSION 1.1

.GUID ce8e0201-4bcd-4e42-9918-1f81d110f520

.AUTHOR K. Chris Nakagaki

.COMPANYNAME Microsoft

.COPYRIGHT (c) Microsoft. All rights reserved.

.DESCRIPTION Powershell generic private functions for general manipulation or validation of strings.

#>

Function Test-AVSProtectedObjectName {
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

Function Convert-StringToArray {
    <#
        .DESCRIPTION
            This function converts a string to an array based on defined delimiter.
        .PARAMETER String
            String value to convert into an array.
        .PARAMETER Delimiter
            Delimiter to use to split the string into an array. 
            Default is ","
        .PARAMETER TrimandCleanup
            Removes any empty entries and preceding/trailing spaces. 
            Default is $true.
    #>
    
    [CmdletBinding(DefaultParameterSetName = "Encryption")]
    param ( 
        [Parameter(Mandatory = $true)]
        [string]
        $String,
        [Parameter(Mandatory = $false)]
        [string]
        $Delimiter = ",",
        [Parameter(Mandatory = $false)]
        [boolean]
        $TrimandCleanup = $true
    )
    Begin {
        #Convert string to array
        Switch ($TrimandCleanup) {
            $true { $Array = $String.Split($Delimiter, [System.StringSplitOptions]::RemoveEmptyEntries).Trim() }
            $false { $Array = $String.Split($Delimiter) }
        }
        
    }
    Process {
        Return $Array
    }
    
}

Function Add-AVSTag{
    <#
        .DESCRIPTION
            This function creates or adds a tag w/ associated to an AVS Tag Category
        .PARAMETER Name
            Name of Tag to create or add.
        .PARAMETER Description
            Description of Tag.
        .PARAMETER Entity
            vCenter Object to add tag to.
    #>
    
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        [Parameter(Mandatory = $false)]
        [string]
        $Description,
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Interop.V1.VIObjectCoreInterop]
        $Entity
    )
    Begin {
        $TagCategory = Get-TagCategory -Name "AVS"
        If (!$TagCategory) {
            $TagCategory = New-TagCategory -Name "AVS" -Description "Category for AVS Operations" -Cardinality:Multiple
        }
        $Tag = Get-Tag -Name $Name -Category $TagCategory
        If (!$Tag) {
            $Tag = New-Tag -Name $Name -Description $Description -Category $TagCategory
        }
        }
        
    Process {
        try {
            New-TagAssignment -Tag $Tag -Entity $Entity -ErrorAction Stop
            return
        }
        catch {
            <#Do this if a terminating exception happens#>
        }

    }
    
}