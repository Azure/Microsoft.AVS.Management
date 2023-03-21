Function Limit-WildcardsandCodeInjectionCharacters {
    <#
        .NOTES :
        --------------------------------------------------------
        Created by: K. Chris Nakagaki
            Organization    : Microsoft
            Copyright (c) Microsoft. All rights reserved.
        --------------------------------------------------------
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
        $String = $String.Replace("*","").Replace("?","").Replace("[","").Replace("]","").Replace(";","").Replace("|","").Replace("\","").Replace('$_',"").Replace("{","").Replace("}","")
    }
    Process {
        Return $String
    }

}