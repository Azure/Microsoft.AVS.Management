Function Get-AVSStoragePolicy {
    <#
        .NOTES :
        --------------------------------------------------------
        Created by: K. Chris Nakagaki
            Organization    : Microsoft
            COPYRIGHT (c) Microsoft. All rights reserved.
        --------------------------------------------------------

    .DESCRIPTION
        This function gets a list of all storage policy of specific type.
    .PARAMETER Name
        Name of Storage Policy
    .PARAMETER ResourceType
        Valid values are RESOURCE, DATA_SERVICE_POLICY, or REQUIREMENT
        Default is REQUIREMENT
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [SupportsWildcards()]
        [string]
        $Name,
        [Parameter(Mandatory = $false)]
        [ValidateSet("RESOURCE", "DATA_SERVICE_POLICY", "REQUIREMENT")]
        [string]
        $ResourceType="REQUIREMENT"
    )
    Begin {
        $serviceInstanceView = Get-SpbmView -Id "PbmServiceInstance-ServiceInstance"
        $spbmServiceContent = $serviceInstanceView.PbmRetrieveServiceContent()
        $spbmProfMgr = Get-SpbmView -Id $spbmServiceContent.ProfileManager

        $pbmprofileresourcetype = new-object vmware.spbm.views.PbmProfileResourceType
        $pbmprofileresourcetype.ResourceType = "STORAGE"

        $profiles = $spbmProfMgr.PbmQueryProfile($pbmprofileresourcetype, $ResourceType)
        if ([string]::IsNullOrEmpty($profiles)) {
            Write-Host "$ResourceType resourcetype produced no results"
            return
        }
        $registeredprofiles = $spbmProfMgr.PbmRetrieveContent($profiles)
    }
    Process {
        if ($Name) {
            if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Name)) {
                $registeredprofiles | Where-Object { $_.name -like $Name }
            }
            elseif (![System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Name)) {
                $registeredprofiles | Where-Object { $_.name -eq $Name }
            }

        }
        else {
            $registeredprofiles
        }
    }
    End {
    }
}

