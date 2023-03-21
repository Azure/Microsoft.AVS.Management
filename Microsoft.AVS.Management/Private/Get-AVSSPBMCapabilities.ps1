Function Get-AVSSPBMCapabilities {

    <#
        .NOTES :
        --------------------------------------------------------
        Created by: K. Chris Nakagaki
            Organization    : Microsoft
            e-mail          : Chris.Nakagaki@microsoft.com
        --------------------------------------------------------
        .DESCRIPTION
        This is meant to pull the capabilities of the SPBM service for application to storage profiles.
#>
    Begin {
        $serviceInstanceView = Get-SpbmView -Id "PbmServiceInstance-ServiceInstance"
        $spbmServiceContent = $serviceInstanceView.PbmRetrieveServiceContent()
        $spbmProfMgr = Get-SpbmView -Id $spbmServiceContent.ProfileManager
        $pbmprofileresourcetype = new-object vmware.spbm.views.PbmProfileResourceType
        $pbmprofileresourcetype.ResourceType = "STORAGE"
        $spbmvendors = $spbmProfMgr.PbmFetchVendorInfo($null)
        $results = @()
    }

    Process {
        Foreach ($spbmvendor in $spbmvendors) {
            Foreach ($namespace in $spbmvendor.VendorNamespaceInfo) {
                Foreach ($vendor in $namespace.vendorinfo) {
                    #$vendor.vendoruuid
                    $TempObjs = $spbmprofmgr.PbmFetchCapabilityMetadata($pbmprofileresourcetype, $vendor.VendorUuid)
                    Foreach ($TempObj in $TempObjs) {
                        $TempObj | Add-Member -MemberType NoteProperty -Name 'NameSpace' -Value $namespace.NamespaceInfo.Namespace
                        $results += $TempObj
                    }
                }
            }
        }
    }
    End{return $results}
}