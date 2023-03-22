<#PSScriptInfo

.VERSION 1.0

.GUID b28778e8-2fd5-4ab1-a4bd-8026dc75d14b

.AUTHOR K. Chris Nakagaki

.COMPANYNAME Microsoft

.COPYRIGHT (c) Microsoft. All rights reserved.

.DESCRIPTION PowerShell private functions for AVS Storage Policy manipulation

#>

Function New-AVSCommonStoragePolicy {
    <#
        .DESCRIPTION
            This function creates a new or overwrites an existing vSAN Storage Policy.
        .PARAMETER Name
            Name of Common Storage Policy
        .PARAMETER Description
            Default is None.  Valid values are None, Site mirroring - stretched cluster, "None - keep data on Preferred (stretched cluster)", "None - keep data on Secondary (stretched cluster)", "None - stretched cluster"
        .PARAMETER Encryption
            To make an encryption common storage policy.  Will require PostIOEncryption parameter.
        .PARAMETER PostIOEncryption
            Valid values are True or False. False encrypts VM prior to VAIO Filter. True encrypts VM after VAIO Filter.
        .PARAMETER StorageIO
            To make a storage IO common storage policy.  Will require IOLimit, IOReservation, and IOShares parameters.
        .PARAMETER IOLimit
            TODO:  Need to add more information about this parameter.
        .PARAMETER IOReservation
            TODO:  Need to add more information about this parameter.
        .PARAMETER IOShares
            TODO:  Need to add more information about this parameter.
        .EXAMPLE
            New-AVSCommonStoragePolicy -Name "Encryption" -Encryption -PostIOEncryption $true
        .EXAMPLE
            New-AVSCommonStoragePolicy -Name "StorageIO" -StorageIO -IOLimit 1000 -IOReservation 100 -IOShares 100
    
    #>
    
    [CmdletBinding(DefaultParameterSetName = "Encryption")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Encryption", Position = 0)]
        [switch]
        $Encryption,
    
        [Parameter(Mandatory = $true, ParameterSetName = "StorageIO", Position = 0)]
        [switch]
        $StorageIO,
    
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
    
        [Parameter(Mandatory = $false)]
        [string]
        $Description,
    
        [Parameter(Mandatory = $true, ParameterSetName = 'Encryption')]
        [bool]
        $PostIOEncryption,
    
        [Parameter(Mandatory = $true, ParameterSetName = 'StorageIO')]
        [int]$IOLimit,
        [Parameter(Mandatory = $true, ParameterSetName = 'StorageIO')]
        [int]$IOReservation,
        [Parameter(Mandatory = $true, ParameterSetName = 'StorageIO')]
        [int]$IOShares
    )
    Begin {
        If ($Encryption) {
            $policyconstraintType = "ENCRYPTION"
            $policycategory = "DATA_SERVICE_POLICY" #Valid options are REQUIREMENT or RESOURCE or DATA_SERVICE_POLICY
            $policyresourceType = "STORAGE" #The only valid option, basically pointless
            $policydescription = $description
        }
        ElseIf ($StorageIO) {
            $policyconstraintType = "STORAGEIO"
            $policycategory = "DATA_SERVICE_POLICY" #Valid options are REQUIREMENT or RESOURCE or DATA_SERVICE_POLICY
            $policyresourceType = "STORAGE" #The only valid option, basically pointless
            $policydescription = $description
        }
        Else {
            Write-Error "Invalid Parameter Set"
            Return
        }
    }
    process {
        $serviceInstanceView = Get-SpbmView -Id "PbmServiceInstance-ServiceInstance"
        $spbmServiceContent = $serviceInstanceView.PbmRetrieveServiceContent()
        $spbmProfMgr = Get-SpbmView -Id $spbmServiceContent.ProfileManager
        $profilespec = new-object VMware.Spbm.Views.PbmCapabilityProfileCreateSpec
        $subprofile = new-object VMware.Spbm.Views.PbmCapabilitySubProfile
        switch ($policyconstraintType) {
            Encryption {
                $subprofile.Name = "Encryption sub-profile"
                $subprofile.Capability = New-Object VMware.Spbm.Views.PbmCapabilityInstance
                $subprofile.Capability[0].Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $subprofile.Capability[0].Id.Namespace = "vmwarevmcrypt"
                $subprofile.Capability[0].Id.Id = "vmwarevmcrypt@ENCRYPTION"
                $subprofile.Capability[0].Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $subprofile.Capability[0].Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $subprofile.Capability[0].Constraint[0].PropertyInstance[0].id = "AllowCleartextFilters" #AllowCleartextFilters only known valid value
                If ($PostIOEncryption) {
                    $subprofile.Capability[0].Constraint[0].PropertyInstance[0].value = "True" #String Value, not Boolean
                }
                Else {
                    $subprofile.Capability[0].Constraint[0].PropertyInstance[0].value = "False" #String Value, not Boolean
                }
            }
    
            StorageIO {
                $subprofile.Name = "SIOC sub-profile"
                $subprofile.Capability = New-Object VMware.Spbm.Views.PbmCapabilityInstance
                $subprofile.Capability[0].Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $subprofile.Capability[0].Id.Namespace = "spm"
                $subprofile.Capability[0].Id.Id = "spm@DATASTOREIOCONTROL"
                $subprofile.Capability[0].Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Limit = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Limit.id = "limit"
                $Limit.value = $IOLimit
                $Reservation = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Reservation.id = "reservation"
                $Reservation.value = $IOReservation
                $Shares = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Shares.id = "shares"
                $Shares.value = $IOShares
                $subprofile.Capability[0].Constraint[0].PropertyInstance = @($Limit, $Reservation, $Shares)
            }
        }
        $pbmprofileresourcetype = new-object vmware.spbm.views.PbmProfileResourceType
        $pbmprofileresourcetype.ResourceType = $policyresourceType
        $profileconstraints = new-object vmware.spbm.views.PbmCapabilitySubProfileConstraints
        $profileconstraints.SubProfiles = @($subprofile)
    
        $profilespec.ResourceType = $pbmprofileresourcetype
        $profilespec.Name = $Name
        $profilespec.Constraints = $profileconstraints
        $profilespec.Description = $policydescription
        $profilespec.Category = $policycategory
        $profileuniqueID = $spbmProfMgr.PbmCreate($profilespec)
        $profileuniqueID.UniqueId
    }
    
}
    

Function Get-AVSSPBMCapabilities {

    <#
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
    End { return $results }
}

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
        $ResourceType = "REQUIREMENT"
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

