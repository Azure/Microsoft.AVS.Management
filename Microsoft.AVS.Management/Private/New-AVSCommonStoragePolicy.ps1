Function New-AVSCommonStoragePolicy {
<#
        .NOTES :
        --------------------------------------------------------
        Created by: K. Chris Nakagaki
            Organization    : Microsoft
            COPYRIGHT (c) Microsoft. All rights reserved.
        --------------------------------------------------------
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
    [Parameter(Mandatory=$true, ParameterSetName = "Encryption", Position = 0)]
    [switch]
    $Encryption,

    [Parameter(Mandatory=$true, ParameterSetName = "StorageIO", Position = 0)]
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
} ElseIf ($StorageIO) {
    $policyconstraintType = "STORAGEIO"
    $policycategory = "DATA_SERVICE_POLICY" #Valid options are REQUIREMENT or RESOURCE or DATA_SERVICE_POLICY
    $policyresourceType = "STORAGE" #The only valid option, basically pointless
    $policydescription = $description
} Else {
    Write-Error "Invalid Parameter Set"
    Return
}
}
process {
    $serviceInstanceView = Get-SpbmView -Id "PbmServiceInstance-ServiceInstance"
    $spbmServiceContent = $serviceInstanceView.PbmRetrieveServiceContent()
    $spbmProfMgr= Get-SpbmView -Id $spbmServiceContent.ProfileManager
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
       } Else {
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
