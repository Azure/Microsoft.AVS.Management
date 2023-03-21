Function New-AVSStoragePolicy {
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
        Name of Storage Policy
    .PARAMETER vSANSiteDisasterTolerance
        Default is None.  Valid values are None, Site mirroring - stretched cluster, "None - keep data on Preferred (stretched cluster)", "None - keep data on Secondary (stretched cluster)", "None - stretched cluster"
    .PARAMETER vSANFailuresToTolerate
        Default is "1 failure - RAID-1 (Mirroring)".  Valid values are "No Data Redundancy", "No Data redundancy with host affinity", "1 failure - RAID-1 (Mirroring)", "1 failure - RAID-5 (Erasure Coding)", "2 failures - RAID-1 (Mirroring)", "2 failures - RAID-6 (Erasure Coding)", "3 failures - RAID-1 (Mirroring)"
        No Data Redundancy options are not covered under Microsoft SLA.
    .PARAMETER vSANEncryptionServices
        Default is Unset. Valid values are True or False.
        This is a preference, AVS is Data-At-Rest by default.
    .PARAMETER VMEncryption
        Default is None.  Valid values are None, PreIO, PostIO.
        PreIO allows IO Filtering solutions to capture data prior to VM encryption.
        PostIO allows IO Filtering solutions to capture data after VM encryption.
    .PARAMETER vSANObjectSpaceReservation
        Default is 0.  Valid values are 0..100
        Object Reservation.  0=Thin Provision, 100=Thick Provision
    .PARAMETER vSANDiskStripesPerObject
        Default is 1.  Valid values are 1..12.
        The number of HDDs across which each replica of a storage object is striped. A value higher than 1 may result in better performance (for e.g. when flash read cache misses need to get serviced from HDD), but also results in higher use of system resources.
    .PARAMETER vSANIOLimit
        Default is unset. Valid values are 0..2147483647
        IOPS limit for the policy.
    .PARAMETER vSANCacheReservation
        Default is 0.
        Percentage of cache reservation for the policy.
	.PARAMETER vSANChecksumDisabled
        Default is unset. Enable or disable checksum for the policy.
    .PARAMETER vSANForceProvisioning
        Default is unset. Force provisioning for the policy.
        vSAN Force Provisioned Objects are not covered under Microsoft SLA.
    .PARAMETER Tags
        Match to datastores that do have these tags.  Tags are case sensitive.
    .PARAMETER NotTags
        Match to datastores that do NOT have these tags. Tags are case sensitive.
    .PARAMETER Overwrite
        Overwrite existing Storage Policy.  Default is $false.
    .EXAMPLE
        Creates a new storage policy named Encryption with that enables Pre-IO filter VM encryption
        New-AVSStoragePolicy -Name "Encryption" -VMEncryption "PreIO"
    .EXAMPLE
        Creates a new storage policy named "RAID-1 FTT-1 with Pre-IO VM Encryption" with a description enabled for Pre-IO VM Encryption
        New-AVSStoragePolicy -Name "RAID-1 FTT-1 with Pre-IO VM Encryption" -Description "My super secure and performant storage policy" -VMEncryption "PreIO" -vSANFailuresToTolerate "1 failure - RAID-1 (Mirroring)"
    .EXAMPLE
        Creates a new storage policy named "Tagged Datastores" to use datastores tagged with "SSD" and "NVMe" and not datastores tagged "Slow"
        New-AVSStoragePolicy -Name "Tagged Datastores" -Tags "SSD","NVMe" -NotTags "Slow"
    .EXAMPLE
        Creates a new storage policy named "Production Only" to use datastore tagged w/ Production and not tagged w/ Test or Dev.  Set with RAID-1, 100% read cache, and Thick Provisioning of Disk.
        New-AVSStoragePolicy -Name "Production Only" -Tags "Production" -NotTags "Test","Dev" -vSANFailuresToTolerate "1 failure - RAID-1 (Mirroring)" -vSANObjectSpaceReservation 100 -vSANCacheReservation 100
    .EXAMPLE
        Passing -Overwrite:$true to any examples provided will overwrite an existing policy exactly as defined.  Those values not passed will be removed or set to default values.
        #>
    param(
        #Add parameterSetNames to allow for vSAN, Tags, VMEncryption, StorageIOControl, vSANDirect to be optional.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        [Parameter(Mandatory = $false)]
        [string]
        $Description,
        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Site mirroring - stretched cluster", "None - keep data on Preferred (stretched cluster)", "None - keep data on Secondary (stretched cluster)", "None - stretched cluster")]
        [string]
        $vSANSiteDisasterTolerance,
        [Parameter(Mandatory = $false)]
        [ValidateSet("No Data Redundancy", "No Data redundancy with host affinity", "1 failure - RAID-1 (Mirroring)", "1 failure - RAID-5 (Erasure Coding)", "2 failures - RAID-1 (Mirroring)", "2 failures - RAID-6 (Erasure Coding)", "3 failures - RAID-1 (Mirroring)")]
        [string]
        $vSANFailuresToTolerate,
        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "PreIO", "PostIO")]
        [string]
        $VMEncryption = "None",
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]
        $vSANObjectSpaceReservation,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 12)]
        [int]
        $vSANDiskStripesPerObject,
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 2147483647)]
        [int]
        $vSANIOLimit,
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]
        $vSANCacheReservation,
        [Parameter(Mandatory = $false)]
        [ValidateSet("unset", $true, $false)]
        [string]
        $vSANChecksumDisabled = "unset",
        [Parameter(Mandatory = $false)]
        [ValidateSet("unset", $true, $false)]
        [string]
        $vSANForceProvisioning = "unset",
        [Parameter(Mandatory = $false)]
        [string[]]
        $Tags,
        [Parameter(Mandatory = $false)]
        [string[]]
        $NotTags,
        [Parameter(Mandatory = $false)]
        [Boolean]
        $Overwrite

    )



    Begin {
        #Cleanup Wildcard and Code Injection Characters
        Write-Debug "Cleaning up Wildcard and Code Injection Characters from Name value: $Name"
        $Name = Limit-WildcardsandCodeInjectionCharacters -String $Name
        Write-Debug "Name value after cleanup: $Name"
        Write-Debug "Cleaning up Wildcard and Code Injection Characters from Description value: $Description"
        If (![string]::IsNullOrEmpty($Description)) { $Description = Limit-WildcardsandCodeInjectionCharacters -String $Description }
        Write-Debug "Description value after cleanup: $Description"

        #Protected Policy Object Name Validation Check
        If (Test-AVSProtectedObjectName -Name $Name) {
            Write-Error "$Name is a protected policy name.  Please choose a different policy name."
            break
        }

        #Check for existing policy
        $ExistingPolicy = Get-AVSStoragePolicy -Name $Name
        Write-Debug ("Existing Policy: " + $ExistingPolicy.name)
        if ($ExistingPolicy -and !$Overwrite) {
            Write-Error "Storage Policy $Name already exists.  Set -Overwrite to $true to overwrite existing policy."
            break
        }
        if (!$ExistingPolicy -and $Overwrite) {
            Write-Error "Storage Policy $Name does not exist.  Set -Overwrite to $false to create new policy."
            break
        }
        Write-Debug "Overwrite value set to: $Overwrite"
        Switch ($Overwrite) {
            $true {
                $pbmprofileresourcetype = new-object vmware.spbm.views.PbmProfileResourceType
                $pbmprofileresourcetype.ResourceType = "STORAGE" # No other known valid value.
                $profilespec = new-object VMware.Spbm.Views.PbmCapabilityProfileUpdateSpec
                $profilespec.Name = $Name
                $profilespec.Constraints = new-object vmware.spbm.views.PbmCapabilitySubProfileConstraints
                If (![string]::IsNullOrEmpty($Description)) { $profilespec.Description = $Description }
            }
            $false {
                $pbmprofileresourcetype = new-object vmware.spbm.views.PbmProfileResourceType
                $pbmprofileresourcetype.ResourceType = "STORAGE" # No other known valid value.
                $profilespec = new-object VMware.Spbm.Views.PbmCapabilityProfileCreateSpec
                $profilespec.ResourceType = $pbmprofileresourcetype
                $profilespec.Name = $Name
                $profilespec.Constraints = new-object vmware.spbm.views.PbmCapabilitySubProfileConstraints
                If (![string]::IsNullOrEmpty($Description)) { $profilespec.Description = $Description }
                $profilespec.Category = "REQUIREMENT" #Valid options are REQUIREMENT = vSAN Storage Policies or RESOURCE = ?? or DATA_SERVICE_POLICY = Common Storage Policies such encryption and storage IO.
                Write-Debug "Profile Name set to: $($profilespec.Name)"
                Write-Debug "Profile Category set to: $($profilespec.Category)"
            }
        }
        Write-Debug "Getting SPBM Capabilities"
        $SPBMCapabilities = Get-AVSSPBMCapabilities
        Foreach ($Capability in $SPBMCapabilities) {
            Write-Debug "SPBM Capability: NameSpace: $($Capability.NameSpace), SubCategory: $($Capability.SubCategory), CapabilityMetaData Count: $($Capability.CapabilityMetadata.Count)"
        }

        #vSAN Site Disaster Tolerance / Stretch Cluster specific configuration
        Write-Debug "vSANSiteDisasterTolerance value set to: $vSANSiteDisasterTolerance"
        Switch ($vSANSiteDisasterTolerance) {
            "None" {
                #Left blank on purpose.  No additional configuration required.
            }
            "Site mirroring - stretched cluster" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "subFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 1
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "locality"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "None"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            "None - keep data on Preferred (stretched cluster)" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "subFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 1
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "locality"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "Preferred Fault Domain"
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
                $Description = $Description + " - Unreplicated objects in a stretch cluster are unprotected by Microsoft SLA"
            }
            "None - keep data on Secondary (stretched cluster)" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "subFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 1
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "locality"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "Secondary Fault Domain"
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
                $Description = $Description + " - Unreplicated objects in a stretch cluster are unprotected by Microsoft SLA"
            }
            "None - stretched cluster" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "subFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 1
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "locality"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "None"
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
                $Description = $Description + " - Unreplicated objects in a stretch cluster are unprotected by Microsoft SLA"
            }
            Default {
                #Left blank on purpose, same as none option.
            }

        }
        #vSANFailurestoTolerate / FTT
        Write-Debug "vSANFailurestoTolerate value set to: $vSANFailuresToTolerate"
        Switch ($vSANFailuresToTolerate) {
            "No Data Redundancy" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "hostFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 0
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
                $Description = $Description + " - FTT 0 based policy objects are unprotected by Microsoft SLA"
            }
            "No Data redundancy with host affinity" {  }
            "1 failure - RAID-1 (Mirroring)" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "hostFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 1
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "replicaPreference"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "RAID-1 (Mirroring) - Performance"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            "1 failure - RAID-5 (Erasure Coding)" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "hostFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 1
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                Write-Debug "Profilespec: $($profilespec | Out-String)"
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "replicaPreference"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "RAID-5/6 (Erasure Coding) - Capacity"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile

                Write-Debug "Profilespec: $($profilespec | Out-String)"
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "storageType"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "Allflash"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                Write-Debug "All Flash added to ProfileSpec as required for $vsanFailurestoTolerate"
            }
            "2 failures - RAID-1 (Mirroring)" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "hostFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 2
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "replicaPreference"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "RAID-1 (Mirroring) - Performance"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            "2 failures - RAID-6 (Erasure Coding)" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "hostFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 2
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "replicaPreference"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "RAID-5/6 (Erasure Coding) - Capacity"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "storageType"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "Allflash"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                Write-Debug "All Flash added to ProfileSpec as required for $vsanFailurestoTolerate"
            }
            "3 failures - RAID-1 (Mirroring)" {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "hostFailuresToTolerate"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = 3
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }

                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "replicaPreference"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = "RAID-1 (Mirroring) - Performance"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            Default {}
        }
        #vSANChecksumDisabled
        Write-Debug "vSANChecksumDisabled value is: $vSANChecksumDisabled"
        Switch ($vSANChecksumDisabled) {
            $true {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "checksumDisabled"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = $true
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
            }
            $false {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "checksumDisabled"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = $false
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
            }
            Default {}
        }
        #vSANForceProvisioning
        Write-Debug "vSANForceProvisioning Value is: $vSANForceProvisioning"
        Switch ($vSANForceProvisioning) {
            $true {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "forceProvisioning"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = $true
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
                $Description = $Description + " - Force Provisioned objects are unprotected by Microsoft SLA"
            }
            $false {
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "VSAN"
                $Subprofile.Id.Id = "forceProvisioning"
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = $false
                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                    Write-Debug "Added VSAN Subprofile to ProfileSpec"
                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
                }
                Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
            }
            Default {}
        }

        #vSANDiskStripesPerObject
        Write-Debug "vSANDiskStripesPerObject value is: $vSANDiskStripesPerObject"
        If ($vSANDiskStripesPerObject -gt 0) {
            Write-Debug "Creating vSAN Disk Stripes Subprofile"
            $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
            $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
            $Subprofile.Id.Namespace = "VSAN"
            $Subprofile.Id.Id = "stripeWidth"
            $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
            $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
            $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
            $Subprofile.Constraint[0].PropertyInstance[0].value = $vSANDiskStripesPerObject
            If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                Write-Debug "Added VSAN Subprofile to ProfileSpec"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
        }

        #VSANIOLimit
        Write-Debug "vSANIOLimit set to: $vSANIOLimit"
        If ($vSANIOLimit -gt 0) {
            Write-Debug "Building vSAN IOLimit Subprofile"
            $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
            $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
            $Subprofile.Id.Namespace = "VSAN"
            $Subprofile.Id.Id = "iopsLimit"
            $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
            $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
            $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
            $Subprofile.Constraint[0].PropertyInstance[0].value = $vSANIOLimit
            If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                Write-Debug "Added VSAN Subprofile to ProfileSpec"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
        }

        #VSANCacheReservation
        Write-Debug "vSANCacheReservation set to: $vSANCacheReservation"
        If ($vSANCacheReservation -gt 0) {
            Write-Debug "Creating vSANCacheReservation Subprofile"
            $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
            $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
            $Subprofile.Id.Namespace = "VSAN"
            $Subprofile.Id.Id = "cacheReservation"
            $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
            $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
            $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
            $Subprofile.Constraint[0].PropertyInstance[0].value = ([int]$vSANCacheReservation * 10000)
            If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                Write-Debug "Added VSAN Subprofile to ProfileSpec"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
        }

        #VSANObjectReservation
        Write-Debug "vSANObjectReservation set to: $vSANObjectSpaceReservation"
        If ($vSANObjectSpaceReservation -gt 0) {
            Write-Debug "Creating vSANObjectReservation Subprofile"
            $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
            $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
            $Subprofile.Id.Namespace = "VSAN"
            $Subprofile.Id.Id = "proportionalCapacity"
            $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
            $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
            $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
            $Subprofile.Constraint[0].PropertyInstance[0].value = $vSANObjectSpaceReservation
            If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).count -eq 0) {
                $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "VSAN" }
                Write-Debug "Added VSAN Subprofile to ProfileSpec"
                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile
            }
            Else { ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "VSAN" }).Capability += $subprofile }
        }

        # Tag Support for Storage Policies
        Write-Debug ("Tags recorded as: " + $Tags)
        $TagData = $SPBMCapabilities | Where-Object { $_.subcategory -eq "Tag" }
        If (![string]::IsNullOrEmpty($Tags)) {
            Foreach ($Tag in $Tags) {
                Write-Debug ("Tag: " + $Tag)
                $Tag = Limit-WildcardsandCodeInjectionCharacters -String $Tag
                $ObjectTag = Get-Tag -Name $Tag
                If (![string]::IsNullOrEmpty($ObjectTag)) {
                    If ($ObjectTag.count -gt 1) {
                        Write-Debug "Multiple Tags found with the name $Tag. Filtering by Datastore category."
                        Foreach ($Entry in $ObjectTag) {
                            Write-Debug ("Tag Name: " + $Entry.Name)
                            If ($Entry.Category.EntityType -eq "Datastore") {
                                $CatData = $TagData.CapabilityMetadata | Where-Object { $_.summary.Label -eq $Entry.Category.Name }
                                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                                $Subprofile.Id = $Catdata.Id
                                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                                $Subprofile.Constraint[0].PropertyInstance[0].id = $Catdata.propertymetadata.id
                                $Subprofile.Constraint[0].PropertyInstance[0].Operator = ""
                                $Subprofile.Constraint[0].PropertyInstance[0].value = New-object VMware.Spbm.Views.PbmCapabilityDiscreteSet
                                $Subprofile.Constraint[0].PropertyInstance[0].value.values = $Entry.Name
                                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).count -eq 0) {
                                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "Tag based placement" }
                                    Write-Debug "Added Tag based placement subprofile to ProfileSpec"
                                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                                    Write-Debug "Added $Tag to profilespec"
                                }
                                Else {
                                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                                }

                            }
                            If ($Entry.Category.EntityType -ne "Datastore") {
                                Write-Debug "Tag $($Entry.Name) of category $($Entry.Category.Name) is not a Datastore Tag. Skipping."
                            }
                        }
                    }
                    If ($ObjectTag.count -eq 1) {
                        If ($ObjectTag.Category.EntityType -ne "Datastore") {
                            Write-Warning "Tag $Tag is not a Datastore Tag. Skipping."
                        }
                        Else {
                            $Entry = $ObjectTag
                            $CatData = $TagData.CapabilityMetadata | Where-Object { $_.summary.Label -eq $Entry.Category.Name }
                            $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                            $Subprofile.Id = $Catdata.Id
                            $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                            $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                            $Subprofile.Constraint[0].PropertyInstance[0].id = $Catdata.propertymetadata.id
                            $Subprofile.Constraint[0].PropertyInstance[0].Operator = ""
                            $Subprofile.Constraint[0].PropertyInstance[0].value = New-object VMware.Spbm.Views.PbmCapabilityDiscreteSet
                            $Subprofile.Constraint[0].PropertyInstance[0].value.values = $Entry.Name
                            If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).count -eq 0) {
                                $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "Tag based placement" }
                                Write-Debug "Added Tag based placement subprofile to ProfileSpec"
                                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                                Write-Debug "Added $Tag to profilespec"
                            }
                            Else {
                                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                            }
                        }


                    }


                }
                Else { Write-Error "Tag $Tag not found. Skipping. Tags are case-sensitive, please verify." }
            }


        }

        # Not Tag Support for Storage Policies
        Write-Debug ("NotTags recorded as: " + $NotTags)
        If (![string]::IsNullOrEmpty($NotTags)) {
            Foreach ($Tag in $NotTags) {
                Write-Debug ("Tag: " + $Tag)
                $Tag = Limit-WildcardsandCodeInjectionCharacters -String $Tag
                $ObjectTag = Get-Tag -Name $Tag
                If (![string]::IsNullOrEmpty($ObjectTag)) {
                    If ($ObjectTag.count -gt 1) {
                        Write-Debug "Multiple Tags found with the name $Tag. Filtering by Datastore category."
                        Foreach ($Entry in $ObjectTag) {
                            Write-Debug ("Tag Name: " + $Entry.Name)
                            If ($Entry.Category.EntityType -eq "Datastore") {
                                $CatData = $TagData.CapabilityMetadata | Where-Object { $_.summary.Label -eq $Entry.Category.Name }
                                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                                $Subprofile.Id = $Catdata.Id
                                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                                $Subprofile.Constraint[0].PropertyInstance[0].id = $Catdata.propertymetadata.id
                                $Subprofile.Constraint[0].PropertyInstance[0].Operator = "NOT"
                                $Subprofile.Constraint[0].PropertyInstance[0].value = New-object VMware.Spbm.Views.PbmCapabilityDiscreteSet
                                $Subprofile.Constraint[0].PropertyInstance[0].value.values = $Entry.Name
                                If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).count -eq 0) {
                                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "Tag based placement" }
                                    Write-Debug "Added Tag based placement subprofile to ProfileSpec"
                                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                                    Write-Debug "Added $Tag to profilespec"
                                }
                                Else {
                                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                                }

                            }
                            If ($Entry.Category.EntityType -ne "Datastore") {
                                Write-Debut "Tag $($Entry.Name) of category $($Entry.Category.Name) is not a Datastore Tag. Skipping."
                            }
                        }
                    }
                    If ($ObjectTag.count -eq 1) {
                        if ($ObjectTag.Category.EntityType -ne "Datastore") {
                            Write-Debug "Tag $Tag is not a Datastore Tag. Skipping."
                        }
                        Else {
                            $Entry = $ObjectTag
                            $CatData = $TagData.CapabilityMetadata | Where-Object { $_.summary.Label -eq $Entry.Category.Name }
                            $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                            $Subprofile.Id = $Catdata.Id
                            $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                            $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                            $Subprofile.Constraint[0].PropertyInstance[0].id = $Catdata.propertymetadata.id
                            $Subprofile.Constraint[0].PropertyInstance[0].Operator = "NOT"
                            $Subprofile.Constraint[0].PropertyInstance[0].value = New-object VMware.Spbm.Views.PbmCapabilityDiscreteSet
                            $Subprofile.Constraint[0].PropertyInstance[0].value.values = $Entry.Name
                            If (($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).count -eq 0) {
                                $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = "Tag based placement" }
                                Write-Debug "Added Tag based placement subprofile to ProfileSpec"
                                ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                                Write-Debug "Added $Tag to profilespec"
                            }
                            Else {
                                    ($profilespec.Constraints.SubProfiles | Where-Object { $_.Name -eq "Tag based placement" }).Capability += $Subprofile
                            }
                        }


                    }


                }
                Else { Write-Error "Tag $Tag not found. Skipping. Tags are case-sensitive, please verify." }
            }


        }
        #IMPORTANT - Any additional functionality should be added before the VMEncryption Parameter.  The reason is that this subprofile must be added as a capability to all subprofile types for API to accept.
        Write-Debug "VMEncryption set to: $VMEncryption"
        Switch ($VMEncryption) {
            "None" {}
            "PreIO" {
                #Check for AVS VM Encryption Policies, create if not present.
                $IOPolicy = Get-AVSStoragePolicy -Name "AVS PRE IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
                If (!$IOPolicy) { $IOPolicy = New-AVSCommonStoragePolicy -Encryption -Name "AVS PRE IO Encryption" -Description "Encrypts VM before VAIO Filter" -PostIOEncryption $false }
                Write-Debug ("VMEncryption uniqueID: " + $IOPolicy.ProfileId.UniqueId)
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "com.vmware.storageprofile.dataservice"
                $Subprofile.Id.Id = $IOPolicy.ProfileId.UniqueId
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = $Subprofile.Id.Id
                If ($profilespec.Constraints.SubProfiles.count -eq 0) {
                    $SubprofileName = "Host based services"
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = $SubprofileName }
                    Write-Debug "Added $SubprofileName to ProfileSpec"
                    Foreach ($service in $profilespec.Constraints.SubProfiles){
                        $service.Capability += $subprofile
                    }
                }
                ElseIf ($profilespec.Constraints.SubProfiles.count -ge 1) {
                    Foreach ($service in $profilespec.Constraints.SubProfiles){
                        $service.Capability += $subprofile
                    }
                }
                Write-Debug "Added $($IOPolicy.Name) to profilespec"

            }
            "PostIO" {
                $IOPolicy = Get-AVSStoragePolicy -Name "AVS POST IO Encryption" -ResourceType "DATA_SERVICE_POLICY"
                If (!$IOPolicy) { $IOPolicy = New-AVSCommonStoragePolicy -Encryption -Name "AVS POST IO Encryption" -Description "Encrypts VM after VAIO Filter" -PostIOEncryption $true }
                Write-Debug ("VMEncryption uniqueID: " + $IOPolicy.ProfileId.UniqueId)
                $Subprofile = new-object VMware.Spbm.Views.PbmCapabilityInstance
                $Subprofile.Id = New-Object VMware.Spbm.Views.PbmCapabilityMetadataUniqueId
                $Subprofile.Id.Namespace = "com.vmware.storageprofile.dataservice"
                $Subprofile.Id.Id = $IOPolicy.profileid.UniqueId
                $Subprofile.Constraint = New-Object VMware.Spbm.Views.PbmCapabilityConstraintInstance
                $Subprofile.Constraint[0].PropertyInstance = New-Object VMware.Spbm.Views.PbmCapabilityPropertyInstance
                $Subprofile.Constraint[0].PropertyInstance[0].id = $Subprofile.Id.Id
                $Subprofile.Constraint[0].PropertyInstance[0].value = $Subprofile.Id.Id
                If ($profilespec.Constraints.SubProfiles.count -eq 0) {
                    $SubprofileName = "Host based services"
                    $profilespec.Constraints.SubProfiles += new-object VMware.Spbm.Views.PbmCapabilitySubProfile -Property @{"Name" = $SubprofileName }
                    Write-Debug "Added $SubprofileName to ProfileSpec"
                    Write-Debug $profilespec.Constraints.SubProfiles[0].Name
                    Foreach ($service in $profilespec.Constraints.SubProfiles){
                        $service.Capability += $subprofile
                    }
                }
                ElseIf ($profilespec.Constraints.SubProfiles.count -ge 1) {
                    Foreach ($service in $profilespec.Constraints.SubProfiles){
                        $service.Capability += $subprofile
                    }
                }
                Write-Debug "Added $($IOPolicy.Name) to profilespec"

            }
            Default {}
        }

    }
    process {
        $profilespec.Description = $Description
        #return $profilespec #Uncomment to capture and debug profile spec.
        If ($profilespec.Constraints.SubProfiles.count -eq 0) {
            Write-Error "At least one parameter must be defined to create a storage policy."
            Return
        }
        $serviceInstanceView = Get-SpbmView -Id "PbmServiceInstance-ServiceInstance"
        $spbmServiceContent = $serviceInstanceView.PbmRetrieveServiceContent()
        $spbmProfMgr = Get-SpbmView -Id $spbmServiceContent.ProfileManager
        If ($Overwrite) {
            $spbmProfMgr.PbmUpdate($ExistingPolicy.ProfileId, $profilespec)
            #TODO: Insert validation code here.  Above API call does not return anything.
        }
        Else {
            $profileuniqueID = $spbmProfMgr.PbmCreate($profilespec)
            return $profileuniqueID.UniqueId
        }

    }
}



