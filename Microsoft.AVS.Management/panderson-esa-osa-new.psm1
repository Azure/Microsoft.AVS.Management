function New-AVSStoragePolicy {
    <#
	.DESCRIPTION
		This function creates a new or overwrites an existing vSphere Storage Policy.
        Non vSAN-Based, vSAN Only, VMEncryption Only, Tag Only based and/or any combination of these policy types are supported.
    .PARAMETER Name
        Name of Storage Policy - Wildcards are not allowed and will be stripped.
    .PARAMETER Description
        Description of Storage Policy you are creating, free form text.
    .PARAMETER vSANSiteDisasterTolerance
        Default is "None"
        Valid Values are "None", "Dual", "Preferred", "Secondary", "NoneStretch"
        None = No Site Redundancy (Recommended Option for Non-Stretch Clusters, NOT recommended for Stretch Clusters)
        Dual = Dual Site Redundancy (Recommended Option for Stretch Clusters)
        Preferred = No site redundancy - keep data on Preferred (stretched cluster)
        Secondary = No site redundancy -  Keep data on Secondary Site (stretched cluster)
        NoneStretch = No site redundancy - Not Recommended (https://kb.vmware.com/s/article/88358)
        Only valid for stretch clusters.
    .PARAMETER vSANFailuresToTolerate
        Default is "R1FTT1"
        Valid values are "None", "R1FTT1", "R1FTT2", "R1FTT3", "R5FTT1", "R6FTT2", "R1FTT3"
        None = No Data Redundancy
        R1FTT1 = 1 failure - RAID-1 (Mirroring)
        R1FTT2 = 2 failures - RAID-1 (Mirroring)
        R1FTT3 = 3 failures - RAID-1 (Mirroring)
        R5FTT1 = 1 failure - RAID-5 (Erasure Coding)
        R6FTT2 = 2 failures - RAID-6 (Erasure Coding)
        No Data Redundancy options are not covered under Microsoft SLA.
    .PARAMETER VMEncryption
        Default is None.  Valid values are None, PreIO, PostIO.
        PreIO allows VAIO filtering solutions to capture data prior to VM encryption.
        PostIO allows VAIO filtering solutions to capture data after VM encryption.
    .PARAMETER vSANObjectSpaceReservation
        Default is 0.  Valid values are 0..100
        Object Reservation.  0=Thin Provision, 100=Thick Provision
    .PARAMETER vSANDiskStripesPerObject
        Default is 1.  Valid values are 1..12.
        The number of HDDs across which each replica of a storage object is striped.
        A value higher than 1 may result in better performance (for e.g. when flash read cache misses need to get serviced from HDD), but also results in higher use of system resources.
    .PARAMETER vSANIOLimit
        Default is unset. Valid values are 0..2147483647
        IOPS limit for the policy.
    .PARAMETER vSANCacheReservation
        Default is 0. Valid values are 0..100
        Percentage of cache reservation for the policy.
	.PARAMETER vSANChecksumDisabled
        Default is $false. Enable or disable checksum for the policy. Valid values are $true or $false.
        WARNING - Disabling checksum may lead to data LOSS and/or corruption.
        Recommended value is $false.
    .PARAMETER vSANForceProvisioning
        Default is $false. Force provisioning for the policy. Valid values are $true or $false.
        WARNING - vSAN Force Provisioned Objects are not covered under Microsoft SLA.  Data LOSS and vSAN instability may occur.
        Recommended value is $false.
    .PARAMETER Tags
        Match to datastores that do have these tags.  Tags are case sensitive.
        Comma seperate multiple tags. Example: Tag1,Tag 2,Tag_3
    .PARAMETER NotTags
        Match to datastores that do NOT have these tags. Tags are case sensitive.
        Comma seperate multiple tags. Example: Tag1,Tag 2,Tag_3
    .PARAMETER Overwrite
        Overwrite existing Storage Policy.  Default is $false.
        Passing overwrite true provided will overwrite an existing policy exactly as defined.
        Those values not passed will be removed or set to default values.
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
    [CmdletBinding()]
    [AVSAttribute(10, UpdatesSDDC = $false)]
    param(
        #Add parameterSetNames to allow for vSAN, Tags, VMEncryption, StorageIOControl, vSANDirect to be optional.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [string]
        $Description,

        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Preferred", "Secondary")]
        [string]
        $vSANSiteDisasterTolerance,

        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "R1FTT1", "R5FTT1", "R1FTT2", "R6FTT2", "R1FTT3")]
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
        [boolean]
        $vSANChecksumDisabled,

        [Parameter(Mandatory = $false)]
        [boolean]
        $vSANForceProvisioning,

        [Parameter(Mandatory = $false)]
        [array]
        $Tags,

        [Parameter(Mandatory = $false)]
        [array]
        $NotTags,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Overwrite
    )

    begin {
        try {
            $clusters = Get-Cluster
            foreach ($cluster in $clusters) {
                try {
                    # Check for ESA by looking at the vSAN version and configuration
                    $config = Get-VsanClusterConfiguration -Cluster $cluster -ErrorAction Stop
                    if ($config.VsanEsaEnabled) {
                        $hasESA = $true
                    } else {
                        $hasOSA = $true
                    }
                } catch {
                    Write-Verbose "Cluster $($cluster.Name) is not a vSAN cluster or config retrieval failed."
                }
            }
        } catch {
            Write-Error "Failed to detect vSAN cluster types: $($_.Exception.Message)"
            return $null
        }

        #Cleanup Wildcard and Code Injection Characters
        Write-Information "Cleaning up Wildcard and Code Injection Characters from Name value: $Name"
        $Name = Limit-WildcardsandCodeInjectionCharacters -String $Name
        Write-Information "Name value after cleanup: $Name"
        Write-Information "Cleaning up Wildcard and Code Injection Characters from Description value: $Description"
        if (![string]::IsNullOrEmpty($Description)) { $Description = Limit-WildcardsandCodeInjectionCharacters -String $Description }
        Write-Information "Description value after cleanup: $Description"

        #Protected Policy Object Name Validation Check
        if (Test-AVSProtectedObjectName -Name $Name) {
            Write-Error "$Name is a protected policy name.  Please choose a different policy name."
            break
        }

        #Check for existing policy
        if ($hasESA -and $hasOSA) {
            # When both cluster types exist, check for suffixed policy names
            $ExistingESAPolicy = Get-AVSStoragePolicy -Name "$Name-esa"
            $ExistingOSAPolicy = Get-AVSStoragePolicy -Name "$Name-osa"
            Write-Information ("Existing ESA Policy: " + $ExistingESAPolicy.name)
            Write-Information ("Existing OSA Policy: " + $ExistingOSAPolicy.name)
            if (($ExistingESAPolicy -or $ExistingOSAPolicy) -and !$Overwrite) {
                Write-Error "Storage Policy $Name-esa and/or $Name-osa already exists.  Set -Overwrite to `$true to overwrite existing policy."
                break
            }
            if ((!$ExistingESAPolicy -and !$ExistingOSAPolicy) -and $Overwrite) {
                Write-Error "Storage Policy $Name-esa and $Name-osa do not exist.  Set -Overwrite to `$false to create new policy."
                break
            }
        } else {
            $ExistingPolicy = Get-AVSStoragePolicy -Name $Name
            Write-Information ("Existing Policy: " + $ExistingPolicy.name)
            if ($ExistingPolicy -and !$Overwrite) {
                Write-Error "Storage Policy $Name already exists.  Set -Overwrite to `$true to overwrite existing policy."
                break
            }
            if (!$ExistingPolicy -and $Overwrite) {
                Write-Error "Storage Policy $Name does not exist.  Set -Overwrite to `$false to create new policy."
                break
            }
        }
        Write-Information "Overwrite value set to: $Overwrite"

        $rules = @()
        # vSAN Storage Type - All Flash
        Write-Information "Adding VSAN.storageType = Allflash to ProfileSpec"
        $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.storageType" ) -Value "Allflash"

        #vSANFailurestoTolerate / FTT (intra-site when stretch cluster selected)
        Write-Information "vSANFailurestoTolerate value set to: $vSANFailuresToTolerate"
        $isStretch = ($vSANSiteDisasterTolerance -and $vSANSiteDisasterTolerance -ne 'None')
        $fttId = if ($isStretch) { 'VSAN.subFailuresToTolerate' } else { 'VSAN.hostFailuresToTolerate' }
        switch ($vSANFailuresToTolerate) {
            'None' {
                Add-VsanCapabilityInstanceLocal -Id $fttId -Value 0 -ProfileSpecRef $profilespec | Out-Null
                $Description = $Description + " - FTT 0 based policy objects are unprotected by Microsoft SLA and data loss/corruption may occur."
                Write-Warning "$Name policy setting $vSANFailurestoTolerate based policy objects are unprotected by Microsoft SLA and data loss/corruption may occur."
            }
            'R1FTT1' {
                Write-Information "Adding VSAN.replicaPreference = RAID-1 (Mirroring) - Performance to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-1 (Mirroring) - Performance"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 1 # $vSANFailuresToTolerate
            }
            'R5FTT1' {
                Write-Information "Adding VSAN.replicaPreference = RAID-5/6 (Erasure Coding) - Capacity to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-5/6 (Erasure Coding) - Capacity"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 1 # $vSANFailuresToTolerate
                Write-Information "All Flash added to ProfileSpec as required for $vSANFailuresToTolerate"
            }
            'R1FTT2' {
                Write-Information "Adding VSAN.replicaPreference = RAID-1 (Mirroring) - Performance to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-1 (Mirroring) - Performance"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 2 # $vSANFailuresToTolerate
            }
            'R6FTT2' {
                Write-Information "Adding VSAN.replicaPreference = RAID-5/6 (Erasure Coding) - Capacity to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-5/6 (Erasure Coding) - Capacity"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 2 # $vSANFailuresToTolerate
                Write-Information "All Flash added to ProfileSpec as required for $vSANFailuresToTolerate"
            }
            'R1FTT3' {
                Write-Information "Adding VSAN.replicaPreference = RAID-1 (Mirroring) - Performance to ProfileSpec"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.replicaPreference" ) -Value "RAID-1 (Mirroring) - Performance"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name $fttId ) -Value 3 # $vSANFailuresToTolerate
            }
            default {}
        }

        # vSAN Site Disaster Tolerance
        Write-Information "Configuring vSAN Site Disaster Tolerance and Failures to Tolerate settings"
        switch ($vSANSiteDisasterTolerance) {
            "Preferred" {
                Write-Information "Writing to Preferred Fault Domain only"
                Write-Information "Unreplicated objects in a stretch cluster are unprotected by Microsoft SLA and data loss/corruption may occur."
                $locality = "Preferred Fault Domain"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.locality" ) -Value $locality
            }
            "Secondary" {
                Write-Information "Writing to Secondary Fault Domain only"
                Write-Information "Unreplicated objects in a stretch cluster are unprotected by Microsoft SLA and data loss/corruption may occur."
                $locality = "Secondary Fault Domain"
                $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.locality" ) -Value $locality
            }
            default { $fttId = 'VSAN.hostFailuresToTolerate' }
        }

        #vSANChecksumDisabled
        Write-Information "vSANChecksumDisabled value is: $vSANChecksumDisabled"
        if ($vSANChecksumDisabled) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.checksumDisabled" ) -Value $true
        }

        # vSANForceProvisioning
        Write-Information "vSANForceProvisioning value is: $vSANForceProvisioning"
        if ($vSANForceProvisioning) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.forceProvisioning" ) -Value $true
        }

        #vSANDiskStripesPerObject
        Write-Information "vSANDiskStripesPerObject value is: $vSANDiskStripesPerObject"
        if ($vSANDiskStripesPerObject -gt 1) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.stripeWidth" ) -Value $vSANDiskStripesPerObject
        }

        #VSANIOLimit
        Write-Information "vSANIOLimit set to: $vSANIOLimit"
        if ($vSANIOLimit -gt 0) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.iopsLimit" ) -Value $vSANIOLimit
        }

        # VSANCacheReservation
        Write-Information "vSANCacheReservation set to: $vSANCacheReservation"
        if ($vSANCacheReservation -gt 0) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.cacheReservation" ) -Value $vSANCacheReservation
        }

        #VSANObjectReservation
        if ($vSANObjectReservation -gt 0) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.proportionalCapacity" ) -Value $vSANObjectReservation
        }

        # Tags Based Placement
        if ($Tags -or $NotTags) {
            $tagCategory = Get-TagCategory -Name "StorageTier" -ErrorAction SilentlyContinue
            if (-not $tagCategory) {
                Write-Information "Creating Tag Category 'StorageTier' for Storage Policy Tag based placement"
                $tagCategory = New-TagCategory -Name "StorageTier" -Cardinality Single -EntityType Datastore
            }

            $alltags = $Tags + $NotTags
            $TagNames = @()
            foreach ($t in $alltags) {
                $TagNames += Limit-WildcardsandCodeInjectionCharacters -String $t
            }
            foreach ($TagName in $TagNames) {
                $tagExists = (Get-Tag -Name $TagName -ErrorAction SilentlyContinue).Category.Name -match "StorageTier"
                if ( $tagExists -match "true" ) {
                    Write-Information "Tag '$TagName' in Category 'StorageTier' already exists for Storage Policy Tag based placement"
                } else {
                    Write-Information "Creating Tag '$TagName' in Category 'StorageTier' for Storage Policy Tag based placement"
                    New-Tag -Name $TagName -Category $tagCategory | Out-Null
                }
            }

            if ($Tags) {
                $withTagNames = @()
                foreach ($t in $Tags) {
                    $withTagNames += Limit-WildcardsandCodeInjectionCharacters -String $t
                }

                # Create SpbmRule objects from each tag
                $withTagRules = $withTagNames | ForEach-Object {
                    $t = Get-Tag -Name $_ -Category $tagCategory
                    New-SpbmRule -AnyOfTags $t
                }
                # Now pass the rules
                $withTagRuleSet = New-SpbmRuleSet -AllOfRules $withTagRules
            }

            if ($NotTags) {
                $withTagNames = @()
                foreach ($t in $NotTags) {
                    $withTagNames += Limit-WildcardsandCodeInjectionCharacters -String $t
                }

                # Create SpbmRule objects from each tag
                $notTagRules = $withTagNames | ForEach-Object {
                    $tag = Get-Tag -Name $_ -Category $tagCategory
                    New-SpbmRule -AnyOfTags $tag -SpbmOperatorType 1
                }
                # Now pass the rules
                $notTagRuleSet = New-SpbmRuleSet -AllOfRules $notTagRules
            }
        }

        # Space Efficiency (Compression) - ESA only
        if ( $hasESA) {
            if ( $NoCompression) {
                # No space efficiency
                # $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "NoSpaceEfficiency"
                $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "NoSpaceEfficiency"
            } else {
                # Compression only
                $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "CompressionOnly"
            }
        }

        # IMPORTANT - Any additional functionality should be added before the VMEncryption Parameter.
        # The reason is that this subprofile must be added as a capability to all subprofile types for API to accept.
        Write-Information "VMEncryption set to: $VMEncryption"
        # VM Encryption
        if ($VmEncryption) {
            $rules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.dataAtRestEncryption" ) -Value $true
        }
    }

    process {
        Write-Debug "=== PROCESS BLOCK START ==="
        Write-Debug "hasESA: $hasESA"
        Write-Debug "hasOSA: $hasOSA"
        Write-Debug "Name: $Name"
        Write-Debug "rules count: $($rules.Count)"
        Write-Debug "esaRules count: $($esaRules.Count)"
        Write-Debug "withTagRuleSet: $($withTagRuleSet -ne $null)"
        Write-Debug "notTagRuleSet: $($notTagRuleSet -ne $null)"

        if ($Description -eq "") {
            $Description = "AVS Common Storage Policy created via PowerCLI"
        }

        $createdPolicyNames = @()

        if ($hasESA -and $hasOSA) {
            Write-Debug "=== CREATING BOTH ESA AND OSA POLICIES ==="
            # Create ESA policy with -esa suffix
            $esaRules = $rules
            if ($hasESA -and $NoCompression) {
                Write-Debug "Creating ESA policy with No Compression with name: $esaName"
             } else {
                Write-Debug "Creating ESA policy with Compression Only with name: $esaName"
                $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "CompressionOnly"
             }
            $esaRuleSet = New-SpbmRuleSet -AllOfRules $esaRules
            $esaName = "$Name-esa"

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $esaPolicy = New-SpbmStoragePolicy -Name $esaName -Description $Description -AnyOfRuleSets $esaRuleSet -Confirm:$false
            }
            Write-Debug "Created ESA policy: $esaName"
            $createdPolicyNames += $esaName

            # Create OSA policy with -osa suffix
            Write-Debug "Creating OSA policy with name: $osaName"
            $osaRuleSet = New-SpbmRuleSet -AllOfRules $rules
            $osaName = "$Name-osa"

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $osaPolicy = New-SpbmStoragePolicy -Name $osaName -Description $Description -AnyOfRuleSets $osaRuleSet -Confirm:$false
            }
            Write-Debug "Created OSA policy: $osaName"
            $createdPolicyNames += $osaName
        } elseif ($hasESA) {
            Write-Debug "=== CREATING ESA-ONLY POLICY ==="
            # ESA only - include esaRules
            $esaRules = $Rules
            $esaRules += New-SpbmRule -Capability (Get-SpbmCapability -Name "VSAN.dataService.datastoreSpaceEfficiency" ) -Value "CompressionOnly"
            $ruleSet = New-SpbmRuleSet -AllOfRules $esaRules # $esaRules, $rules
            Write-Debug "=== CREATING ESA-ONLY ruleset ==="

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet -Confirm:$false
            }
            Write-Debug "Created ESA-only policy: $Name"
            $createdPolicyNames += $Name
        } else {
            Write-Debug "=== CREATING OSA-ONLY POLICY ==="
            # OSA only - no esaRules
            $ruleSet = New-SpbmRuleSet -AllOfRules $rules

            if (($withTagRuleSet) -and (-not $notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet -Confirm:$false
            } elseif ((-not $withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $notTagRuleSet -Confirm:$false
            } elseif (($withTagRuleSet) -and ($notTagRuleSet)) {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet, $withTagRuleSet, $notTagRuleSet -Confirm:$false
            } else {
                $policy = New-SpbmStoragePolicy -Name $Name -Description $Description -AnyOfRuleSets $ruleSet -Confirm:$false
            }
            Write-Debug "Created OSA-only policy: $Name"
            $createdPolicyNames += $Name
        }

        Write-Debug "=== PROCESS BLOCK END ==="
        Write-Debug "Returning policy names: $($createdPolicyNames -join ', ')"
        return $createdPolicyNames
    }
}
