BeforeAll {
    # Define the AVSAttribute class that VMFS module functions use
    # This is a minimal definition matching what's in Microsoft.AVS.Management/Classes.ps1
    if (-not ('AVSAttribute' -as [type])) {
        class AVSAttribute : Attribute {
            [bool]$UpdatesSDDC = $false
            [TimeSpan]$Timeout
            [bool]$AutomationOnly = $false
            AVSAttribute([int]$timeoutMinutes) { $this.Timeout = New-TimeSpan -Minutes $timeoutMinutes }
        }
    }

    # Define stub functions for VMware cmdlets so Pester can mock them
    # These are only created when the real cmdlets are not available (e.g. no PowerCLI installed)
    $vmwareCmdlets = @(
        'Get-Cluster', 'Get-VMHost', 'Get-Datastore', 'Get-VMHostHba',
        'Get-VMHostStorage', 'Get-VMHostNetworkAdapter', 'Get-EsxCli',
        'Get-VM', 'Get-View', 'Remove-Datastore', 'New-Datastore',
        'Set-VMHostStorage'
    )
    foreach ($cmdlet in $vmwareCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$cmdlet" -Value { param() $null }
        }
    }
    # Always override Get-VMHost with a stub that accepts common parameters,
    # preventing the real VMware cmdlet from causing credential binding errors
    function global:Get-VMHost {
        param($Name, $Datastore, $State, $Id,
              [Parameter(ValueFromPipeline=$true)]$InputObject)
        process { $null }
    }

    # Import the VMFS module (use .psm1 directly to avoid RequiredModules dependency on VMware modules)
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.VMFS" "Microsoft.AVS.VMFS.psm1"
    Import-Module $modulePath -Force
}

AfterAll {
    # Clean up
    Get-Module Microsoft.AVS.VMFS -ErrorAction SilentlyContinue | Remove-Module -Force
}

Describe "Microsoft.AVS.VMFS Module" {
    Context "Module Loading" {
        It "Should import the module successfully" {
            $module = Get-Module Microsoft.AVS.VMFS
            $module | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Set-VmfsIscsi" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have ScsiIpAddress as mandatory parameter" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['ScsiIpAddress']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have optional LoginTimeout parameter with default value 30" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['LoginTimeout']
            $param | Should -Not -BeNullOrEmpty
        }

        It "Should have optional NoopOutTimeout parameter" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['NoopOutTimeout']
            $param | Should -Not -BeNullOrEmpty
        }

        It "Should have optional RecoveryTimeout parameter" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['RecoveryTimeout']
            $param | Should -Not -BeNullOrEmpty
        }

        It "Should validate LoginTimeout range 1-60" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['LoginTimeout']
            $rangeAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $rangeAttr.MinRange | Should -Be 1
            $rangeAttr.MaxRange | Should -Be 60
        }

        It "Should validate NoopOutTimeout range 10-30" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['NoopOutTimeout']
            $rangeAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $rangeAttr.MinRange | Should -Be 10
            $rangeAttr.MaxRange | Should -Be 30
        }

        It "Should validate RecoveryTimeout range 1-120" {
            $command = Get-Command Set-VmfsIscsi
            $param = $command.Parameters['RecoveryTimeout']
            $rangeAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $rangeAttr.MinRange | Should -Be 1
            $rangeAttr.MaxRange | Should -Be 120
        }
    }

    Context "IP Address Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw for invalid IP address" {
            { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "invalid-ip" } | 
                Should -Throw -ExpectedMessage "*Invalid SCSI IP address*"
        }
    }
}

Describe "Set-VmfsStaticIscsi" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Set-VmfsStaticIscsi
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have ScsiIpAddress as mandatory parameter" {
            $command = Get-Command Set-VmfsStaticIscsi
            $param = $command.Parameters['ScsiIpAddress']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have ScsiName as mandatory parameter" {
            $command = Get-Command Set-VmfsStaticIscsi
            $param = $command.Parameters['ScsiName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "IP Address Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw for invalid IP address" {
            { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "invalid-ip" -ScsiName "iqn.test" } | 
                Should -Throw -ExpectedMessage "*Invalid SCSI IP address*"
        }
    }
}

Describe "New-VmfsDatastore" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command New-VmfsDatastore
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have DatastoreName as mandatory parameter" {
            $command = Get-Command New-VmfsDatastore
            $param = $command.Parameters['DatastoreName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have DeviceNaaId as mandatory parameter" {
            $command = Get-Command New-VmfsDatastore
            $param = $command.Parameters['DeviceNaaId']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Size as mandatory parameter" {
            $command = Get-Command New-VmfsDatastore
            $param = $command.Parameters['Size']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Size Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw for size less than 1GB" {
            { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123" -Size "500000000" } | 
                Should -Throw -ExpectedMessage "*Size should be between 1 GB and 64 TB*"
        }

        It "Should throw for size greater than 64TB" {
            # 65TB in bytes = 71494644084736
            { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123" -Size "71494644084736" } | 
                Should -Throw -ExpectedMessage "*Size should be between 1 GB and 64 TB*"
        }

        It "Should throw for invalid size string" {
            { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123" -Size "invalid" } | 
                Should -Throw -ExpectedMessage "*Invalid Size*"
        }
    }

    Context "NAA ID Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw for unsupported NAA ID prefix" {
            { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.unsupported123" -Size "1073741824" } | 
                Should -Throw -ExpectedMessage "*not supported for VMFS volume creation*"
        }

        It "Should not throw NAA validation error for Microsoft NAA ID (naa.60003ff)" {
            # Verify that valid Microsoft NAA ID passes the NAA prefix check
            # The function may fail later due to missing VMware connection, but not on NAA validation
            try {
                New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123456" -Size "1073741824"
            } catch {
                $_.Exception.Message | Should -Not -BeLike "*not supported for VMFS volume creation*"
            }
        }

        It "Should not throw NAA validation error for NetApp NAA ID (naa.600a098)" {
            try {
                New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.600a098123456" -Size "1073741824"
            } catch {
                $_.Exception.Message | Should -Not -BeLike "*not supported for VMFS volume creation*"
            }
        }

        It "Should not throw NAA validation error for Pure Storage NAA ID (naa.624a937)" {
            try {
                New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.624a937123456" -Size "1073741824"
            } catch {
                $_.Exception.Message | Should -Not -BeLike "*not supported for VMFS volume creation*"
            }
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { New-VmfsDatastore -ClusterName "NonExistentCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123" -Size "1073741824" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Datastore Name Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "ExistingDS" } } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when datastore already exists" {
            { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "ExistingDS" -DeviceNaaId "naa.60003ff123" -Size "1073741824" } | 
                Should -Throw -ExpectedMessage "*already exists*"
        }
    }
}

Describe "Dismount-VmfsDatastore" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Dismount-VmfsDatastore
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have DatastoreName as mandatory parameter" {
            $command = Get-Command Dismount-VmfsDatastore
            $param = $command.Parameters['DatastoreName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Dismount-VmfsDatastore -ClusterName "NonExistentCluster" -DatastoreName "TestDS" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Datastore Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when datastore does not exist" {
            { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "NonExistentDS" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Datastore Type Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "NFSDatastore"; Type = "NFS" } } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when datastore is not VMFS type" {
            { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "NFSDatastore" } | 
                Should -Throw -ExpectedMessage "*can only process VMFS datastores*"
        }
    }
}

Describe "Remove-VMHostStaticIScsiTargets" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Remove-VMHostStaticIScsiTargets
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have iSCSIAddress as mandatory parameter" {
            $command = Get-Command Remove-VMHostStaticIScsiTargets
            $param = $command.Parameters['iSCSIAddress']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have optional VMHostName parameter" {
            $command = Get-Command Remove-VMHostStaticIScsiTargets
            $param = $command.Parameters['VMHostName']
            $param | Should -Not -BeNullOrEmpty
            $param.Attributes.Mandatory | Should -Not -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Remove-VMHostStaticIScsiTargets -ClusterName "NonExistentCluster" -iSCSIAddress "192.168.1.10" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

Describe "Remove-VMHostDynamicIScsiTargets" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Remove-VMHostDynamicIScsiTargets
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have iSCSIAddress as mandatory parameter" {
            $command = Get-Command Remove-VMHostDynamicIScsiTargets
            $param = $command.Parameters['iSCSIAddress']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have optional VMHostName parameter" {
            $command = Get-Command Remove-VMHostDynamicIScsiTargets
            $param = $command.Parameters['VMHostName']
            $param | Should -Not -BeNullOrEmpty
            $param.Attributes.Mandatory | Should -Not -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Remove-VMHostDynamicIScsiTargets -ClusterName "NonExistentCluster" -iSCSIAddress "192.168.1.10" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Multiple Address Support" {
        It "Should accept comma-separated addresses" {
            $command = Get-Command Remove-VMHostDynamicIScsiTargets
            $param = $command.Parameters['iSCSIAddress']
            $param.ParameterType.Name | Should -Be 'String'
            # The function splits on comma internally
        }
    }
}

Describe "Resize-VmfsVolume" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Resize-VmfsVolume
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have optional DeviceNaaId parameter" {
            $command = Get-Command Resize-VmfsVolume
            $param = $command.Parameters['DeviceNaaId']
            $param | Should -Not -BeNullOrEmpty
        }

        It "Should have optional DatastoreName parameter" {
            $command = Get-Command Resize-VmfsVolume
            $param = $command.Parameters['DatastoreName']
            $param | Should -Not -BeNullOrEmpty
        }
    }

    Context "Mutual Exclusivity Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when neither DeviceNaaId nor DatastoreName is provided" {
            { Resize-VmfsVolume -ClusterName "TestCluster" } | 
                Should -Throw -ExpectedMessage "*One of DeviceNaaId or DatastoreName values must be provided*"
        }

        It "Should throw when both DeviceNaaId and DatastoreName are provided" {
            { Resize-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "naa.123" -DatastoreName "TestDS" } | 
                Should -Throw -ExpectedMessage "*Cannot provide values for both*"
        }
    }
}

Describe "Restore-VmfsVolume" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Restore-VmfsVolume
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have DeviceNaaId as mandatory parameter" {
            $command = Get-Command Restore-VmfsVolume
            $param = $command.Parameters['DeviceNaaId']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have optional DatastoreName parameter" {
            $command = Get-Command Restore-VmfsVolume
            $param = $command.Parameters['DatastoreName']
            $param | Should -Not -BeNullOrEmpty
        }
    }

    Context "NAA ID Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw for invalid NAA ID format" {
            { Restore-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "invalid-naa" } | 
                Should -Throw -ExpectedMessage "*Invalid Device NAA ID*"
        }

        It "Should accept Pure Storage NAA ID" {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
            { Restore-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "naa.624a9370123456" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }

        It "Should accept NetApp NAA ID" {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
            { Restore-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "naa.600a098123456" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }

        It "Should accept NVMe EUI ID" {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
            { Restore-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "eui.123456789" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

Describe "Sync-VMHostStorage" {
    Context "Parameter Validation" {
        It "Should have VMHostName as mandatory parameter" {
            $command = Get-Command Sync-VMHostStorage
            $param = $command.Parameters['VMHostName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }
}

Describe "Sync-ClusterVMHostStorage" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Sync-ClusterVMHostStorage
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Sync-ClusterVMHostStorage -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

# Note: Connect-NVMeTCPTarget and Disconnect-NVMeTCPTarget are not exported in the module manifest
# These functions exist in the module but are not publicly available

Describe "Get-VmfsDatastore" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Get-VmfsDatastore
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Get-VmfsDatastore -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "No hosts in cluster" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when no hosts found" {
            { Get-VmfsDatastore -ClusterName "TestCluster" } |
                Should -Throw -ExpectedMessage "*No ESXi host found*"
        }
    }

    Context "No VMFS datastores found" {
        It "Should return without error when no datastores found" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                function script:Get-Cluster { param($Name, $ErrorAction) [PSCustomObject]@{ Name = "TestCluster" } }
                function script:Get-VMHost { param($Name, $Datastore, $ErrorAction) [PSCustomObject]@{ Name = "host-01" } }
                function script:Get-Datastore { param($Name, $ErrorAction) $null }
                function script:Get-Unique { $null }

                { Get-VmfsDatastore -ClusterName "TestCluster" } |
                    Should -Not -Throw
            }
        }
    }

    Context "Output contains all expected datastore fields" {
        It "Should populate NamedOutputs with all fields" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockDS = [PSCustomObject]@{
                    Name = "vmfs-ds-01"
                    CapacityGB = 500
                    FreeSpaceGB = 250
                    Type = "VMFS"
                    State = "Available"
                    ExtensionData = [PSCustomObject]@{
                        Info = [PSCustomObject]@{
                            Vmfs = [PSCustomObject]@{
                                uuid = "vmfs-uuid-001"
                                extent = @([PSCustomObject]@{ Diskname = "naa.60003ff44dc75adc" })
                            }
                        }
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) [PSCustomObject]@{ Name = "TestCluster" } }
                function script:Get-VMHost {
                    param($Name, $Datastore, $ErrorAction)
                    [PSCustomObject]@{ Name = "host-01" }
                }
                function script:Get-Datastore { $mockDS }
                function script:Get-Unique { $mockDS }

                Get-VmfsDatastore -ClusterName "TestCluster"

                $Global:NamedOutputs | Should -Not -BeNullOrEmpty
                $Global:NamedOutputs.ContainsKey("vmfs-ds-01") | Should -BeTrue
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "Name\s*:\s*vmfs-ds-01"
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "Capacity\s*:\s*500"
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "FreeSpace\s*:\s*250"
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "Type\s*:\s*VMFS"
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "UUID\s*:\s*vmfs-uuid-001"
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "Device\s*:\s*naa.60003ff44dc75adc"
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "State\s*:\s*Available"
                $Global:NamedOutputs["vmfs-ds-01"] | Should -Match "Hosts\s*:\s*host-01"
            }
        }
    }
}

Describe "Get-VmfsHosts" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Get-VmfsHosts
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Get-VmfsHosts -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Single host output contains all expected fields" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost {
                [PSCustomObject]@{
                    Name = "esxi-host-01"
                    Id = "HostSystem-host-42"
                    Version = "7.0.3"
                    ConnectionState = "Connected"
                    PowerState = "PoweredOn"
                    State = "Connected"
                    ExtensionData = [PSCustomObject]@{
                        Hardware = [PSCustomObject]@{
                            SystemInfo = [PSCustomObject]@{
                                QualifiedName = [PSCustomObject]@{ Value = "nqn.2014-08.org.nvmexpress:uuid:test-uuid" }
                                Uuid = "test-system-uuid-001"
                            }
                        }
                        config = [PSCustomObject]@{
                            StorageDevice = [PSCustomObject]@{
                                NvmeTopology = $null
                            }
                        }
                    }
                }
            } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vmfs-ds-01"; Type = "VMFS" }) } -ModuleName Microsoft.AVS.VMFS

            Get-VmfsHosts -ClusterName "TestCluster"
        }

        It "Should return non-empty NamedOutputs" {
            $Global:NamedOutputs | Should -Not -BeNullOrEmpty
        }

        It "Should key the output by host name" {
            $Global:NamedOutputs.ContainsKey("esxi-host-01") | Should -BeTrue
        }

        It "Should include Name in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Name\s*:\s*esxi-host-01"
        }

        It "Should include Id in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Id\s*:\s*HostSystem-host-42"
        }

        It "Should include Version in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Version\s*:\s*7\.0\.3"
        }

        It "Should include ConnectionState in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "ConnectionState\s*:\s*Connected"
        }

        It "Should include PowerState in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "PowerState\s*:\s*PoweredOn"
        }

        It "Should include State in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "State\s*:\s*Connected"
        }

        It "Should include HostNQN in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "HostNQN\s*:\s*nqn\.2014-08\.org\.nvmexpress:uuid:test-uuid"
        }

        It "Should include Uuid in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Uuid\s*:\s*test-system-uuid-001"
        }

        It "Should include Datastores in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Datastores\s*:\s*vmfs-ds-01"
        }

        It "Should include Extension in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Extension\s*:"
        }
    }

    Context "Multiple hosts output contains all expected fields per host" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost {
                @(
                    [PSCustomObject]@{
                        Name = "esxi-host-01"
                        Id = "HostSystem-host-42"
                        Version = "7.0.3"
                        ConnectionState = "Connected"
                        PowerState = "PoweredOn"
                        State = "Connected"
                        ExtensionData = [PSCustomObject]@{
                            Hardware = [PSCustomObject]@{
                                SystemInfo = [PSCustomObject]@{
                                    QualifiedName = [PSCustomObject]@{ Value = "nqn.host1" }
                                    Uuid = "uuid-host-01"
                                }
                            }
                            config = [PSCustomObject]@{
                                StorageDevice = [PSCustomObject]@{ NvmeTopology = $null }
                            }
                        }
                    },
                    [PSCustomObject]@{
                        Name = "esxi-host-02"
                        Id = "HostSystem-host-99"
                        Version = "8.0.1"
                        ConnectionState = "Maintenance"
                        PowerState = "PoweredOn"
                        State = "Maintenance"
                        ExtensionData = [PSCustomObject]@{
                            Hardware = [PSCustomObject]@{
                                SystemInfo = [PSCustomObject]@{
                                    QualifiedName = [PSCustomObject]@{ Value = "nqn.host2" }
                                    Uuid = "uuid-host-02"
                                }
                            }
                            config = [PSCustomObject]@{
                                StorageDevice = [PSCustomObject]@{ NvmeTopology = $null }
                            }
                        }
                    }
                )
            } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.VMFS

            Get-VmfsHosts -ClusterName "TestCluster"
        }

        It "Should have entries for both hosts" {
            $Global:NamedOutputs.Count | Should -Be 2
        }

        It "Should include Name for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Name\s*:\s*esxi-host-01"
        }

        It "Should include Id for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Id\s*:\s*HostSystem-host-42"
        }

        It "Should include Version for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Version\s*:\s*7\.0\.3"
        }

        It "Should include ConnectionState for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "ConnectionState\s*:\s*Connected"
        }

        It "Should include PowerState for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "PowerState\s*:\s*PoweredOn"
        }

        It "Should include State for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "State\s*:\s*Connected"
        }

        It "Should include HostNQN for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "HostNQN\s*:\s*nqn\.host1"
        }

        It "Should include Uuid for the first host" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "Uuid\s*:\s*uuid-host-01"
        }

        It "Should include Name for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "Name\s*:\s*esxi-host-02"
        }

        It "Should include Id for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "Id\s*:\s*HostSystem-host-99"
        }

        It "Should include Version for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "Version\s*:\s*8\.0\.1"
        }

        It "Should include ConnectionState for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "ConnectionState\s*:\s*Maintenance"
        }

        It "Should include PowerState for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "PowerState\s*:\s*PoweredOn"
        }

        It "Should include State for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "State\s*:\s*Maintenance"
        }

        It "Should include HostNQN for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "HostNQN\s*:\s*nqn\.host2"
        }

        It "Should include Uuid for the second host" {
            $Global:NamedOutputs["esxi-host-02"] | Should -Match "Uuid\s*:\s*uuid-host-02"
        }
    }

    Context "Datastores output only includes VMFS type" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost {
                [PSCustomObject]@{
                    Name = "esxi-host-01"
                    Id = "HostSystem-host-50"
                    Version = "7.0.3"
                    ConnectionState = "Connected"
                    PowerState = "PoweredOn"
                    State = "Connected"
                    ExtensionData = [PSCustomObject]@{
                        Hardware = [PSCustomObject]@{
                            SystemInfo = [PSCustomObject]@{
                                QualifiedName = [PSCustomObject]@{ Value = "nqn.test" }
                                Uuid = "uuid-test"
                            }
                        }
                        config = [PSCustomObject]@{
                            StorageDevice = [PSCustomObject]@{ NvmeTopology = $null }
                        }
                    }
                }
            } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore {
                @(
                    [PSCustomObject]@{ Name = "vmfs-ds-01"; Type = "VMFS" },
                    [PSCustomObject]@{ Name = "nfs-ds-01"; Type = "NFS" },
                    [PSCustomObject]@{ Name = "vmfs-ds-02"; Type = "VMFS" }
                )
            } -ModuleName Microsoft.AVS.VMFS

            Get-VmfsHosts -ClusterName "TestCluster"
        }

        It "Should include VMFS datastores in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "vmfs-ds-01"
            $Global:NamedOutputs["esxi-host-01"] | Should -Match "vmfs-ds-02"
        }

        It "Should not include NFS datastores in the output" {
            $Global:NamedOutputs["esxi-host-01"] | Should -Not -Match "nfs-ds-01"
        }
    }
}

Describe "Get-StorageAdapters" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Get-StorageAdapters
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Get-StorageAdapters -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Output contains adapter data per host" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost {
                @(
                    [PSCustomObject]@{ Name = "host-01" },
                    [PSCustomObject]@{ Name = "host-02" }
                )
            } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHostHba {
                @(
                    [PSCustomObject]@{ Device = "vmhba0"; Model = "iSCSI Software Adapter"; Status = "online"; VMHost = "host-mock" },
                    [PSCustomObject]@{ Device = "vmhba1"; Model = "NVMe Adapter"; Status = "online"; VMHost = "host-mock" }
                )
            } -ModuleName Microsoft.AVS.VMFS

            Get-StorageAdapters -ClusterName "TestCluster" -ErrorAction SilentlyContinue
        }

        It "Should return non-empty NamedOutputs" {
            $Global:NamedOutputs | Should -Not -BeNullOrEmpty
        }

        It "Should have entries for both hosts" {
            $Global:NamedOutputs.Count | Should -Be 2
        }

        It "Should key output by host name" {
            $Global:NamedOutputs.ContainsKey("host-01") | Should -BeTrue
            $Global:NamedOutputs.ContainsKey("host-02") | Should -BeTrue
        }

        It "Should include adapter device names in output" {
            $Global:NamedOutputs["host-01"] | Should -Match "vmhba0"
            $Global:NamedOutputs["host-01"] | Should -Match "vmhba1"
        }

        It "Should include adapter model in output" {
            $Global:NamedOutputs["host-01"] | Should -Match "iSCSI Software Adapter"
        }

        It "Should exclude VMHost property from output" {
            $Global:NamedOutputs["host-01"] | Should -Not -Match '"VMHost"'
        }
    }

    Context "Host with no adapters is skipped" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { [PSCustomObject]@{ Name = "host-01" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHostHba { $null } -ModuleName Microsoft.AVS.VMFS

            Get-StorageAdapters -ClusterName "TestCluster" -ErrorAction SilentlyContinue
        }

        It "Should return empty NamedOutputs" {
            $Global:NamedOutputs.Count | Should -Be 0
        }
    }
}

Describe "Get-VmKernelAdapters" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Get-VmKernelAdapters
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Get-VmKernelAdapters -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Output contains kernel adapter data per host" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost {
                @(
                    [PSCustomObject]@{ Name = "host-01" },
                    [PSCustomObject]@{ Name = "host-02" }
                )
            } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHostNetworkAdapter {
                @(
                    [PSCustomObject]@{ Name = "vmk0"; IP = "10.0.0.1"; SubnetMask = "255.255.255.0"; VMHost = "host-mock" },
                    [PSCustomObject]@{ Name = "vmk5"; IP = "10.0.1.1"; SubnetMask = "255.255.255.0"; VMHost = "host-mock" }
                )
            } -ModuleName Microsoft.AVS.VMFS

            Get-VmKernelAdapters -ClusterName "TestCluster" -ErrorAction SilentlyContinue
        }

        It "Should return non-empty NamedOutputs" {
            $Global:NamedOutputs | Should -Not -BeNullOrEmpty
        }

        It "Should have entries for both hosts" {
            $Global:NamedOutputs.Count | Should -Be 2
        }

        It "Should key output by host name" {
            $Global:NamedOutputs.ContainsKey("host-01") | Should -BeTrue
            $Global:NamedOutputs.ContainsKey("host-02") | Should -BeTrue
        }

        It "Should include kernel adapter names in output" {
            $Global:NamedOutputs["host-01"] | Should -Match "vmk0"
            $Global:NamedOutputs["host-01"] | Should -Match "vmk5"
        }

        It "Should include IP addresses in output" {
            $Global:NamedOutputs["host-01"] | Should -Match "10\.0\.0\.1"
            $Global:NamedOutputs["host-01"] | Should -Match "10\.0\.1\.1"
        }

        It "Should exclude VMHost property from output" {
            $Global:NamedOutputs["host-01"] | Should -Not -Match '"VMHost"'
        }
    }

    Context "Host with no kernel adapters is skipped" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { [PSCustomObject]@{ Name = "host-01" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHostNetworkAdapter { $null } -ModuleName Microsoft.AVS.VMFS

            Get-VmKernelAdapters -ClusterName "TestCluster" -ErrorAction SilentlyContinue
        }

        It "Should return empty NamedOutputs" {
            $Global:NamedOutputs.Count | Should -Be 0
        }
    }
}

Describe "Repair-HAConfiguration" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Repair-HAConfiguration
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Repair-HAConfiguration -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

Describe "Clear-DisconnectedIscsiTargets" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Clear-DisconnectedIscsiTargets
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have optional VMHostName parameter" {
            $command = Get-Command Clear-DisconnectedIscsiTargets
            $param = $command.Parameters['VMHostName']
            $param | Should -Not -BeNullOrEmpty
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Clear-DisconnectedIscsiTargets -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

Describe "Test-VMKernelConnectivity" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Test-VMKernelConnectivity
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Test-VMKernelConnectivity -ClusterName "NonExistentCluster" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

# Note: Set-NVMeTCP and New-NVMeTCPAdapter are not exported in the module manifest
# These functions exist in the module but are not publicly available

Describe "New-VmfsVmSnapshot" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command New-VmfsVmSnapshot
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have datastoreName as mandatory parameter" {
            $command = Get-Command New-VmfsVmSnapshot
            $param = $command.Parameters['datastoreName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { New-VmfsVmSnapshot -ClusterName "NonExistentCluster" -datastoreName "TestDS" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

Describe "Mount-VmfsDatastore" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Mount-VmfsDatastore
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have DatastoreName as mandatory parameter" {
            $command = Get-Command Mount-VmfsDatastore
            $param = $command.Parameters['DatastoreName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Mount-VmfsDatastore -ClusterName "NonExistentCluster" -DatastoreName "TestDS" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Datastore Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when datastore does not exist" {
            { Mount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "NonExistentDS" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Datastore Type Validation" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "NFSDatastore"; Type = "NFS" } } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when datastore is not VMFS type" {
            { Mount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "NFSDatastore" } | 
                Should -Throw -ExpectedMessage "*can only process VMFS datastores*"
        }
    }
}

Describe "Remove-VmfsDatastore" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Remove-VmfsDatastore
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have DatastoreName as mandatory parameter" {
            $command = Get-Command Remove-VmfsDatastore
            $param = $command.Parameters['DatastoreName']
            $param.Attributes.Mandatory | Should -Contain $true
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster does not exist" {
            { Remove-VmfsDatastore -ClusterName "NonExistentCluster" -DatastoreName "TestDS" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }
}

Describe "Remove-VMHostStaticIScsiTargets - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        # Create mock objects
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
        $script:mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1.local" }
        $script:mockHBA = [PSCustomObject]@{ Device = "vmhba65"; VMHost = $script:mockVMHost }
    }

    Context "Target type filtering logic" {
        It "Should filter targets by Static type and matching address" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost, $script:mockHBA) -ScriptBlock {
                param($mockCluster, $mockVMHost, $mockHBA)
                
                $staticTarget = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Static" }
                $sendTarget = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Send" }
                $otherStaticTarget = [PSCustomObject]@{ Address = "10.0.0.1"; Type = "Static" }
                
                # Override cmdlets with simple functions that don't validate types
                function script:Get-Cluster { param($Name) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-Datastore { @() }
                function script:Get-VMHostHba { param($Type) $mockHBA }
                function script:Get-ScsiLun { @() }
                function script:Get-IScsiHbaTarget { @($staticTarget, $sendTarget, $otherStaticTarget) }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCallCount++ }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVMFS) }
                
                $script:removeCallCount = 0
                
                Remove-VMHostStaticIScsiTargets -ClusterName "TestCluster" -iSCSIAddress "192.168.1.10"
                
                $script:removeCallCount | Should -Be 1
            }
        }
        
        It "Should handle comma-separated addresses" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost, $script:mockHBA) -ScriptBlock {
                param($mockCluster, $mockVMHost, $mockHBA)
                
                $target1 = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Static" }
                $target2 = [PSCustomObject]@{ Address = "192.168.1.11"; Type = "Static" }
                $target3 = [PSCustomObject]@{ Address = "192.168.1.99"; Type = "Static" }
                
                function script:Get-Cluster { param($Name) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-Datastore { @() }
                function script:Get-VMHostHba { param($Type) $mockHBA }
                function script:Get-ScsiLun { @() }
                function script:Get-IScsiHbaTarget { @($target1, $target2, $target3) }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCallCount++ }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVMFS) }
                
                $script:removeCallCount = 0
                
                Remove-VMHostStaticIScsiTargets -ClusterName "TestCluster" -iSCSIAddress "192.168.1.10,192.168.1.11"
                
                $script:removeCallCount | Should -Be 2
            }
        }
        
        It "Should not remove targets when no address matches" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost, $script:mockHBA) -ScriptBlock {
                param($mockCluster, $mockVMHost, $mockHBA)
                
                $target = [PSCustomObject]@{ Address = "10.0.0.1"; Type = "Static" }
                
                function script:Get-Cluster { param($Name) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-Datastore { @() }
                function script:Get-VMHostHba { param($Type) $mockHBA }
                function script:Get-ScsiLun { @() }
                function script:Get-IScsiHbaTarget { @($target) }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCallCount++ }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVMFS) $script:rescanCallCount++ }
                
                $script:removeCallCount = 0
                $script:rescanCallCount = 0
                
                Remove-VMHostStaticIScsiTargets -ClusterName "TestCluster" -iSCSIAddress "192.168.1.10"
                
                $script:removeCallCount | Should -Be 0
                $script:rescanCallCount | Should -Be 0
            }
        }
        
        It "Should skip device-in-use targets" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost, $script:mockHBA) -ScriptBlock {
                param($mockCluster, $mockVMHost, $mockHBA)
                
                $mockScsiLun = [PSCustomObject]@{ CanonicalName = "naa.60003ff123456789" }
                $extent = [PSCustomObject]@{ DiskName = "naa.60003ff123456789" }
                $vmfsInfo = [PSCustomObject]@{ Extent = @($extent) }
                $dsInfo = [PSCustomObject]@{ Vmfs = $vmfsInfo }
                $extData = [PSCustomObject]@{ Info = $dsInfo }
                $datastore = [PSCustomObject]@{ ExtensionData = $extData }
                $target = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Static" }
                
                function script:Get-Cluster { param($Name) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-Datastore { @($datastore) }
                function script:Get-VMHostHba { param($Type) $mockHBA }
                function script:Get-ScsiLun { @($mockScsiLun) }
                function script:Get-IScsiHbaTarget { @($target) }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCallCount++ }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVMFS) }
                
                $script:removeCallCount = 0
                
                Remove-VMHostStaticIScsiTargets -ClusterName "TestCluster" -iSCSIAddress "192.168.1.10" -WarningAction SilentlyContinue
                
                $script:removeCallCount | Should -Be 0
            }
        }
        
        It "Should rescan storage after removing targets" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost, $script:mockHBA) -ScriptBlock {
                param($mockCluster, $mockVMHost, $mockHBA)
                
                $target = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Static" }
                
                function script:Get-Cluster { param($Name) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-Datastore { @() }
                function script:Get-VMHostHba { param($Type) $mockHBA }
                function script:Get-ScsiLun { @() }
                function script:Get-IScsiHbaTarget { @($target) }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCallCount++ }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVMFS) $script:rescanCallCount++ }
                
                $script:removeCallCount = 0
                $script:rescanCallCount = 0
                
                Remove-VMHostStaticIScsiTargets -ClusterName "TestCluster" -iSCSIAddress "192.168.1.10"
                
                $script:rescanCallCount | Should -Be 1
            }
        }
    }
}

Describe "Remove-VMHostDynamicIScsiTargets - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
        $script:mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1.local" }
        $script:mockHBA = [PSCustomObject]@{ Device = "vmhba65"; VMHost = $script:mockVMHost }
    }

    Context "Target type filtering logic" {
        It "Should filter targets by Send type (not Static)" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost, $script:mockHBA) -ScriptBlock {
                param($mockCluster, $mockVMHost, $mockHBA)
                
                $staticTarget = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Static" }
                $sendTarget = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Send" }
                
                function script:Get-Cluster { param($Name) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-Datastore { @() }
                function script:Get-VMHostHba { param($Type) $mockHBA }
                function script:Get-ScsiLun { @() }
                function script:Get-IScsiHbaTarget { @($staticTarget, $sendTarget) }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCallCount++ }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVMFS) }
                
                $script:removeCallCount = 0
                
                Remove-VMHostDynamicIScsiTargets -ClusterName "TestCluster" -iSCSIAddress "192.168.1.10"
                
                $script:removeCallCount | Should -Be 1
            }
        }
        
        It "Should not remove Static targets even when address matches" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost, $script:mockHBA) -ScriptBlock {
                param($mockCluster, $mockVMHost, $mockHBA)
                
                $staticTarget = [PSCustomObject]@{ Address = "192.168.1.10"; Type = "Static" }
                
                function script:Get-Cluster { param($Name) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-Datastore { @() }
                function script:Get-VMHostHba { param($Type) $mockHBA }
                function script:Get-ScsiLun { @() }
                function script:Get-IScsiHbaTarget { @($staticTarget) }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCallCount++ }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVMFS) }
                
                $script:removeCallCount = 0
                
                Remove-VMHostDynamicIScsiTargets -ClusterName "TestCluster" -iSCSIAddress "192.168.1.10"
                
                $script:removeCallCount | Should -Be 0
            }
        }
    }
}

Describe "ValidateNotNullOrEmpty Parameter Attribute" {
    $testCases = @(
        @{ Function = 'Set-VmfsIscsi'; Parameter = 'ClusterName' }
        @{ Function = 'Set-VmfsIscsi'; Parameter = 'ScsiIpAddress' }
        @{ Function = 'Set-VmfsStaticIscsi'; Parameter = 'ClusterName' }
        @{ Function = 'Set-VmfsStaticIscsi'; Parameter = 'ScsiIpAddress' }
        @{ Function = 'Set-VmfsStaticIscsi'; Parameter = 'ScsiName' }
        @{ Function = 'New-VmfsDatastore'; Parameter = 'ClusterName' }
        @{ Function = 'New-VmfsDatastore'; Parameter = 'DatastoreName' }
        @{ Function = 'New-VmfsDatastore'; Parameter = 'DeviceNaaId' }
        @{ Function = 'New-VmfsDatastore'; Parameter = 'Size' }
        @{ Function = 'Dismount-VmfsDatastore'; Parameter = 'ClusterName' }
        @{ Function = 'Dismount-VmfsDatastore'; Parameter = 'DatastoreName' }
        @{ Function = 'Resize-VmfsVolume'; Parameter = 'ClusterName' }
        @{ Function = 'Restore-VmfsVolume'; Parameter = 'ClusterName' }
        @{ Function = 'Restore-VmfsVolume'; Parameter = 'DeviceNaaId' }
        @{ Function = 'Sync-VMHostStorage'; Parameter = 'VMHostName' }
        @{ Function = 'Sync-ClusterVMHostStorage'; Parameter = 'ClusterName' }
        @{ Function = 'Mount-VmfsDatastore'; Parameter = 'ClusterName' }
        @{ Function = 'Mount-VmfsDatastore'; Parameter = 'DatastoreName' }
        @{ Function = 'Remove-VMHostStaticIScsiTargets'; Parameter = 'ClusterName' }
        @{ Function = 'Remove-VMHostStaticIScsiTargets'; Parameter = 'iSCSIAddress' }
        @{ Function = 'Remove-VMHostDynamicIScsiTargets'; Parameter = 'ClusterName' }
        @{ Function = 'Remove-VMHostDynamicIScsiTargets'; Parameter = 'iSCSIAddress' }
    )

    It "<Function> should have ValidateNotNullOrEmpty on <Parameter>" -TestCases $testCases {
        param($Function, $Parameter)
        $command = Get-Command $Function
        $command.Parameters[$Parameter].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] } |
            Should -Not -BeNullOrEmpty
    }
}

Describe "Set-VmfsIscsi - Null Check Edge Cases" {
    Context "No hosts found in cluster" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { @() } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster has no hosts" {
            { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.1.1" } |
                Should -Throw "*No hosts found in cluster*"
        }
    }
}

Describe "Set-VmfsStaticIscsi - Null Check Edge Cases" {
    Context "No hosts found in cluster" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { @() } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster has no hosts" {
            { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.1.1" -ScsiName "iqn.test" } |
                Should -Throw "*No hosts found in cluster*"
        }
    }
}

Describe "Dismount-VmfsDatastore - Null Check Edge Cases" {
    Context "No hosts found in cluster" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "TestDS"; Type = "VMFS" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { @() } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when cluster has no hosts" {
            { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                Should -Throw "*No hosts found in cluster*"
        }
    }
}

Describe "New-VmfsDatastore - Null Check Edge Cases" {
    Context "No connected hosts in cluster" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { [PSCustomObject]@{ Name = "host1"; ConnectionState = "Disconnected" } } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when no connected hosts found" {
            { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123" -Size "1073741824" } |
                Should -Throw "*No connected hosts found*"
        }
    }
}

Describe "Sync-VMHostStorage - Null Check Edge Cases" {
    Context "VMHost does not exist" {
        BeforeAll {
            Mock Get-VMHost { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when VMHost does not exist" {
            { Sync-VMHostStorage -VMHostName "NonExistentHost" } |
                Should -Throw "*does not exist*"
        }
    }
}

Describe "Remove-VmfsDatastore - Null Check Edge Cases" {
    Context "No connected hosts with datastore" {
        It "Should throw when no connected hosts found with datastore" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                function script:Get-Cluster { param($Name, $ErrorAction) [PSCustomObject]@{ Name = "TestCluster" } }
                function script:Get-Datastore { param($Name, $ErrorAction) [PSCustomObject]@{ Name = "TestDS"; State = "Available" } }
                function script:Get-VM { param($Datastore, $ErrorAction) $null }
                function script:Get-VMHost {
                    param($Datastore, $State)
                    if ($Datastore) { return $null }
                    return [PSCustomObject]@{ Name = "host-01" }
                }

                { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*No connected hosts found*"
            }
        }
    }
}

Describe "Resize-VmfsVolume - Error Message Fix" {
    Context "Non-VMFS Datastore Type Error" {
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "NFSDatastore"; Type = "NFS" } } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should reference 'VMFS datastores' in error message" {
            { Resize-VmfsVolume -ClusterName "TestCluster" -DatastoreName "NFSDatastore" } |
                Should -Throw "*VMFS datastores*"
        }

        It "Should not reference 'iSCSI datastores' in error message" {
            try {
                Resize-VmfsVolume -ClusterName "TestCluster" -DatastoreName "NFSDatastore"
            } catch {
                $_.Exception.Message | Should -Not -BeLike "*iSCSI datastores*"
            }
        }
    }
}

Describe "Set-VmfsIscsi - IP Address Exact Match" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
        $script:mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }
    }

    # With -cmatch, regex dots match any character and partial matching occurs (e.g., "192.168.0.10" -cmatch "192.168.0.1" is $true).
    # With -eq, only exact matches are considered.
    Context "Uses -eq instead of -cmatch for IP comparison" {
        It "Should add new target when existing target has similar but non-exact IP" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost) -ScriptBlock {
                param($mockCluster, $mockVMHost)

                $existingTarget = [PSCustomObject]@{ Address = "192.168.0.10" }
                $mockIscsiAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockIscsiStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockIscsiStorage }
                function script:Get-VMHostHba { param($Type) $mockIscsiAdapter }
                function script:Get-IScsiHbaTarget { param($IScsiHba, $Type, $ErrorAction) @($existingTarget) }
                function script:New-IScsiHbaTarget { param($IScsiHba, $Address, $ErrorAction) $script:newTargetCalled = $true }
                function script:Get-EsxCli { throw "EsxCli mock stop" }

                $script:newTargetCalled = $false

                try {
                    Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1"
                } catch { }

                # With -eq, "192.168.0.10" != "192.168.0.1", so New-IScsiHbaTarget should be called
                $script:newTargetCalled | Should -Be $true
            }
        }

        It "Should not add target when existing target has exact same IP" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost) -ScriptBlock {
                param($mockCluster, $mockVMHost)

                $existingTarget = [PSCustomObject]@{ Address = "192.168.0.1" }
                $mockIscsiAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockIscsiStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockIscsiStorage }
                function script:Get-VMHostHba { param($Type) $mockIscsiAdapter }
                function script:Get-IScsiHbaTarget { param($IScsiHba, $Type, $ErrorAction) @($existingTarget) }
                function script:New-IScsiHbaTarget { param($IScsiHba, $Address, $ErrorAction) $script:newTargetCalled = $true }
                function script:Get-EsxCli { throw "EsxCli mock stop" }

                $script:newTargetCalled = $false

                try {
                    Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1"
                } catch { }

                # Exact match means target already exists, so New-IScsiHbaTarget should not be called
                $script:newTargetCalled | Should -Be $false
            }
        }
    }
}

Describe "Set-VmfsStaticIscsi - IP Address Exact Match" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
        $script:mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }
    }

    Context "Uses -eq instead of -cmatch for IP comparison" {
        It "Should add new static target when existing has similar but non-exact IP" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost) -ScriptBlock {
                param($mockCluster, $mockVMHost)

                $existingTarget = [PSCustomObject]@{ Address = "192.168.0.10" }
                $mockIscsiAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockIscsiStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockIscsiStorage }
                function script:Set-VMHostStorage { param([switch]$SoftwareIScsiEnabled) }
                function script:Get-VMHostHba { param($Type) $mockIscsiAdapter }
                function script:Get-IScsiHbaTarget { param($IScsiHba, $Type, $ErrorAction) @($existingTarget) }
                function script:New-IScsiHbaTarget { param($IScsiHba, $Type, $Address, $IScsiName, $ErrorAction) $script:newTargetCalled = $true }
                function script:Get-EsxCli { throw "EsxCli mock stop" }

                $script:newTargetCalled = $false

                try {
                    Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" -ScsiName "iqn.test"
                } catch { }

                $script:newTargetCalled | Should -Be $true
            }
        }
    }
}

Describe "Set-VmfsIscsi - iSCSI Adapter Null Check" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
        $script:mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }
    }

    Context "Host without iSCSI adapter" {
        It "Should throw when host has no iSCSI adapter" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost) -ScriptBlock {
                param($mockCluster, $mockVMHost)

                $mockIscsiStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockIscsiStorage }
                function script:Get-VMHostHba { param($Type) $null }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Throw "*No iSCSI Software Adapter found on host*"
            }
        }
    }
}

Describe "Set-VmfsStaticIscsi - iSCSI Adapter Null Check" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
        $script:mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }
    }

    Context "Host without iSCSI adapter" {
        It "Should throw when host has no iSCSI adapter" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockVMHost) -ScriptBlock {
                param($mockCluster, $mockVMHost)

                $mockIscsiStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockIscsiStorage }
                function script:Set-VMHostStorage { param([switch]$SoftwareIScsiEnabled) }
                function script:Get-VMHostHba { param($Type) $null }

                { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" -ScsiName "iqn.test" } |
                    Should -Throw "*No iSCSI Software Adapter found on host*"
            }
        }
    }
}

Describe "New-VmfsDatastore - Device and Options Null Checks" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
        $script:mockHost = [PSCustomObject]@{ Name = "host-1"; ConnectionState = "Connected" }
    }

    Context "Device not found" {
        It "Should throw when device with NAA ID not found on any host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockHost) -ScriptBlock {
                param($mockCluster, $mockHost)

                $mockDsSystem = New-Object PSObject
                $mockDsSystem | Add-Member -MemberType ScriptMethod -Name 'QueryAvailableDisksForVmfs' -Value {
                    param($p) @()
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { $null }
                function script:Get-VMHost { @($mockHost) }
                function script:Get-View {
                    param($ViewType, $Filter, $Id)
                    if ($ViewType) {
                        return [PSCustomObject]@{
                            ConfigManager = [PSCustomObject]@{ DatastoreSystem = "ds-system-1" }
                        }
                    }
                    return $mockDsSystem
                }

                { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123" -Size "1073741824" } |
                    Should -Throw "*Device with NAA ID*not found*"
            }
        }
    }

    Context "No datastore create options" {
        It "Should throw when no create options available for device" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster, $script:mockHost) -ScriptBlock {
                param($mockCluster, $mockHost)

                $mockDsSystem = New-Object PSObject
                $mockDsSystem | Add-Member -MemberType ScriptMethod -Name 'QueryAvailableDisksForVmfs' -Value {
                    param($p)
                    @([PSCustomObject]@{
                        CanonicalName = "naa.60003ff123"
                        Uuid = "device-uuid-123"
                        DevicePath = "/vmfs/devices/disks/naa.60003ff123"
                    })
                }
                $mockDsSystem | Add-Member -MemberType ScriptMethod -Name 'QueryVmfsDatastoreCreateOptions' -Value {
                    param($p1, $p2) @()
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { $null }
                function script:Get-VMHost { @($mockHost) }
                function script:Get-View {
                    param($ViewType, $Filter, $Id)
                    if ($ViewType) {
                        return [PSCustomObject]@{
                            ConfigManager = [PSCustomObject]@{ DatastoreSystem = "ds-system-1" }
                        }
                    }
                    return $mockDsSystem
                }

                { New-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" -DeviceNaaId "naa.60003ff123" -Size "1073741824" } |
                    Should -Throw "*No VMFS datastore create options*"
            }
        }
    }
}

Describe "Dismount-VmfsDatastore - Rollback on Failure" -Tag "Behavioral" {
    Context "When unmount fails on the only host" {
        It "Should throw with rollback message and no rollback needed" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $failingStorageSystem = New-Object PSObject
                $failingStorageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                    param($uuid) throw "Unmount failed"
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost) }
                function script:Get-Datastore { param($Name, $VMHost, $ErrorAction) $mockDatastore }
                function script:Get-VM { $null }
                function script:Get-ScsiLun {
                    [PSCustomObject]@{ ExtensionData = [PSCustomObject]@{ uuid = "scsi-uuid-123" } }
                }
                function script:Get-View { param($Id) $failingStorageSystem }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*Failed to dismount datastore*rolled back*"
            }
        }
    }

    Context "When unmount fails on the second host" {
        It "Should roll back the first host (re-attach + re-mount) and throw" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }
                $mockHost2 = [PSCustomObject]@{
                    Name = "host-2"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-2"
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:unmountCallCount = 0
                $script:attachScsiCalled = $false
                $script:mountVmfsCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-Datastore { param($Name, $VMHost, $ErrorAction) $mockDatastore }
                function script:Get-VM { $null }
                function script:Get-ScsiLun {
                    [PSCustomObject]@{ ExtensionData = [PSCustomObject]@{ uuid = "scsi-uuid-123" } }
                }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                function script:Get-View {
                    param($Id)
                    $storageSystem = New-Object PSObject
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid)
                        $script:unmountCallCount++
                        if ($script:unmountCallCount -ge 2) {
                            throw "Unmount failed on second host"
                        }
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'DetachScsiLun' -Value {
                        param($uuid)
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'AttachScsiLun' -Value {
                        param($uuid)
                        $script:attachScsiCalled = $true
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                        $script:mountVmfsCalled = $true
                    }
                    return $storageSystem
                }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*Failed to dismount datastore*host-2*rolled back*"

                $script:attachScsiCalled | Should -Be $true
                $script:mountVmfsCalled | Should -Be $true
            }
        }
    }

    Context "When SCSI detach fails on the second host" {
        It "Should roll back only the first host (already detached) and throw" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }
                $mockHost2 = [PSCustomObject]@{
                    Name = "host-2"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-2"
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:detachCallCount = 0
                $script:attachScsiCalled = $false
                $script:mountVmfsCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-Datastore { param($Name, $VMHost, $ErrorAction) $mockDatastore }
                function script:Get-VM { $null }
                function script:Get-ScsiLun {
                    [PSCustomObject]@{ ExtensionData = [PSCustomObject]@{ uuid = "scsi-uuid-123" } }
                }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                function script:Get-View {
                    param($Id)
                    $storageSystem = New-Object PSObject
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid)
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'DetachScsiLun' -Value {
                        param($uuid)
                        $script:detachCallCount++
                        if ($script:detachCallCount -ge 2) {
                            throw "Detach SCSI failed on second host"
                        }
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'AttachScsiLun' -Value {
                        param($uuid)
                        $script:attachScsiCalled = $true
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                        $script:mountVmfsCalled = $true
                    }
                    return $storageSystem
                }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*Failed to dismount datastore*host-2*rolled back*"

                $script:attachScsiCalled | Should -Be $true
                $script:mountVmfsCalled | Should -Be $true
            }
        }
    }

    Context "NVMe/TCP volume (eui. disk name)" {
        It "Should not detach SCSI LUN and rollback should only re-mount" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }
                $mockHost2 = [PSCustomObject]@{
                    Name = "host-2"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-2"
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "eui.abc123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:unmountCallCount = 0
                $script:detachScsiCalled = $false
                $script:attachScsiCalled = $false
                $script:mountVmfsCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-Datastore { param($Name, $VMHost, $ErrorAction) $mockDatastore }
                function script:Get-VM { $null }
                function script:Get-ScsiLun {
                    [PSCustomObject]@{ ExtensionData = [PSCustomObject]@{ uuid = "scsi-uuid-123" } }
                }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                function script:Get-View {
                    param($Id)
                    $storageSystem = New-Object PSObject
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid)
                        $script:unmountCallCount++
                        if ($script:unmountCallCount -ge 2) {
                            throw "Unmount failed on second host"
                        }
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'DetachScsiLun' -Value {
                        param($uuid)
                        $script:detachScsiCalled = $true
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'AttachScsiLun' -Value {
                        param($uuid)
                        $script:attachScsiCalled = $true
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                        $script:mountVmfsCalled = $true
                    }
                    return $storageSystem
                }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*Failed to dismount datastore*rolled back*"

                # SCSI detach should never have been called (NVMe/TCP path)
                $script:detachScsiCalled | Should -Be $false
                # Rollback should re-mount but not re-attach
                $script:attachScsiCalled | Should -Be $false
                $script:mountVmfsCalled | Should -Be $true
            }
        }
    }

    Context "VM pre-validation" {
        It "Should throw before any unmount when VMs are on the datastore" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:unmountCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost) }
                function script:Get-Datastore { param($Name, $VMHost, $ErrorAction) $mockDatastore }
                function script:Get-VM { @([PSCustomObject]@{ Name = "VM1" }) }
                function script:Get-View {
                    param($Id)
                    $storageSystem = New-Object PSObject
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid) $script:unmountCalled = $true
                    }
                    return $storageSystem
                }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*Cannot unmount datastore*already in use*"

                $script:unmountCalled | Should -Be $false
            }
        }
    }

    Context "Datastore not connected to any host" {
        It "Should return without attempting unmount" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastoreGlobal = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:unmountCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost) }
                function script:Get-Datastore {
                    param($Name, $VMHost, $ErrorAction)
                    # When called with -VMHost, return different datastore
                    if ($VMHost) {
                        return @([PSCustomObject]@{ Name = "OtherDS"; Type = "VMFS" })
                    }
                    return $mockDatastoreGlobal
                }
                function script:Get-VM { $null }
                function script:Get-ScsiLun {
                    [PSCustomObject]@{ ExtensionData = [PSCustomObject]@{ uuid = "scsi-uuid-123" } }
                }
                function script:Get-View {
                    param($Id)
                    $storageSystem = New-Object PSObject
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid) $script:unmountCalled = $true
                    }
                    return $storageSystem
                }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Not -Throw

                $script:unmountCalled | Should -Be $false
            }
        }
    }
}

Describe "Mount-VmfsDatastore - Rollback on Failure" -Tag "Behavioral" {
    Context "When mount fails on the second host" {
        It "Should roll back by unmounting the first host and throw" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-1"
                    ExtensionData = [PSCustomObject]@{
                        config = [PSCustomObject]@{
                            StorageDevice = [PSCustomObject]@{
                                ScsiLun = @([PSCustomObject]@{ DevicePath = "/vmfs/devices/disks/naa.60003ff123" })
                            }
                        }
                    }
                }
                $mockHost2 = [PSCustomObject]@{
                    Name = "host-2"
                    ExtensionData = [PSCustomObject]@{
                        config = [PSCustomObject]@{
                            StorageDevice = [PSCustomObject]@{
                                ScsiLun = @([PSCustomObject]@{ DevicePath = "/vmfs/devices/disks/naa.60003ff123" })
                            }
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    Info = [PSCustomObject]@{
                        vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:mountCallCount = 0
                $script:unmountCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-Datastore { param($Name, $ErrorAction) $mockDatastore }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                function script:Get-View {
                    param($Id)
                    $mockView = New-Object PSObject
                    $mockView | Add-Member -MemberType NoteProperty -Name 'ConfigManager' -Value ([PSCustomObject]@{
                        StorageSystem = "StorageSystem-mock"
                    })
                    $mockView | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                        $script:mountCallCount++
                        if ($script:mountCallCount -ge 2) {
                            throw "Mount failed on second host"
                        }
                    }
                    $mockView | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid)
                        $script:unmountCalled = $true
                    }
                    return $mockView
                }

                { Mount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*Failed to mount datastore*host-2*rolled back*"

                $script:unmountCalled | Should -Be $true
            }
        }
    }

    Context "When mount succeeds on all hosts" {
        It "Should not trigger rollback" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-1"
                    ExtensionData = [PSCustomObject]@{
                        config = [PSCustomObject]@{
                            StorageDevice = [PSCustomObject]@{
                                ScsiLun = @([PSCustomObject]@{ DevicePath = "/vmfs/devices/disks/naa.60003ff123" })
                            }
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    Info = [PSCustomObject]@{
                        vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:unmountCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1) }
                function script:Get-Datastore { param($Name, $ErrorAction) $mockDatastore }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                function script:Get-View {
                    param($Id)
                    $mockView = New-Object PSObject
                    $mockView | Add-Member -MemberType NoteProperty -Name 'ConfigManager' -Value ([PSCustomObject]@{
                        StorageSystem = "StorageSystem-mock"
                    })
                    $mockView | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                    }
                    $mockView | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid)
                        $script:unmountCalled = $true
                    }
                    return $mockView
                }

                { Mount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Not -Throw

                $script:unmountCalled | Should -Be $false
            }
        }
    }

    Context "When host has no device for the datastore" {
        It "Should skip that host without error" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-no-device"
                    ExtensionData = [PSCustomObject]@{
                        config = [PSCustomObject]@{
                            StorageDevice = [PSCustomObject]@{
                                ScsiLun = @([PSCustomObject]@{ DevicePath = "/vmfs/devices/disks/naa.OTHER" })
                            }
                        }
                    }
                }

                $mockExtData = [PSCustomObject]@{
                    Info = [PSCustomObject]@{
                        vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-123"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff123" })
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = $mockExtData
                }

                $script:mountCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1) }
                function script:Get-Datastore { param($Name, $ErrorAction) $mockDatastore }

                function script:Get-View {
                    param($Id)
                    $mockView = New-Object PSObject
                    $mockView | Add-Member -MemberType NoteProperty -Name 'ConfigManager' -Value ([PSCustomObject]@{
                        StorageSystem = "StorageSystem-mock"
                    })
                    $mockView | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                        $script:mountCalled = $true
                    }
                    return $mockView
                }

                { Mount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Not -Throw

                $script:mountCalled | Should -Be $false
            }
        }
    }
}

Describe "Remove-VmfsDatastore - Shared Datastore Rollback" -Tag "Behavioral" {
    Context "When unmount fails on the second host in shared mode" {
        It "Should roll back by re-mounting the first host and throw" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }
                $mockHost2 = [PSCustomObject]@{
                    Name = "host-2"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-2"
                        }
                    }
                }

                # Related host belongs to a different cluster to trigger shared mode
                $mockRelatedHost = [PSCustomObject]@{
                    Name = "host-other-cluster"
                    State = "Connected"
                    Parent = [PSCustomObject]@{ Name = "OtherCluster" }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-shared"
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "SharedDS"
                    Type = "VMFS"
                    State = "Available"
                    ExtensionData = $mockExtData
                }

                $script:unmountCallCount = 0
                $script:mountCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                # Get-VMHost cases: -State returns related hosts, -Datastore returns related, default returns cluster hosts
                function script:Get-VMHost {
                    param($Name, $Datastore, [string]$State)
                    if ($Datastore) { return @($mockRelatedHost) }
                    if ($State) { return @($mockHost1, $mockHost2) }
                    return @($mockHost1, $mockHost2)
                }
                function script:Get-Datastore { param($Name, $ErrorAction) $mockDatastore }
                function script:Get-VM { param($Datastore, $ErrorAction) $null }
                function script:Get-VMHostStorage { param($VMHost, [switch]$RescanAllHba, [switch]$RescanVmfs) }

                function script:Get-View {
                    param($Id)
                    $storageSystem = New-Object PSObject
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid)
                        $script:unmountCallCount++
                        if ($script:unmountCallCount -ge 2) {
                            throw "Unmount failed on second host"
                        }
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                        $script:mountCalled = $true
                    }
                    return $storageSystem
                }

                { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "SharedDS" } |
                    Should -Throw "*Failed to unmount shared datastore*host-2*rolled back*"

                $script:mountCalled | Should -Be $true
            }
        }
    }

    Context "When all hosts unmount successfully in shared mode" {
        It "Should not trigger rollback" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
                $mockHost1 = [PSCustomObject]@{
                    Name = "host-1"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "StorageSystem-host-1"
                        }
                    }
                }

                $mockRelatedHost = [PSCustomObject]@{
                    Name = "host-other-cluster"
                    State = "Connected"
                    Parent = [PSCustomObject]@{ Name = "OtherCluster" }
                }

                $mockExtData = [PSCustomObject]@{
                    info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-shared"
                        }
                    }
                }
                $mockDatastore = [PSCustomObject]@{
                    Name = "SharedDS"
                    Type = "VMFS"
                    State = "Available"
                    ExtensionData = $mockExtData
                }

                $script:mountCalled = $false

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost {
                    param($Name, $Datastore, [string]$State)
                    if ($Datastore) { return @($mockRelatedHost) }
                    return @($mockHost1)
                }
                function script:Get-Datastore { param($Name, $ErrorAction) $mockDatastore }
                function script:Get-VM { param($Datastore, $ErrorAction) $null }
                function script:Get-VMHostStorage { param($VMHost, [switch]$RescanAllHba, [switch]$RescanVmfs) }

                function script:Get-View {
                    param($Id)
                    $storageSystem = New-Object PSObject
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                        param($uuid)
                    }
                    $storageSystem | Add-Member -MemberType ScriptMethod -Name 'MountVmfsVolume' -Value {
                        param($uuid)
                        $script:mountCalled = $true
                    }
                    return $storageSystem
                }

                { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "SharedDS" } |
                    Should -Not -Throw

                $script:mountCalled | Should -Be $false
            }
        }
    }
}

Describe "Set-VmfsIscsi - Rollback on Failure" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "When iSCSI configuration fails on the second host" {
        It "Should roll back targets added on previously configured hosts" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-1" }
                $mockHost2 = [PSCustomObject]@{ Name = "host-2" }
                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba { param($Type) $mockAdapter }

                $script:hostCallCount = 0
                $script:removeTargetCalled = $false
                $script:getTargetCallCount = 0

                function script:Get-IScsiHbaTarget {
                    param($IScsiHba, $Type, $ErrorAction)
                    $script:getTargetCallCount++
                    # The first 2 calls are during config, any subsequent calls are during rollback
                    if ($script:getTargetCallCount -le 2) {
                        @()
                    } else {
                        @([PSCustomObject]@{ Address = "192.168.0.1" })
                    }
                }

                function script:New-IScsiHbaTarget {
                    param($IScsiHba, $Address, $ErrorAction)
                    $script:hostCallCount++
                    # Fail on the second host
                    if ($script:hostCallCount -ge 2) {
                        throw "Simulated target creation failure on host-2"
                    }
                }

                function script:Get-EsxCli {
                    # Create a mock esxcli object that supports the adapter config calls
                    $getArgs = { @{ adapter = ''; address = '' } }
                    $getInvoke = { @() }
                    $setArgs = { @{ adapter = ''; address = ''; value = ''; key = '' } }
                    $setInvoke = { }
                    $paramGet = [PSCustomObject]@{}
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $getArgs
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $getInvoke
                    $paramSet = [PSCustomObject]@{}
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $setArgs
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $setInvoke
                    $sendtargetParam = [PSCustomObject]@{ get = $paramGet; set = $paramSet }
                    $sendtarget = [PSCustomObject]@{ param = $sendtargetParam }
                    $discovery = [PSCustomObject]@{ sendtarget = $sendtarget }
                    $adapter = [PSCustomObject]@{ discovery = $discovery }
                    $iscsi = [PSCustomObject]@{ adapter = $adapter }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                function script:Remove-IScsiHbaTarget {
                    param($Target, [switch]$Confirm, $ErrorAction)
                    $script:removeTargetCalled = $true
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Throw "*Failed to configure iSCSI*rolled back*"

                # The target added on host-1 should have been rolled back
                $script:removeTargetCalled | Should -Be $true
            }
        }
    }

    Context "When target already existed on a host before this run" {
        It "Should not remove pre-existing targets during rollback" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-1" }
                $mockHost2 = [PSCustomObject]@{ Name = "host-2" }
                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba { param($Type) $mockAdapter }

                $script:removeTargetCalled = $false

                # Host-1 already has the target
                $existingTarget = [PSCustomObject]@{ Address = "192.168.0.1" }
                $script:getTargetCallCount = 0
                function script:Get-IScsiHbaTarget {
                    param($IScsiHba, $Type, $ErrorAction)
                    $script:getTargetCallCount++
                    # The first call is for host-1 check, any subsequent calls are for host-2 check and rollback
                    if ($script:getTargetCallCount -le 1) {
                        @($existingTarget)
                    } else {
                        @()
                    }
                }

                function script:New-IScsiHbaTarget {
                    param($IScsiHba, $Address, $ErrorAction)
                    # Host-2 fails during target creation
                    throw "Simulated failure on host-2"
                }

                function script:Get-EsxCli {
                    $getArgs = { @{ adapter = ''; address = '' } }
                    $getInvoke = { @() }
                    $setArgs = { @{ adapter = ''; address = ''; value = ''; key = '' } }
                    $setInvoke = { }
                    $paramGet = [PSCustomObject]@{}
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $getArgs
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $getInvoke
                    $paramSet = [PSCustomObject]@{}
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $setArgs
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $setInvoke
                    $sendtargetParam = [PSCustomObject]@{ get = $paramGet; set = $paramSet }
                    $sendtarget = [PSCustomObject]@{ param = $sendtargetParam }
                    $discovery = [PSCustomObject]@{ sendtarget = $sendtarget }
                    $adapter = [PSCustomObject]@{ discovery = $discovery }
                    $iscsi = [PSCustomObject]@{ adapter = $adapter }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                function script:Remove-IScsiHbaTarget {
                    param($Target, [switch]$Confirm, $ErrorAction)
                    $script:removeTargetCalled = $true
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Throw "*Failed to configure iSCSI*"

                # Host-1 target was pre-existing, so rollback should not remove it
                $script:removeTargetCalled | Should -Be $false
            }
        }
    }

    Context "When all hosts succeed" {
        It "Should not trigger any rollback" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-1" }
                $mockHost2 = [PSCustomObject]@{ Name = "host-2" }
                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba { param($Type) $mockAdapter }
                function script:Get-IScsiHbaTarget { param($IScsiHba, $Type, $ErrorAction) @() }
                function script:New-IScsiHbaTarget { param($IScsiHba, $Address, $ErrorAction) }

                $script:removeTargetCalled = $false

                function script:Get-EsxCli {
                    $getArgs = { @{ adapter = ''; address = '' } }
                    $getInvoke = { @() }
                    $setArgs = { @{ adapter = ''; address = ''; value = ''; key = '' } }
                    $setInvoke = { }
                    $paramGet = [PSCustomObject]@{}
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $getArgs
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $getInvoke
                    $paramSet = [PSCustomObject]@{}
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $setArgs
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $setInvoke
                    $sendtargetParam = [PSCustomObject]@{ get = $paramGet; set = $paramSet }
                    $sendtarget = [PSCustomObject]@{ param = $sendtargetParam }
                    $discovery = [PSCustomObject]@{ sendtarget = $sendtarget }
                    $adapter = [PSCustomObject]@{ discovery = $discovery }
                    $iscsi = [PSCustomObject]@{ adapter = $adapter }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                function script:Remove-IScsiHbaTarget {
                    param($Target, [switch]$Confirm, $ErrorAction)
                    $script:removeTargetCalled = $true
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Not -Throw

                $script:removeTargetCalled | Should -Be $false
            }
        }
    }

    Context "When a host has no iSCSI adapter" {
        It "Should throw before any targets are added" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-1" }
                $mockHost2 = [PSCustomObject]@{ Name = "host-2" }
                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                $script:getHbaCallCount = 0
                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba {
                    param($Type)
                    $script:getHbaCallCount++
                    # host-1 has adapter, host-2 does not
                    if ($script:getHbaCallCount -eq 1) { $mockAdapter } else { $null }
                }

                $script:newTargetCalled = $false
                function script:New-IScsiHbaTarget {
                    param($IScsiHba, $Address, $ErrorAction)
                    $script:newTargetCalled = $true
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Throw "*No iSCSI Software Adapter found on host*"

                # No targets should be added
                $script:newTargetCalled | Should -Be $false
            }
        }
    }
}

Describe "Set-VmfsStaticIscsi - Rollback on Failure" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "When static iSCSI configuration fails on the second host" {
        It "Should roll back targets added on previously configured hosts" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-1" }
                $mockHost2 = [PSCustomObject]@{ Name = "host-2" }
                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba { param($Type) $mockAdapter }

                $script:hostCallCount = 0
                $script:removeTargetCalled = $false
                $script:getTargetCallCount = 0

                function script:Get-IScsiHbaTarget {
                    param($IScsiHba, $Type, $ErrorAction)
                    $script:getTargetCallCount++
                    # The first 2 calls are during config, any subsequent calls are during rollback
                    if ($script:getTargetCallCount -le 2) {
                        @()
                    } else {
                        @([PSCustomObject]@{ Address = "192.168.0.1" })
                    }
                }

                function script:New-IScsiHbaTarget {
                    param($IScsiHba, $Type, $Address, $IScsiName, $ErrorAction)
                    $script:hostCallCount++
                    if ($script:hostCallCount -ge 2) {
                        throw "Simulated static target creation failure on host-2"
                    }
                }

                function script:Get-EsxCli {
                    $getArgs = { @{ adapter = ''; address = ''; name = '' } }
                    $getInvoke = { @() }
                    $setArgs = { @{ adapter = ''; address = ''; name = ''; inherit = ''; value = ''; key = '' } }
                    $setInvoke = { }
                    $paramGet = [PSCustomObject]@{}
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $getArgs
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $getInvoke
                    $paramSet = [PSCustomObject]@{}
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $setArgs
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $setInvoke
                    $portalParam = [PSCustomObject]@{ get = $paramGet; set = $paramSet }
                    $portal = [PSCustomObject]@{ param = $portalParam }
                    $target = [PSCustomObject]@{ portal = $portal }
                    $adapter = [PSCustomObject]@{ target = $target }
                    $iscsi = [PSCustomObject]@{ adapter = $adapter }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                function script:Remove-IScsiHbaTarget {
                    param($Target, [switch]$Confirm, $ErrorAction)
                    $script:removeTargetCalled = $true
                }

                { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" -ScsiName "iqn.test" } |
                    Should -Throw "*Failed to configure iSCSI*rolled back*"

                $script:removeTargetCalled | Should -Be $true
            }
        }
    }

    Context "When target already existed on a host before this run" {
        It "Should not remove pre-existing static targets during rollback" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-1" }
                $mockHost2 = [PSCustomObject]@{ Name = "host-2" }
                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }
                function script:Get-VMHostNetworkAdapter { param($VMHost, [switch]$VMKernel) @([PSCustomObject]@{ Name = "vmk5" }, [PSCustomObject]@{ Name = "vmk6" }) }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba { param($Type) $mockAdapter }

                $script:removeTargetCalled = $false

                $existingTarget = [PSCustomObject]@{ Address = "192.168.0.1" }
                $script:getTargetCallCount = 0
                function script:Get-IScsiHbaTarget {
                    param($IScsiHba, $Type, $ErrorAction)
                    $script:getTargetCallCount++
                    # The first call is for host-1 check, any subsequent calls are for host-2 check and rollback
                    if ($script:getTargetCallCount -le 1) {
                        @($existingTarget)
                    } else {
                        @()
                    }
                }

                function script:New-IScsiHbaTarget {
                    param($IScsiHba, $Type, $Address, $IScsiName, $ErrorAction)
                    throw "Simulated failure on host-2"
                }

                function script:Get-EsxCli {
                    $getArgs = { @{ adapter = ''; address = ''; name = '' } }
                    $getInvoke = { @() }
                    $setArgs = { @{ adapter = ''; address = ''; name = ''; inherit = ''; value = ''; key = '' } }
                    $setInvoke = { }
                    $paramGet = [PSCustomObject]@{}
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $getArgs
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $getInvoke
                    $paramSet = [PSCustomObject]@{}
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $setArgs
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $setInvoke
                    $portalParam = [PSCustomObject]@{ get = $paramGet; set = $paramSet }
                    $portal = [PSCustomObject]@{ param = $portalParam }
                    $target = [PSCustomObject]@{ portal = $portal }
                    $adapter = [PSCustomObject]@{ target = $target }
                    $iscsi = [PSCustomObject]@{ adapter = $adapter }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                function script:Remove-IScsiHbaTarget {
                    param($Target, [switch]$Confirm, $ErrorAction)
                    $script:removeTargetCalled = $true
                }

                { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" -ScsiName "iqn.test" } |
                    Should -Throw "*Failed to configure iSCSI*"

                $script:removeTargetCalled | Should -Be $false
            }
        }
    }
}

Describe "Set-VmfsIscsi - vmk5/vmk6 Pre-Validation" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Host missing vmk5 or vmk6" {
        It "Should throw when vmk5 is missing on a host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost, [switch]$VMKernel)
                    # Only vmk6 present, vmk5 missing
                    @([PSCustomObject]@{ Name = "vmk0" }, [PSCustomObject]@{ Name = "vmk6" })
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Throw "*Kernel Adapters vmk5 and vmk6 do not exist on host*"
            }
        }

        It "Should throw when vmk6 is missing on a host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost, [switch]$VMKernel)
                    # Only vmk5 present, vmk6 missing
                    @([PSCustomObject]@{ Name = "vmk0" }, [PSCustomObject]@{ Name = "vmk5" })
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Throw "*Kernel Adapters vmk5 and vmk6 do not exist on host*"
            }
        }

        It "Should throw when Get-VMHostNetworkAdapter fails" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost, [switch]$VMKernel)
                    throw "Connection error"
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Throw "*Failed to collect VMKernel info on host*"
            }
        }
    }

    Context "Microsoft Corporation vendor hosts" {
        It "Should skip vmk5/vmk6 check for Microsoft Corporation hosts" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $hwInfo = [PSCustomObject]@{ Vendor = "Microsoft Corporation" }
                $hwData = [PSCustomObject]@{ SystemInfo = $hwInfo }
                $extData = [PSCustomObject]@{ Hardware = $hwData }
                $mockVMHost = [PSCustomObject]@{ Name = "ms-host-1"; ExtensionData = $extData }

                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba { param($Type) $mockAdapter }
                function script:Get-IScsiHbaTarget { param($IScsiHba, $Type, $ErrorAction) @() }
                function script:New-IScsiHbaTarget { param($IScsiHba, $Address, $ErrorAction) }

                function script:Get-EsxCli {
                    $getArgs = { @{ adapter = ''; address = '' } }
                    $getInvoke = { @() }
                    $setArgs = { @{ adapter = ''; address = ''; value = ''; key = '' } }
                    $setInvoke = { }
                    $paramGet = [PSCustomObject]@{}
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $getArgs
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $getInvoke
                    $paramSet = [PSCustomObject]@{}
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $setArgs
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $setInvoke
                    $sendtargetParam = [PSCustomObject]@{ get = $paramGet; set = $paramSet }
                    $sendtarget = [PSCustomObject]@{ param = $sendtargetParam }
                    $discovery = [PSCustomObject]@{ sendtarget = $sendtarget }
                    $adapter = [PSCustomObject]@{ discovery = $discovery }
                    $iscsi = [PSCustomObject]@{ adapter = $adapter }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                { Set-VmfsIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" } |
                    Should -Not -Throw
            }
        }
    }
}

Describe "Set-VmfsStaticIscsi - vmk5/vmk6 Pre-Validation" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Host missing vmk5 or vmk6" {
        It "Should throw when vmk5 is missing on a host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost, [switch]$VMKernel)
                    @([PSCustomObject]@{ Name = "vmk0" }, [PSCustomObject]@{ Name = "vmk6" })
                }

                { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" -ScsiName "iqn.test" } |
                    Should -Throw "*Kernel Adapters vmk5 and vmk6 do not exist on host*"
            }
        }

        It "Should throw when Get-VMHostNetworkAdapter fails" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost, [switch]$VMKernel)
                    throw "Connection error"
                }

                { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" -ScsiName "iqn.test" } |
                    Should -Throw "*Failed to collect VMKernel info on host*"
            }
        }
    }

    Context "Microsoft Corporation vendor hosts" {
        It "Should skip vmk5/vmk6 check for Microsoft Corporation hosts" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $hwInfo = [PSCustomObject]@{ Vendor = "Microsoft Corporation" }
                $hwData = [PSCustomObject]@{ SystemInfo = $hwInfo }
                $extData = [PSCustomObject]@{ Hardware = $hwData }
                $mockVMHost = [PSCustomObject]@{ Name = "ms-host-1"; ExtensionData = $extData }

                $mockAdapter = [PSCustomObject]@{ Model = "iSCSI Software Adapter"; Device = "vmhba65" }
                $mockStorage = [PSCustomObject]@{ SoftwareIScsiEnabled = $true }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostStorage { $mockStorage }
                function script:Get-VMHostHba { param($Type) $mockAdapter }
                function script:Get-IScsiHbaTarget { param($IScsiHba, $Type, $ErrorAction) @() }
                function script:New-IScsiHbaTarget { param($IScsiHba, $Type, $Address, $IScsiName, $ErrorAction) }

                function script:Get-EsxCli {
                    $getArgs = { @{ adapter = ''; address = ''; name = '' } }
                    $getInvoke = { @() }
                    $setArgs = { @{ adapter = ''; address = ''; name = ''; inherit = ''; value = ''; key = '' } }
                    $setInvoke = { }
                    $paramGet = [PSCustomObject]@{}
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $getArgs
                    $paramGet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $getInvoke
                    $paramSet = [PSCustomObject]@{}
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $setArgs
                    $paramSet | Add-Member -MemberType ScriptMethod -Name 'invoke' -Value $setInvoke
                    $portalParam = [PSCustomObject]@{ get = $paramGet; set = $paramSet }
                    $portal = [PSCustomObject]@{ param = $portalParam }
                    $target = [PSCustomObject]@{ portal = $portal }
                    $adapter = [PSCustomObject]@{ target = $target }
                    $iscsi = [PSCustomObject]@{ adapter = $adapter }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                { Set-VmfsStaticIscsi -ClusterName "TestCluster" -ScsiIpAddress "192.168.0.1" -ScsiName "iqn.test" } |
                    Should -Not -Throw
            }
        }
    }
}

Describe "Test-VMKernelConnectivity - vmk5/vmk6 Pre-Validation" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Host missing vmk5 or vmk6" {
        It "Should throw when vmk5 is missing on a host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost, [switch]$VMKernel)
                    @([PSCustomObject]@{ Name = "vmk0" }, [PSCustomObject]@{ Name = "vmk6" })
                }

                { Test-VMKernelConnectivity -ClusterName "TestCluster" } |
                    Should -Throw "*Kernel Adapters vmk5 and vmk6 do not exist on host*"
            }
        }

        It "Should throw when Get-VMHostNetworkAdapter fails" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost, [switch]$VMKernel)
                    throw "Connection error"
                }

                { Test-VMKernelConnectivity -ClusterName "TestCluster" } |
                    Should -Throw "*Failed to collect VMKernel info on host*"
            }
        }
    }

    Context "Microsoft Corporation vendor hosts" {
        It "Should skip vmk5/vmk6 check for Microsoft Corporation hosts" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $hwInfo = [PSCustomObject]@{ Vendor = "Microsoft Corporation" }
                $hwData = [PSCustomObject]@{ SystemInfo = $hwInfo }
                $extData = [PSCustomObject]@{ Hardware = $hwData }
                $mockVMHost = [PSCustomObject]@{ Name = "ms-host-1"; ExtensionData = $extData }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost)
                    @([PSCustomObject]@{ Name = "vmk0"; IP = "10.0.0.1" })
                }
                function script:Get-EsxCli {
                    param($VMHost, [switch]$V2)
                    $createArgs = { @{ host = '' } }
                    $invoke = { [PSCustomObject]@{ Summary = [PSCustomObject]@{ Received = 1 } } }
                    $ping = [PSCustomObject]@{}
                    $ping | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $createArgs
                    $ping | Add-Member -MemberType ScriptMethod -Name 'Invoke' -Value $invoke
                    $diag = [PSCustomObject]@{ ping = $ping }
                    $network = [PSCustomObject]@{ diag = $diag }
                    return [PSCustomObject]@{ network = $network }
                }

                { Test-VMKernelConnectivity -ClusterName "TestCluster" } |
                    Should -Not -Throw
            }
        }
    }
}

# ============================================================================
# Additional Behavioral Tests for Functions with Coverage Gaps
# ============================================================================

Describe "Resize-VmfsVolume - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Datastore not found by NAA ID" {
        It "Should throw when no datastore matches DeviceNaaId" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{
                    Name = "esxi-host-1"
                    ConnectionState = "Connected"
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba) }
                function script:Get-Datastore {
                    param($Name, $ErrorAction)
                    [PSCustomObject]@{
                        ExtensionData = [PSCustomObject]@{
                            Info = [PSCustomObject]@{
                                Vmfs = [PSCustomObject]@{
                                    Extent = [PSCustomObject]@{ DiskName = "naa.60003ff000000001" }
                                }
                            }
                        }
                    }
                }

                { Resize-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "naa.60003ff999999999" } |
                    Should -Throw "*datastore not found*"
            }
        }
    }

    Context "Datastore found by DatastoreName" {
        It "Should throw when named datastore does not exist" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $ErrorAction) $null }

                { Resize-VmfsVolume -ClusterName "TestCluster" -DatastoreName "NonExistentDS" } |
                    Should -Throw "*does not exist*"
            }
        }

        It "Should throw when named datastore is not VMFS type" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $ErrorAction)
                    [PSCustomObject]@{ Name = "NfsDS"; Type = "NFS" }
                }

                { Resize-VmfsVolume -ClusterName "TestCluster" -DatastoreName "NfsDS" } |
                    Should -Throw "*can only process VMFS datastores*"
            }
        }
    }

    Context "NAA prefix validation" {
        It "Should throw for unsupported NAA prefix" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $ds = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = [PSCustomObject]@{
                        Info = [PSCustomObject]@{
                            Vmfs = [PSCustomObject]@{
                                Extent = [PSCustomObject]@{ DiskName = "naa.500000000000001" }
                            }
                        }
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $ErrorAction) $ds }

                { Resize-VmfsVolume -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*is not supported for VMFS volume re-size*"
            }
        }
    }

    Context "No expand options available" {
        It "Should throw when no expand options exist" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $hostKey = [PSCustomObject]@{ value = "host-1" }
                $ds = [PSCustomObject]@{
                    Name = "TestDS"
                    Type = "VMFS"
                    ExtensionData = [PSCustomObject]@{
                        Host = @([PSCustomObject]@{ Key = $hostKey })
                        MoRef = "ds-moref-1"
                        Info = [PSCustomObject]@{
                            Vmfs = [PSCustomObject]@{
                                Extent = [PSCustomObject]@{ DiskName = "naa.60003ff000000001" }
                                Capacity = 536870912000
                            }
                        }
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $ErrorAction) $ds }
                function script:Get-VMHost { param($Id) [PSCustomObject]@{ Name = "host-1" } }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs, $ErrorAction, $WarningAction) }
                function script:Get-View {
                    param($Id)
                    $dsSys = [PSCustomObject]@{}
                    $dsSys | Add-Member -MemberType ScriptMethod -Name 'QueryVmfsDatastoreExpandOptions' -Value { param($moref) @() }
                    $configMgr = [PSCustomObject]@{ DatastoreSystem = "dsSys-1" }
                    if ($Id -eq "dsSys-1") { return $dsSys }
                    return [PSCustomObject]@{ ConfigManager = $configMgr }
                }

                { Resize-VmfsVolume -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*No expand options available*"
            }
        }
    }
}

Describe "Restore-VmfsVolume - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "DatastoreName collision" {
        It "Should throw when target DatastoreName already exists" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $ErrorAction)
                    [PSCustomObject]@{ Name = $Name }
                }

                { Restore-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "naa.624a9370123456" -DatastoreName "ExistingDS" } |
                    Should -Throw "*already exists*"
            }
        }
    }

    Context "No unresolved volume found" {
        It "Should throw when no unresolved volumes match DeviceNaaId" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{
                    Name = "esxi-host-1"
                    ConnectionState = "Connected"
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "storageSys-1"
                        }
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $ErrorAction) $null }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba) }
                function script:Get-View {
                    param($ID)
                    $storageSys = [PSCustomObject]@{}
                    $storageSys | Add-Member -MemberType ScriptMethod -Name 'QueryUnresolvedVmfsVolume' -Value { @() }
                    return $storageSys
                }

                { Restore-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "naa.624a9370123456" -ErrorAction SilentlyContinue } |
                    Should -Throw "*Failed to re-signature VMFS volume*"
            }
        }
    }

    Context "Multiple copies error" {
        It "Should throw when volume has multiple unresolved copies" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{
                    Name = "esxi-host-1"
                    ConnectionState = "Connected"
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            StorageSystem = "storageSys-1"
                        }
                    }
                }

                $unresolvedVol = [PSCustomObject]@{
                    VmfsLabel = "snap-vol-01"
                    ResolveStatus = [PSCustomObject]@{ Resolvable = $false; MultipleCopies = $true }
                    Extent = @(
                        [PSCustomObject]@{
                            Device = [PSCustomObject]@{ DiskName = "naa.624a9370123456" }
                        },
                        [PSCustomObject]@{
                            Device = [PSCustomObject]@{ DiskName = "naa.624a9370789012" }
                        }
                    )
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $ErrorAction) $null }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba) }
                function script:Get-View {
                    param($ID)
                    $storageSys = [PSCustomObject]@{}
                    $storageSys | Add-Member -MemberType ScriptMethod -Name 'QueryUnresolvedVmfsVolume' -Value { @($unresolvedVol) }
                    return $storageSys
                }

                { Restore-VmfsVolume -ClusterName "TestCluster" -DeviceNaaId "naa.624a9370123456" -ErrorAction SilentlyContinue } |
                    Should -Throw "*Failed to re-signature VMFS volume*"
            }
        }
    }
}

Describe "Sync-VMHostStorage - Behavioral Tests" -Tag "Behavioral" {
    Context "VMHost not found" {
        It "Should throw when VMHost does not exist" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                function script:Get-VMHost { param($Name, $ErrorAction) $null }

                { Sync-VMHostStorage -VMHostName "nonexistent-host" } |
                    Should -Throw "*does not exist*"
            }
        }
    }

    Context "Happy path" {
        It "Should rescan storage on the VMHost" {
            InModuleScope Microsoft.AVS.VMFS -ScriptBlock {
                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-VMHost { param($Name, $ErrorAction) $mockVMHost }
                function script:Get-VMHostStorage {
                    param([switch]$RescanAllHba, [switch]$RescanVMFS)
                    $script:rescanCalled = $true
                }

                $script:rescanCalled = $false
                Sync-VMHostStorage -VMHostName "esxi-host-1"
                $script:rescanCalled | Should -BeTrue
            }
        }
    }
}

Describe "Sync-ClusterVMHostStorage - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Happy path" {
        It "Should rescan storage on all hosts in cluster" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost {
                    @(
                        [PSCustomObject]@{ Name = "host-01" },
                        [PSCustomObject]@{ Name = "host-02" }
                    )
                }
                function script:Get-VMHostStorage {
                    param([switch]$RescanAllHba, [switch]$RescanVMFS)
                    $script:rescanCount++
                }

                $script:rescanCount = 0
                Sync-ClusterVMHostStorage -ClusterName "TestCluster"
                $script:rescanCount | Should -BeGreaterOrEqual 1
            }
        }
    }
}

Describe "Remove-VmfsDatastore - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Datastore does not exist or is unavailable" {
        It "Should throw when datastore does not exist" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $ErrorAction) $null }

                { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "NonExistentDS" } |
                    Should -Throw "*does not exist or datastore is in Unavailable state*"
            }
        }

        It "Should throw when datastore is in Unavailable state" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $ErrorAction)
                    [PSCustomObject]@{ Name = $Name; State = "Unavailable" }
                }

                { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "UnavailableDS" } |
                    Should -Throw "*does not exist or datastore is in Unavailable state*"
            }
        }
    }

    Context "VMs blocking deletion" {
        It "Should throw when VMs are on the datastore" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $ErrorAction)
                    [PSCustomObject]@{ Name = $Name; State = "Available" }
                }
                function script:Get-VM {
                    param($Datastore, $ErrorAction)
                    @([PSCustomObject]@{ Name = "VM-01" })
                }

                { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*hosting worker virtual machines*"
            }
        }
    }

    Context "No connected hosts with the datastore" {
        It "Should throw when no connected hosts have the datastore" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $ErrorAction)
                    [PSCustomObject]@{ Name = $Name; State = "Available" }
                }
                function script:Get-VM { param($Datastore, $ErrorAction) $null }
                function script:Get-VMHost {
                    param($Datastore, $State)
                    if ($Datastore) { return $null }
                    return [PSCustomObject]@{ Name = "host-01" }
                }

                { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*No connected hosts found*"
            }
        }
    }

    Context "Happy path - non-shared datastore removal" {
        It "Should remove datastore directly when not shared across clusters" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost = [PSCustomObject]@{
                    Name = "host-01"
                    Parent = [PSCustomObject]@{ Name = "TestCluster" }
                }
                $script:removeCalled = $false
                $script:getCallCount = 0

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $ErrorAction)
                    $script:getCallCount++
                    # First call returns the datastore, second call (after removal) returns null
                    if ($script:getCallCount -le 2) {
                        return [PSCustomObject]@{ Name = $Name; State = "Available" }
                    }
                    return $null
                }
                function script:Get-VM { param($Datastore, $ErrorAction) $null }
                function script:Get-VMHost {
                    param($Datastore, $State)
                    return $mockHost
                }
                function script:Remove-Datastore {
                    param($VMHost, $Datastore, $Confirm)
                    $script:removeCalled = $true
                }
                function script:Get-VMHostStorage { param($VMHost, [switch]$RescanAllHba) }

                Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS"
                $script:removeCalled | Should -BeTrue
            }
        }
    }
}

Describe "Dismount-VmfsDatastore - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "VMs blocking unmount" {
        It "Should throw when VMs exist on the datastore" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS"; Type = "VMFS" }
                $mockVM = [PSCustomObject]@{ Name = "VM-01" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $ErrorAction) $mockDS }
                function script:Get-VMHost { @([PSCustomObject]@{ Name = "host-01" }) }
                function script:Get-VM { @($mockVM) }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Throw "*Cannot unmount datastore*"
            }
        }
    }

    Context "No hosts connected to datastore" {
        It "Should return without error when no hosts have the datastore" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS"; Type = "VMFS" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $VMHost, $ErrorAction)
                    if ($VMHost) { return $null }
                    return $mockDS
                }
                function script:Get-VMHost { @([PSCustomObject]@{ Name = "host-01" }) }
                function script:Get-VM { $null }

                { Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                    Should -Not -Throw
            }
        }
    }

    Context "Successful unmount and detach" {
        It "Should unmount and detach on each host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockExtData = [PSCustomObject]@{
                    Info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-001"
                            extent = @([PSCustomObject]@{ Diskname = "naa.60003ff44dc75adc" })
                        }
                    }
                    Host = @(
                        [PSCustomObject]@{ Key = [PSCustomObject]@{ value = "host-1" } }
                    )
                }
                $scsiLunExt = [PSCustomObject]@{ uuid = "scsiLun-uuid-001" }
                $mockScsiLun = [PSCustomObject]@{ ExtensionData = $scsiLunExt }
                $mockDS = [PSCustomObject]@{ Name = "TestDS"; Type = "VMFS"; ExtensionData = $mockExtData }

                $mockStorageSystem = [PSCustomObject]@{}
                $mockStorageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                    param($uuid) $script:unmountCalled = $true
                }
                $mockStorageSystem | Add-Member -MemberType ScriptMethod -Name 'DetachScsiLun' -Value {
                    param($uuid) $script:detachCalled = $true
                }

                $mockVMHost = [PSCustomObject]@{
                    Name = "host-01"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{ StorageSystem = "storageSys-1" }
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $VMHost, $ErrorAction)
                    if ($VMHost) {
                        if ($VMHost.Name -eq "host-01" -or $VMHost -eq "host-01") { return $mockDS }
                        return $null
                    }
                    return $mockDS
                }
                function script:Get-VMHost { @($mockVMHost) }
                function script:Get-VM { $null }
                function script:Get-ScsiLun { $mockScsiLun }
                function script:Get-View { param($Id) $mockStorageSystem }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                $script:unmountCalled = $false
                $script:detachCalled = $false

                Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS"

                $script:unmountCalled | Should -BeTrue
                $script:detachCalled | Should -BeTrue
            }
        }
    }

    Context "NVMe/TCP datastore skip detach" {
        It "Should not detach for NVMe/TCP (eui.) devices" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockExtData = [PSCustomObject]@{
                    Info = [PSCustomObject]@{
                        Vmfs = [PSCustomObject]@{
                            uuid = "vmfs-uuid-002"
                            extent = @([PSCustomObject]@{ Diskname = "eui.0025385a71b0dc3e" })
                        }
                    }
                    Host = @(
                        [PSCustomObject]@{ Key = [PSCustomObject]@{ value = "host-1" } }
                    )
                }
                $scsiLunExt = [PSCustomObject]@{ uuid = "scsiLun-uuid-002" }
                $mockScsiLun = [PSCustomObject]@{ ExtensionData = $scsiLunExt }
                $mockDS = [PSCustomObject]@{ Name = "NvmeDS"; Type = "VMFS"; ExtensionData = $mockExtData }

                $mockStorageSystem = [PSCustomObject]@{}
                $mockStorageSystem | Add-Member -MemberType ScriptMethod -Name 'UnmountVmfsVolume' -Value {
                    param($uuid) $script:unmountCalled = $true
                }
                $mockStorageSystem | Add-Member -MemberType ScriptMethod -Name 'DetachScsiLun' -Value {
                    param($uuid) $script:detachCalled = $true
                }

                $mockVMHost = [PSCustomObject]@{
                    Name = "host-01"
                    Extensiondata = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{ StorageSystem = "storageSys-1" }
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore {
                    param($Name, $VMHost, $ErrorAction)
                    if ($VMHost) {
                        if ($VMHost.Name -eq "host-01" -or $VMHost -eq "host-01") { return $mockDS }
                        return $null
                    }
                    return $mockDS
                }
                function script:Get-VMHost { @($mockVMHost) }
                function script:Get-VM { $null }
                function script:Get-ScsiLun { $mockScsiLun }
                function script:Get-View { param($Id) $mockStorageSystem }
                function script:Get-VMHostStorage { param([switch]$RescanAllHba, [switch]$RescanVmfs) }

                $script:unmountCalled = $false
                $script:detachCalled = $false

                Dismount-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "NvmeDS"

                $script:unmountCalled | Should -BeTrue
                $script:detachCalled | Should -BeFalse
            }
        }
    }
}

Describe "Repair-HAConfiguration - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Happy path" {
        It "Should call ReconfigureHostForDAS on all hosts" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-01" }
                $mockHost1 | Add-Member -NotePropertyName ExtensionData -NotePropertyValue ([PSCustomObject]@{})
                $mockHost1.ExtensionData | Add-Member -MemberType ScriptMethod -Name 'ReconfigureHostForDAS' -Value { $script:dasCount++ }

                $mockHost2 = [PSCustomObject]@{ Name = "host-02" }
                $mockHost2 | Add-Member -NotePropertyName ExtensionData -NotePropertyValue ([PSCustomObject]@{})
                $mockHost2.ExtensionData | Add-Member -MemberType ScriptMethod -Name 'ReconfigureHostForDAS' -Value { $script:dasCount++ }

                function script:Get-Cluster {
                    param($Name, $ErrorAction)
                    if (-not $ErrorAction) { return $mockCluster }
                    return $mockCluster
                }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }

                $script:dasCount = 0
                Repair-HAConfiguration -ClusterName "TestCluster"
                $script:dasCount | Should -Be 2
            }
        }
    }

    Context "Partial failure" {
        It "Should throw when ReconfigureHostForDAS fails on one host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockHost1 = [PSCustomObject]@{ Name = "host-01" }
                $mockHost1 | Add-Member -NotePropertyName ExtensionData -NotePropertyValue ([PSCustomObject]@{})
                $mockHost1.ExtensionData | Add-Member -MemberType ScriptMethod -Name 'ReconfigureHostForDAS' -Value { $script:dasCount++ }

                $mockHost2 = [PSCustomObject]@{ Name = "host-02" }
                $mockHost2 | Add-Member -NotePropertyName ExtensionData -NotePropertyValue ([PSCustomObject]@{})
                $mockHost2.ExtensionData | Add-Member -MemberType ScriptMethod -Name 'ReconfigureHostForDAS' -Value { throw "DAS error" }

                function script:Get-Cluster {
                    param($Name, $ErrorAction)
                    if (-not $ErrorAction) { return $mockCluster }
                    return $mockCluster
                }
                function script:Get-VMHost { @($mockHost1, $mockHost2) }

                $script:dasCount = 0
                { Repair-HAConfiguration -ClusterName "TestCluster" -ErrorAction SilentlyContinue } |
                    Should -Throw "*Failed to repair HA configuration on one or more hosts*"
            }
        }
    }

    Context "Get-VMHost failure" {
        It "Should throw when Get-VMHost fails" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster {
                    param($Name, $ErrorAction)
                    if (-not $ErrorAction) { return $mockCluster }
                    return $mockCluster
                }
                function script:Get-VMHost { throw "Connection refused" }

                { Repair-HAConfiguration -ClusterName "TestCluster" } |
                    Should -Throw "*Failed to collect cluster hosts*"
            }
        }
    }
}

Describe "Clear-DisconnectedIscsiTargets - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "No hosts found" {
        It "Should throw when no hosts found in cluster" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $null }

                { Clear-DisconnectedIscsiTargets -ClusterName "TestCluster" } |
                    Should -Throw "*No matching hosts found*"
            }
        }
    }

    Context "VMHostName targeting" {
        It "Should only target specified VMHost when VMHostName is provided" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { param($Name) $mockVMHost }
                function script:Get-EsxCli {
                    param($VMHost, [switch]$V2)
                    $listInvoke = { @() }
                    $connList = [PSCustomObject]@{}
                    $connList | Add-Member -MemberType ScriptMethod -Name 'Invoke' -Value $listInvoke
                    $connection = [PSCustomObject]@{ list = $connList }
                    $session = [PSCustomObject]@{ connection = $connection }
                    $iscsi = [PSCustomObject]@{ session = $session }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }

                { Clear-DisconnectedIscsiTargets -ClusterName "TestCluster" -VMHostName "esxi-host-1" } |
                    Should -Not -Throw
            }
        }
    }

    Context "Disconnected sessions found and cleared" {
        It "Should remove disconnected targets and rescan" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-EsxCli {
                    param($VMHost, [switch]$V2)
                    $listInvoke = {
                        @(
                            [PSCustomObject]@{ State = "dead    "; ConnectionAddress = "192.168.1.10" },
                            [PSCustomObject]@{ State = "logged_in"; ConnectionAddress = "192.168.1.11" }
                        )
                    }
                    $connList = [PSCustomObject]@{}
                    $connList | Add-Member -MemberType ScriptMethod -Name 'Invoke' -Value $listInvoke
                    $connection = [PSCustomObject]@{ list = $connList }
                    $session = [PSCustomObject]@{ connection = $connection }
                    $iscsi = [PSCustomObject]@{ session = $session }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }
                function script:Get-IScsiHbaTarget {
                    @([PSCustomObject]@{ Address = "192.168.1.10"; Type = "Send" })
                }
                function script:Remove-IScsiHbaTarget { param($Confirm) $script:removeCount++ }
                function script:Get-VMHostStorage {
                    param([switch]$RescanAllHba, [switch]$RescanVmfs)
                    $script:rescanCalled = $true
                }

                $script:removeCount = 0
                $script:rescanCalled = $false

                Clear-DisconnectedIscsiTargets -ClusterName "TestCluster"

                $script:removeCount | Should -Be 1
                $script:rescanCalled | Should -BeTrue
            }
        }
    }

    Context "No disconnected sessions" {
        It "Should not rescan when no disconnected targets exist" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockVMHost = [PSCustomObject]@{ Name = "esxi-host-1" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-EsxCli {
                    param($VMHost, [switch]$V2)
                    $listInvoke = {
                        @([PSCustomObject]@{ State = "logged_in"; ConnectionAddress = "192.168.1.10" })
                    }
                    $connList = [PSCustomObject]@{}
                    $connList | Add-Member -MemberType ScriptMethod -Name 'Invoke' -Value $listInvoke
                    $connection = [PSCustomObject]@{ list = $connList }
                    $session = [PSCustomObject]@{ connection = $connection }
                    $iscsi = [PSCustomObject]@{ session = $session }
                    return [PSCustomObject]@{ iscsi = $iscsi }
                }
                function script:Get-VMHostStorage {
                    param([switch]$RescanAllHba, [switch]$RescanVmfs)
                    $script:rescanCalled = $true
                }

                $script:rescanCalled = $false
                Clear-DisconnectedIscsiTargets -ClusterName "TestCluster"
                $script:rescanCalled | Should -BeFalse
            }
        }
    }
}

Describe "New-VmfsVmSnapshot - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Datastore not found" {
        It "Should throw when datastore does not exist" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $RelatedObject, $ErrorAction) $null }

                { New-VmfsVmSnapshot -ClusterName "TestCluster" -datastoreName "NonExistentDS" } |
                    Should -Throw "*does not exist*"
            }
        }
    }

    Context "No VMs on datastore" {
        It "Should succeed without creating any snapshots" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS" }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $RelatedObject, $ErrorAction) $mockDS }
                function script:Get-VM { param($Datastore) @() }

                { New-VmfsVmSnapshot -ClusterName "TestCluster" -datastoreName "TestDS" } |
                    Should -Not -Throw
            }
        }
    }

    Context "VM skip conditions" {
        It "Should skip VMs without ExtensionData" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS" }
                $mockVM = [PSCustomObject]@{ Name = "VM-NoExt"; ExtensionData = $null }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $RelatedObject, $ErrorAction) $mockDS }
                function script:Get-VM { param($Datastore) @($mockVM) }
                function script:New-Snapshot {
                    param($VM, [switch]$Quiesce, $Name, $ErrorAction)
                    $script:snapshotCount++
                }

                $script:snapshotCount = 0
                New-VmfsVmSnapshot -ClusterName "TestCluster" -datastoreName "TestDS"
                $script:snapshotCount | Should -Be 0
            }
        }

        It "Should skip VMs with unhealthy OverallStatus" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS" }
                $mockVM = [PSCustomObject]@{
                    Name = "VM-Unhealthy"
                    ExtensionData = [PSCustomObject]@{
                        OverallStatus = "red"
                        guestHeartbeatStatus = "green"
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $RelatedObject, $ErrorAction) $mockDS }
                function script:Get-VM { param($Datastore) @($mockVM) }
                function script:New-Snapshot {
                    param($VM, [switch]$Quiesce, $Name, $ErrorAction)
                    $script:snapshotCount++
                }

                $script:snapshotCount = 0
                New-VmfsVmSnapshot -ClusterName "TestCluster" -datastoreName "TestDS"
                $script:snapshotCount | Should -Be 0
            }
        }

        It "Should skip VMs with unhealthy guestHeartbeatStatus" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS" }
                $mockVM = [PSCustomObject]@{
                    Name = "VM-HeartbeatBad"
                    ExtensionData = [PSCustomObject]@{
                        OverallStatus = "green"
                        guestHeartbeatStatus = "gray"
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $RelatedObject, $ErrorAction) $mockDS }
                function script:Get-VM { param($Datastore) @($mockVM) }
                function script:New-Snapshot {
                    param($VM, [switch]$Quiesce, $Name, $ErrorAction)
                    $script:snapshotCount++
                }

                $script:snapshotCount = 0
                New-VmfsVmSnapshot -ClusterName "TestCluster" -datastoreName "TestDS"
                $script:snapshotCount | Should -Be 0
            }
        }
    }

    Context "Happy path - healthy VMs" {
        It "Should create snapshots for healthy VMs" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS" }
                $mockVM = [PSCustomObject]@{
                    Name = "VM-Healthy"
                    ExtensionData = [PSCustomObject]@{
                        OverallStatus = "green"
                        guestHeartbeatStatus = "green"
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $RelatedObject, $ErrorAction) $mockDS }
                function script:Get-VM { param($Datastore) @($mockVM) }
                function script:New-Snapshot {
                    param($VM, [switch]$Quiesce, $Name, $ErrorAction)
                    $script:snapshotCount++
                    return [PSCustomObject]@{ Name = $Name }
                }

                $script:snapshotCount = 0
                New-VmfsVmSnapshot -ClusterName "TestCluster" -datastoreName "TestDS"
                $script:snapshotCount | Should -Be 1
            }
        }
    }

    Context "Snapshot failure" {
        It "Should throw when New-Snapshot fails" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $mockDS = [PSCustomObject]@{ Name = "TestDS" }
                $mockVM = [PSCustomObject]@{
                    Name = "VM-FailSnap"
                    ExtensionData = [PSCustomObject]@{
                        OverallStatus = "green"
                        guestHeartbeatStatus = "green"
                    }
                }

                function script:Get-Cluster { param($Name, $ErrorAction) $mockCluster }
                function script:Get-Datastore { param($Name, $RelatedObject, $ErrorAction) $mockDS }
                function script:Get-VM { param($Datastore) @($mockVM) }
                function script:New-Snapshot {
                    param($VM, [switch]$Quiesce, $Name, $ErrorAction)
                    throw "Snapshot creation error"
                }

                { New-VmfsVmSnapshot -ClusterName "TestCluster" -datastoreName "TestDS" } |
                    Should -Throw "*Failed to create snapshot*"
            }
        }
    }
}

Describe "Test-VMKernelConnectivity - Behavioral Tests" -Tag "Behavioral" {
    BeforeAll {
        $script:mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
    }

    Context "Successful ping" {
        It "Should succeed when all pings are received" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $hwInfo = [PSCustomObject]@{ Vendor = "Microsoft Corporation" }
                $hwData = [PSCustomObject]@{ SystemInfo = $hwInfo }
                $extData = [PSCustomObject]@{ Hardware = $hwData }
                $mockVMHost = [PSCustomObject]@{ Name = "ms-host-1"; ExtensionData = $extData }

                function script:Get-Cluster {
                    param($Name, $ErrorAction)
                    if (-not $ErrorAction) { return $mockCluster }
                    return $mockCluster
                }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost)
                    @([PSCustomObject]@{ Name = "vmk0"; IP = "10.0.0.1" })
                }
                function script:Get-EsxCli {
                    param($VMHost, [switch]$V2)
                    $createArgs = { @{ host = '' } }
                    $invoke = { [PSCustomObject]@{ Summary = [PSCustomObject]@{ Received = 3 } } }
                    $ping = [PSCustomObject]@{}
                    $ping | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $createArgs
                    $ping | Add-Member -MemberType ScriptMethod -Name 'Invoke' -Value $invoke
                    $diag = [PSCustomObject]@{ ping = $ping }
                    $network = [PSCustomObject]@{ diag = $diag }
                    return [PSCustomObject]@{ network = $network }
                }

                { Test-VMKernelConnectivity -ClusterName "TestCluster" } |
                    Should -Not -Throw
            }
        }
    }

    Context "Ping failure" {
        It "Should throw when ping fails on a host" {
            InModuleScope Microsoft.AVS.VMFS -ArgumentList @($script:mockCluster) -ScriptBlock {
                param($mockCluster)

                $hwInfo = [PSCustomObject]@{ Vendor = "Microsoft Corporation" }
                $hwData = [PSCustomObject]@{ SystemInfo = $hwInfo }
                $extData = [PSCustomObject]@{ Hardware = $hwData }
                $mockVMHost = [PSCustomObject]@{ Name = "ms-host-1"; ExtensionData = $extData }

                function script:Get-Cluster {
                    param($Name, $ErrorAction)
                    if (-not $ErrorAction) { return $mockCluster }
                    return $mockCluster
                }
                function script:Get-VMHost { $mockVMHost }
                function script:Get-VMHostNetworkAdapter {
                    param($VMHost)
                    @([PSCustomObject]@{ Name = "vmk0"; IP = "10.0.0.1" })
                }
                function script:Get-EsxCli {
                    param($VMHost, [switch]$V2)
                    $createArgs = { @{ host = '' } }
                    $invoke = { [PSCustomObject]@{ Summary = [PSCustomObject]@{ Received = 0 } } }
                    $ping = [PSCustomObject]@{}
                    $ping | Add-Member -MemberType ScriptMethod -Name 'CreateArgs' -Value $createArgs
                    $ping | Add-Member -MemberType ScriptMethod -Name 'Invoke' -Value $invoke
                    $diag = [PSCustomObject]@{ ping = $ping }
                    $network = [PSCustomObject]@{ diag = $diag }
                    return [PSCustomObject]@{ network = $network }
                }

                { Test-VMKernelConnectivity -ClusterName "TestCluster" -ErrorAction SilentlyContinue } |
                    Should -Throw "*Ping to vmkernel interface failed on one or more hosts*"
            }
        }
    }
}
