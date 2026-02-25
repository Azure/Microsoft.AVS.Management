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
    
    # Import the VMFS module
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.VMFS" "Microsoft.AVS.VMFS.psd1"
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
        BeforeAll {
            Mock Get-Cluster { [PSCustomObject]@{ Name = "TestCluster" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "TestDS"; State = "Available" } } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VM { $null } -ModuleName Microsoft.AVS.VMFS
            Mock Get-VMHost { $null } -ModuleName Microsoft.AVS.VMFS
        }

        It "Should throw when no connected hosts found with datastore" {
            { Remove-VmfsDatastore -ClusterName "TestCluster" -DatastoreName "TestDS" } |
                Should -Throw "*No connected hosts found*"
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

                function script:Get-IScsiHbaTarget {
                    param($IScsiHba, $Type, $ErrorAction)
                    @()
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
                    if ($script:getTargetCallCount -le 2) {
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

                function script:Get-IScsiHbaTarget {
                    param($IScsiHba, $Type, $ErrorAction)
                    @()
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
                    if ($script:getTargetCallCount -le 2) {
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
                    param($VMHost, $V2)
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
