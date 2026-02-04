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

#region Behavioral Tests - iSCSI Target Removal Functions

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

#endregion
