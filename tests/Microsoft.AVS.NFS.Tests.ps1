BeforeAll {
    # Define the AVSAttribute class that NFS module functions use
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
        'Get-Cluster', 'Get-VMHost', 'Get-Datastore', 'Get-EsxCli',
        'Get-VM', 'Remove-Datastore', 'New-Datastore'
    )
    foreach ($cmdlet in $vmwareCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$cmdlet" -Value { param() $null }
        }
    }

    # Override Get-VMHost with a stub that accepts common parameters
    function global:Get-VMHost {
        param($Name, $Datastore, $State, $Id,
              [Parameter(ValueFromPipeline=$true)]$InputObject)
        process { $null }
    }

    # Override Get-Datastore with a stub that accepts pipeline input and Name parameter
    function global:Get-Datastore {
        param($Name, 
              [Parameter(ValueFromPipeline=$true)]$InputObject)
        process { $null }
    }

    # Override Get-EsxCli with a permissive stub so PSCustomObject mock hosts pass parameter binding
    function global:Get-EsxCli {
        param($VMHost, [switch]$V2, $Server)
        $null
    }

    # Stub for Limit-WildcardsandCodeInjectionCharacters from Microsoft.AVS.Management
    if (-not (Get-Command 'Limit-WildcardsandCodeInjectionCharacters' -ErrorAction SilentlyContinue)) {
        function global:Limit-WildcardsandCodeInjectionCharacters {
            param([string]$String)
            return $String
        }
    }

    # Import the NFS module (use .psm1 directly to avoid RequiredModules dependency on VMware modules)
    $modulePath = Join-Path (Join-Path (Join-Path $PSScriptRoot "..") "Microsoft.AVS.NFS") "Microsoft.AVS.NFS.psm1"
    Import-Module $modulePath -Force
}

AfterAll {
    # Clean up
    Get-Module Microsoft.AVS.NFS -ErrorAction SilentlyContinue | Remove-Module -Force
}

Describe "Microsoft.AVS.NFS Module" {
    Context "Module Loading" {
        It "Should import the module successfully" {
            $module = Get-Module Microsoft.AVS.NFS
            $module | Should -Not -BeNullOrEmpty
        }

        It "Should export expected functions" {
            $module = Get-Module Microsoft.AVS.NFS
            $module.ExportedFunctions.Keys | Should -Contain 'New-NFSDatastore'
            $module.ExportedFunctions.Keys | Should -Contain 'Remove-NFSDatastore'
            $module.ExportedFunctions.Keys | Should -Contain 'Get-NFSDatastoreNConnectValue'
        }
    }
}

Describe "Get-NFSDatastoreNConnectValue" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory parameter" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $param = $command.Parameters['ClusterName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have DatastoreName as mandatory parameter" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $param = $command.Parameters['DatastoreName']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have ClusterName as String type" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $param = $command.Parameters['ClusterName']
            $param.ParameterType.Name | Should -Be 'String'
        }

        It "Should have DatastoreName as String type" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $param = $command.Parameters['DatastoreName']
            $param.ParameterType.Name | Should -Be 'String'
        }

        It "Should have ValidateNotNullOrEmpty on ClusterName" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $param = $command.Parameters['ClusterName']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }

        It "Should have ValidateNotNullOrEmpty on DatastoreName" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $param = $command.Parameters['DatastoreName']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }
    }

    Context "Cluster Validation" {
        BeforeAll {
            Mock Get-Cluster { $null } -ModuleName Microsoft.AVS.NFS
        }

        It "Should throw when cluster does not exist" {
            { Get-NFSDatastoreNConnectValue -ClusterName "NonExistentCluster" -DatastoreName "TestDS" } | 
                Should -Throw -ExpectedMessage "*does not exist*"
        }
    }

    Context "Datastore Validation" {
        BeforeAll {
            # Create a mock cluster that returns null when piped to Get-Datastore
            $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
            Mock Get-Cluster { $mockCluster } -ModuleName Microsoft.AVS.NFS
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.NFS
        }

        It "Should throw when datastore not found on cluster" {
            { Get-NFSDatastoreNConnectValue -ClusterName "TestCluster" -DatastoreName "NonExistentDS" } | 
                Should -Throw -ExpectedMessage "*not found on cluster*"
        }
    }

    Context "NFS Type Validation" {
        BeforeAll {
            $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
            Mock Get-Cluster { $mockCluster } -ModuleName Microsoft.AVS.NFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "VmfsDS"; Type = "VMFS" } } -ModuleName Microsoft.AVS.NFS
        }

        It "Should throw when datastore is VMFS type" {
            { Get-NFSDatastoreNConnectValue -ClusterName "TestCluster" -DatastoreName "VmfsDS" } | 
                Should -Throw -ExpectedMessage "*only supports NFS datastores*"
        }
    }

    Context "Host Validation" {
        BeforeAll {
            $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
            Mock Get-Cluster { $mockCluster } -ModuleName Microsoft.AVS.NFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "NfsDS"; Type = "NFS" } } -ModuleName Microsoft.AVS.NFS
            Mock Get-VMHost { $null } -ModuleName Microsoft.AVS.NFS
        }

        It "Should throw when no hosts found in cluster" {
            { Get-NFSDatastoreNConnectValue -ClusterName "TestCluster" -DatastoreName "NfsDS" } | 
                Should -Throw -ExpectedMessage "*No hosts found*"
        }
    }

    Context "Disconnected Host Handling" {
        BeforeAll {
            $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
            Mock Get-Cluster { $mockCluster } -ModuleName Microsoft.AVS.NFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "NfsDS"; Type = "NFS" } } -ModuleName Microsoft.AVS.NFS
            # All hosts disconnected
            Mock Get-VMHost { 
                @(
                    [PSCustomObject]@{ Name = "esxi-01"; ConnectionState = "Disconnected" },
                    [PSCustomObject]@{ Name = "esxi-02"; ConnectionState = "Maintenance" }
                )
            } -ModuleName Microsoft.AVS.NFS
        }

        It "Should throw when all hosts are disconnected" {
            { Get-NFSDatastoreNConnectValue -ClusterName "TestCluster" -DatastoreName "NfsDS" } | 
                Should -Throw -ExpectedMessage "*No connected hosts*"
        }
    }

    Context "Happy Path - NConnect Value Retrieval" {
        BeforeAll {
            $mockCluster = [PSCustomObject]@{ Name = "TestCluster" }
            Mock Get-Cluster { $mockCluster } -ModuleName Microsoft.AVS.NFS
            Mock Get-Datastore { [PSCustomObject]@{ Name = "NfsDS"; Type = "NFS" } } -ModuleName Microsoft.AVS.NFS

            # Two connected hosts and one disconnected host (which should be skipped)
            Mock Get-VMHost {
                @(
                    [PSCustomObject]@{ Name = "esxi-01"; ConnectionState = "Connected" },
                    [PSCustomObject]@{ Name = "esxi-02"; ConnectionState = "Connected" },
                    [PSCustomObject]@{ Name = "esxi-03"; ConnectionState = "Disconnected" }
                )
            } -ModuleName Microsoft.AVS.NFS

            # Mock Get-EsxCli to return an object with a storage.nfs.list.invoke() chain
            Mock Get-EsxCli {
                $listObj = New-Object PSObject
                $listObj | Add-Member -MemberType ScriptMethod -Name invoke -Value {
                    @(
                        [PSCustomObject]@{
                            VolumeName  = "NfsDS"
                            Host        = "10.0.0.10"
                            Share       = "/exports/nfsds"
                            NFSv41      = $false
                            Connections = 4
                            Accessible  = $true
                            Mounted     = $true
                        }
                    )
                }
                [PSCustomObject]@{
                    storage = [PSCustomObject]@{
                        nfs = [PSCustomObject]@{
                            list = $listObj
                        }
                    }
                }
            } -ModuleName Microsoft.AVS.NFS
        }

        AfterAll {
            Remove-Variable -Name NamedOutputs -Scope Global -ErrorAction SilentlyContinue
        }

        It "Should populate NamedOutputs for connected hosts and skip disconnected hosts" {
            Remove-Variable -Name NamedOutputs -Scope Global -ErrorAction SilentlyContinue

            Get-NFSDatastoreNConnectValue -ClusterName "TestCluster" -DatastoreName "NfsDS"

            $global:NamedOutputs | Should -Not -BeNullOrEmpty
            $global:NamedOutputs.Count | Should -Be 2
            $global:NamedOutputs.Keys | Should -Contain "esxi-01"
            $global:NamedOutputs.Keys | Should -Contain "esxi-02"
            $global:NamedOutputs.Keys | Should -Not -Contain "esxi-03"

            $global:NamedOutputs["esxi-01"] | Should -Match "NConnectValue : 4"
            $global:NamedOutputs["esxi-01"] | Should -Match "DatastoreName : NfsDS"
            $global:NamedOutputs["esxi-01"] | Should -Match "NfsServerHost : 10.0.0.10"
            $global:NamedOutputs["esxi-01"] | Should -Match "SharePath : /exports/nfsds"
            $global:NamedOutputs["esxi-01"] | Should -Match "NfsVersion : 3"
        }

        It "Should call Get-EsxCli only for connected hosts" {
            Get-NFSDatastoreNConnectValue -ClusterName "TestCluster" -DatastoreName "NfsDS" 
            Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.NFS -Times 2 -Exactly
        }
    }

    Context "AVSAttribute Verification" {
        It "Should have AVSAttribute with 10 minute timeout" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr | Should -Not -BeNullOrEmpty
            $avsAttr.Timeout.TotalMinutes | Should -Be 10
        }

        It "Should have AVSAttribute with UpdatesSDDC set to false" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.UpdatesSDDC | Should -Be $false
        }

        It "Should have AVSAttribute timeout <= 60 minutes" {
            $command = Get-Command Get-NFSDatastoreNConnectValue
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.Timeout.TotalMinutes | Should -BeLessOrEqual 60
        }
    }

}

Describe "New-NFSDatastore" {
    Context "AVSAttribute Verification" {
        It "Should have AVSAttribute with 10 minute timeout" {
            $command = Get-Command New-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr | Should -Not -BeNullOrEmpty
            $avsAttr.Timeout.TotalMinutes | Should -Be 10
        }

        It "Should have AVSAttribute with UpdatesSDDC set to false" {
            $command = Get-Command New-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.UpdatesSDDC | Should -Be $false
        }

        It "Should have AVSAttribute with AutomationOnly set to true" {
            $command = Get-Command New-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.AutomationOnly | Should -Be $true
        }

        It "Should have AVSAttribute timeout <= 60 minutes" {
            $command = Get-Command New-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.Timeout.TotalMinutes | Should -BeLessOrEqual 60
        }
    }
}

Describe "Remove-NFSDatastore" {
    Context "AVSAttribute Verification" {
        It "Should have AVSAttribute with 10 minute timeout" {
            $command = Get-Command Remove-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr | Should -Not -BeNullOrEmpty
            $avsAttr.Timeout.TotalMinutes | Should -Be 10
        }

        It "Should have AVSAttribute with UpdatesSDDC set to false" {
            $command = Get-Command Remove-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.UpdatesSDDC | Should -Be $false
        }

        It "Should have AVSAttribute with AutomationOnly set to true" {
            $command = Get-Command Remove-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.AutomationOnly | Should -Be $true
        }

        It "Should have AVSAttribute timeout <= 60 minutes" {
            $command = Get-Command Remove-NFSDatastore
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.Timeout.TotalMinutes | Should -BeLessOrEqual 60
        }
    }
}
