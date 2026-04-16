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

}
