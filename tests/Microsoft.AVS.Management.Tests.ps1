BeforeAll {
    # Define the AVSAttribute class that Management module functions use
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
        'Get-Cluster', 'Get-VMHost', 'Get-Datastore', 'Get-View',
        'Copy-DatastoreItem', 'New-PSDrive', 'Remove-PSDrive'
    )
    foreach ($cmdlet in $vmwareCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$cmdlet" -Value { param() $null }
        }
    }
    # Always override Get-VMHost with a stub that accepts pipeline input,
    # preventing mock failures when PowerCLI is not installed
    function global:Get-VMHost {
        param($Name, $Location, $State,
              [Parameter(ValueFromPipeline=$true)]$InputObject)
        process { $null }
    }

    # Import the Management module
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1"
    Import-Module $modulePath -Force
}

AfterAll {
    # Clean up
    Get-Module Microsoft.AVS.Management -ErrorAction SilentlyContinue | Remove-Module -Force
}

Describe "Microsoft.AVS.Management Module" {
    Context "Module Loading" {
        It "Should import the module successfully" {
            $module = Get-Module Microsoft.AVS.Management
            $module | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Set-ToolsRepo" {
    BeforeAll {
        # Helper function to create SecureString from plain text for testing
        function ConvertTo-TestSecureString {
            param([string]$PlainText)
            return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
        }
    }

    Context "Parameter Validation" {
        It "Should have ToolsURL as mandatory parameter" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have ToolsURL parameter of type SecureString" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $param.ParameterType.Name | Should -Be 'SecureString'
        }

        It "Should have ValidateNotNullOrEmpty attribute on ToolsURL" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }

        It "Should have HelpMessage on ToolsURL parameter" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $paramAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $paramAttr.HelpMessage | Should -Not -BeNullOrEmpty
        }

        It "Should have AVSAttribute with 30 minute timeout" {
            $command = Get-Command Set-ToolsRepo
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr | Should -Not -BeNullOrEmpty
            $avsAttr.Timeout.TotalMinutes | Should -Be 30
        }

        It "Should have AVSAttribute with UpdatesSDDC set to false" {
            $command = Get-Command Set-ToolsRepo
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.UpdatesSDDC | Should -Be $false
        }
    }

    Context "URL Pattern Validation" {
        It "Should throw for non-HTTP/HTTPS URL" {
            $secureUrl = ConvertTo-TestSecureString "ftp://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should throw for URL without protocol" {
            $secureUrl = ConvertTo-TestSecureString "example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should throw for file:// URL" {
            $secureUrl = ConvertTo-TestSecureString "file:///path/to/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should proceed past URL validation for valid HTTP URL" {
            Mock Invoke-WebRequest { throw "Expected network call" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "http://example.com/tools.zip"
            
            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }

        It "Should proceed past URL validation for valid HTTPS URL" {
            Mock Invoke-WebRequest { throw "Expected network call" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            
            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }

        It "Should proceed past URL validation for HTTPS URL with query parameters" {
            Mock Invoke-WebRequest { throw "Expected network call" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://storage.example.com/tools.zip?token=secret123&sig=abc"
            
            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }
    }

    Context "URL Accessibility Validation" {
        It "Should throw when URL is not accessible" {
            Mock Invoke-WebRequest { throw "404 Not Found" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://example.com/nonexistent.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }

        It "Should throw when URL returns non-200 status code" {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 403 } 
            } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://example.com/forbidden.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*URL returned status code: 403*"
        }
    }

    Context "Temporary Directory Creation" {
        BeforeAll {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
        }

        It "Should throw when temporary directory cannot be created" {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item { throw "Permission denied" } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Failed to create temporary directory*"
        }
    }

    Context "File Download Validation" {
        BeforeAll {
            # Mock successful HEAD request
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            
            # Mock successful temp directory creation
            Mock New-Item { 
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
        }

        It "Should throw when download fails" {
            Mock Invoke-WebRequest { throw "Download failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Failed to download tools file*"
        }

        It "Should throw when downloaded file is empty" {
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 0 } } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Downloaded file is empty*"
        }
    }

    Context "Archive Extraction Validation" {
        BeforeAll {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            
            Mock New-Item { 
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when archive extraction fails" {
            Mock Expand-Archive { throw "Invalid archive" } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Failed to extract tools archive*"
        }
    }

    Context "VMtools Directory Validation" {
        BeforeAll {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            
            Mock New-Item { 
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when vmtools directory not found in archive" {
            Mock Get-ChildItem { $null } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Unable to find vmtools directory*"
        }
    }

    Context "vSAN Datastore Validation" {
        BeforeAll {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            
            Mock New-Item { 
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem { 
                [PSCustomObject]@{ Name = "vmtools-12.3.0" } 
            } -ModuleName Microsoft.AVS.Management
            Mock Join-Path { "/tmp/newtools_test/vmware/apps/vmtools/windows64/vmtools-*" } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when no vSAN datastores found" {
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*No vSAN datastores found*"
        }

        It "Should throw when Get-Datastore fails" {
            Mock Get-Datastore { throw "Connection error" } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Failed to retrieve vSAN datastores*"
        }
    }

    Context "SecureString Handling" {
        It "Should pass converted SecureString URL to HEAD request" {
            $capturedUri = $null
            Mock Invoke-WebRequest { 
                $capturedUri = $Uri
                throw "Stop here for test"
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            
            $testUrl = "https://example.com/tools.zip?token=secret123"
            $secureUrl = ConvertTo-TestSecureString $testUrl
            
            try { Set-ToolsRepo -ToolsURL $secureUrl } catch { }
            
            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { 
                $Uri -eq $testUrl -and $Method -eq 'Head' 
            }
        }

        It "Should pass converted SecureString URL to download request" {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            
            Mock New-Item { 
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            
            Mock Invoke-WebRequest { throw "Stop here" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            
            $testUrl = "https://example.com/tools.zip?token=secret123"
            $secureUrl = ConvertTo-TestSecureString $testUrl
            
            try { Set-ToolsRepo -ToolsURL $secureUrl } catch { }
            
            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { 
                $Uri -eq $testUrl -and $OutFile 
            }
        }
    }

    Context "Error Handling" {
        It "Should wrap original error in descriptive message" {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item { throw "Permission denied" } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            
            { Set-ToolsRepo -ToolsURL $secureUrl } | 
                Should -Throw -ExpectedMessage "*Failed to create temporary directory*Permission denied*"
        }

        It "Should re-throw after catching to propagate error" {
            Mock Invoke-WebRequest { throw "Network error" } -ModuleName Microsoft.AVS.Management
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            
            { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Throw
        }
    }

    Context "PSDrive Cleanup" {
        It "Should attempt PSDrive cleanup even when datastore processing fails" {
            Mock Invoke-WebRequest { 
                [PSCustomObject]@{ StatusCode = 200 } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item { 
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" } 
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem { [PSCustomObject]@{ Name = "vmtools-12.3.0" } } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore { 
                [PSCustomObject]@{ 
                    Name = "vsanDatastore"
                    extensionData = [PSCustomObject]@{ Summary = [PSCustomObject]@{ Type = 'vsan' } }
                } 
            } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { throw "PSDrive creation failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Name -eq 'DS' }
            
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            
            try { Set-ToolsRepo -ToolsURL $secureUrl } catch { }
            
            # Verify cleanup was attempted
            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -ParameterFilter { $Name -eq 'DS' }
        }
    }
}

Describe "Get-EsxtopData" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory String parameter" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['ClusterName']
            $param.ParameterType.Name | Should -Be 'String'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $true
        }

        It "Should have EsxiHostName as mandatory String parameter" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['EsxiHostName']
            $param.ParameterType.Name | Should -Be 'String'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $true
        }

        It "Should have Iterations as optional Int32 with default 6" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['Iterations']
            $param.ParameterType.Name | Should -Be 'Int32'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $false
        }

        It "Should have IntervalSeconds as optional Int32 with ValidateRange(2,30)" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['IntervalSeconds']
            $param.ParameterType.Name | Should -Be 'Int32'
            $rangeAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $rangeAttr | Should -Not -BeNullOrEmpty
            $rangeAttr.MinRange | Should -Be 2
            $rangeAttr.MaxRange | Should -Be 30
        }

        It "Should have Iterations with ValidateRange(1,6)" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['Iterations']
            $rangeAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $rangeAttr | Should -Not -BeNullOrEmpty
            $rangeAttr.MinRange | Should -Be 1
            $rangeAttr.MaxRange | Should -Be 6
        }

        It "Should have OutputDatastoreName as optional String parameter" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['OutputDatastoreName']
            $param.ParameterType.Name | Should -Be 'String'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $false
        }

        It "Should have ValidateNotNullOrEmpty on ClusterName" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['ClusterName']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }

        It "Should have ValidateNotNullOrEmpty on EsxiHostName" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['EsxiHostName']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }

        It "Should have HelpMessage on all parameters" {
            $cmd = Get-Command Get-EsxtopData
            foreach ($name in @('ClusterName', 'EsxiHostName', 'Iterations', 'IntervalSeconds', 'OutputDatastoreName')) {
                $param = $cmd.Parameters[$name]
                $paramAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
                $paramAttr.HelpMessage | Should -Not -BeNullOrEmpty -Because "$name should have HelpMessage"
            }
        }
    }

    Context "AVSAttribute Verification" {
        It "Should have AVSAttribute with 30 minute timeout" {
            $cmd = Get-Command Get-EsxtopData
            $avsAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr | Should -Not -BeNullOrEmpty
            $avsAttr.Timeout.TotalMinutes | Should -Be 30
        }

        It "Should have AVSAttribute with UpdatesSDDC set to false" {
            $cmd = Get-Command Get-EsxtopData
            $avsAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.UpdatesSDDC | Should -Be $false
        }

        It "Should have AVSAttribute timeout <= 60 minutes" {
            $cmd = Get-Command Get-EsxtopData
            $avsAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.Timeout.TotalMinutes | Should -BeLessOrEqual 60
        }
    }

    Context "Sampling Span Validation" {
        BeforeEach {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when (Iterations-1)*IntervalSeconds exceeds 30" {
            { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -Iterations 6 -IntervalSeconds 7 } |
                Should -Throw -ExpectedMessage "*Esxtop sampling is limited to 30 seconds*"
        }

        It "Should not throw on sampling span validation when spacing equals 30" {
            Mock Get-Cluster { throw "Expected: past validation" } -ModuleName Microsoft.AVS.Management
            $err = $null
            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -Iterations 6 -IntervalSeconds 6 } catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Not -BeLike "*Esxtop sampling is limited*"
        }

        It "Should not throw on sampling span validation with single iteration" {
            Mock Get-Cluster { throw "Expected: past validation" } -ModuleName Microsoft.AVS.Management
            $err = $null
            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -Iterations 1 -IntervalSeconds 30 } catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Not -BeLike "*Esxtop sampling is limited*"
        }
    }

    Context "Host Resolution" {
        BeforeEach {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when cluster is not found" {
            Mock Get-Cluster { throw "Cluster 'BadCluster' not found." } -ModuleName Microsoft.AVS.Management
            { Get-EsxtopData -ClusterName 'BadCluster' -EsxiHostName 'host1' } |
                Should -Throw -ExpectedMessage "*BadCluster*"
        }

        It "Should throw when no matching connected host is found" {
            Mock Get-Cluster { [PSCustomObject]@{ Name = 'TestCluster' } } -ModuleName Microsoft.AVS.Management
            Mock Get-VMHost { return $null } -ModuleName Microsoft.AVS.Management
            { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'nohost' } |
                Should -Throw -ExpectedMessage "*No connected ESXi host matching*"
        }

    }

    Context "Input Sanitization" {
        It "Should call Limit-WildcardsandCodeInjectionCharacters for ClusterName and EsxiHostName" {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
            Mock Get-Cluster { throw "stop here" } -ModuleName Microsoft.AVS.Management

            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' } catch { }

            Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 2 -Exactly
        }

        It "Should sanitize OutputDatastoreName when provided" {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
            Mock Get-Cluster { throw "stop here" } -ModuleName Microsoft.AVS.Management

            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -OutputDatastoreName 'myDS' } catch { }

            Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 3 -Exactly
        }
    }

    Context "CmdletBinding" {
        It "Should have CmdletBinding attribute" {
            $cmd = Get-Command Get-EsxtopData
            $cmdletBindingAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
            $cmdletBindingAttr | Should -Not -BeNullOrEmpty
        }
    }
}
