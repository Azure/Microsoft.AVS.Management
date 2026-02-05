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
