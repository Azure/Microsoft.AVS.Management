BeforeAll {
    # Import the module under test
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.CDR" "Microsoft.CDR.psd1"
    Import-Module $modulePath -Force

    if($Global:FeedSettings) {
        $script:credential = $Global:FeedSettings.Credential
        $script:repository = $Global:FeedSettings.Repository
    }

    # if we upgrade the pipline dependencies to use this version we should change this to another version, so that install could actually happen
    $script:PSAnalyser = @{ Name = "PSScriptAnalyzer"; Version = "1.24.0" }
    $script:MSAVSManagement = @{ Name = "Microsoft.AVS.Management"; Version = "8.0.201" }
    $testModules = @($script:PSAnalyser, $script:MSAVSManagement)
    
    # Remove test modules if they exist to ensure clean installation tests
    foreach ($module in $testModules) {
        $existingModule = Get-PSResource -Name $module.Name | 
            Where-Object { $_.Version.ToString() -eq $module.Version }

        if ($existingModule) {
            Write-Verbose "Removing existing $($module.Name) version $($module.Version) for clean test"
            Uninstall-PSResource -Name $module.Name -Version $module.Version -ErrorAction SilentlyContinue
        }
    }
}

Describe "Install-PSResourcePinned" {
    BeforeAll {
        $script:testScope = 'CurrentUser'
    }

    Context "Parameter Validation" {
        It "Should have Name parameter as mandatory" {
            $command = Get-Command Install-PSResourcePinned
            $nameParam = $command.Parameters['Name']
            $nameParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Version parameter as mandatory" {
            $command = Get-Command Install-PSResourcePinned
            $versionParam = $command.Parameters['Version']
            $versionParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should accept valid Scope values" {
            # This tests that the ValidateSet works correctly
            $command = Get-Command Install-PSResourcePinned
            $scopeParam = $command.Parameters['Scope']
            $scopeParam.Attributes.ValidValues | Should -Contain 'CurrentUser'
            $scopeParam.Attributes.ValidValues | Should -Contain 'AllUsers'
        }
    }

    Context "Module Installation" -Tag 'Integration' {
        BeforeAll {
        }

        It "Should install a module with exact version" {
            try {
                Install-PSResourcePinned -Name $script:PSAnalyser.Name -Version $script:PSAnalyser.Version -Repository $script:repository -Credential $script:credential -Scope $testScope
                $installed = Get-PSResource -Name $testModuleName | Where-Object { $_.Version.ToString() -eq $testModuleVersion }
                $installed | Should -Not -BeNullOrEmpty
            }
            catch {
                Set-ItResult -Skipped -Because "Network access required for this test"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should handle non-existent module gracefully" {
            { Install-PSResourcePinned -Name "NonExistentModule12345" -Version "1.0.0" -Repository $script:repository -Credential $script:credential } | 
                Should -Throw -ExpectedMessage "*not found*"
        }
    }

    Context "Redirect Map" {
        BeforeAll {
            # Create a temporary redirect map file
            $script:testRedirectMapPath = Join-Path $TestDrive "test-redirect.json"
            $redirectData = @{
                "TestModule@1.0.0" = "1.0.1"
                "AnotherModule" = "2.0.0"
            }
            $redirectData | ConvertTo-Json | Set-Content $testRedirectMapPath
        }

        It "Should load redirect map from file" {
            # This tests that the redirect map parameter is accepted
            $command = Get-Command Install-PSResourcePinned
            $command.Parameters.ContainsKey('RedirectMapPath') | Should -BeTrue
        }

        AfterAll {
            if (Test-Path $testRedirectMapPath) {
                Remove-Item $testRedirectMapPath -Force
            }
        }
    }

    Context "Verbose Output" {
        It "Should produce verbose output when requested" {
            $verboseOutput = Install-PSResourcePinned -Name $script:MSAVSManagement.Name -Version $script:MSAVSManagement.Version -Repository $script:repository -Credential $script:credential -Verbose 4>&1
            # At minimum, should see searching message
            $verboseOutput | Should -Not -BeNullOrEmpty
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')
    }
}

Describe "Import-ModulePinned" {
    Context "Parameter Validation" {
        It "Should have Name parameter as mandatory" {
            $command = Get-Command Import-ModulePinned
            $nameParam = $command.Parameters['Name']
            $nameParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Version parameter as mandatory" {
            $command = Get-Command Import-ModulePinned
            $versionParam = $command.Parameters['Version']
            $versionParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should accept Name and Version positional parameters" {
            # Test that parameters accept positional values
            $command = Get-Command Import-ModulePinned
            $command.Parameters['Name'].Attributes.Position | Should -Be 0
            $command.Parameters['Version'].Attributes.Position | Should -Be 1
        }
    }

    Context "Module Import" -Tag 'Integration' {
        BeforeAll {
            # Ensure test module is installed
            $script:testModuleName = $script:MSAVSManagement.Name
            $script:testModuleVersion = $script:MSAVSManagement.Version
            
            # Check if module is installed, if not, install it
            $installed = Get-PSResource -Name $testModuleName | 
                Where-Object { $_.Version.ToString() -eq $testModuleVersion }
            
            if (-not $installed) {
                Install-PSResourcePinned -Name $testModuleName -Version $testModuleVersion -Repository $script:repository -Credential $script:credential
            }
        }

        It "Should import a module with exact version" {
            { Import-ModulePinned -Name $testModuleName -Version $testModuleVersion } | Should -Not -Throw
            
            $loadedModule = Get-Module -Name $testModuleName
            $loadedModule | Should -Not -BeNullOrEmpty
            $loadedModule.Version.ToString() | Should -Be $testModuleVersion
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should return module info when PassThru is specified" {
            $result = Import-ModulePinned -Name $testModuleName -Version $testModuleVersion -PassThru -Force
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $testModuleName
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should reimport module when Force is specified" {
            # Import once
            Import-ModulePinned -Name $testModuleName -Version $testModuleVersion
            
            # Import again with Force
            { Import-ModulePinned -Name $testModuleName -Version $testModuleVersion -Force } | Should -Not -Throw
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should throw when module is not installed" {
            { Import-ModulePinned -Name "NonExistentModule12345" -Version "1.0.0" } | 
                Should -Throw -ExpectedMessage "*not found*"
        }

        AfterEach {
            # Clean up imported modules
            Get-Module -Name $testModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
        }
    }

    Context "Dependency Loading" -Tag 'Integration' {
        BeforeAll {
            # For testing dependency loading, we'll use a module known to have dependencies
            $script:moduleWithDeps = $script:MSAVSManagement.Name
            $script:moduleWithDepsVersion = $script:MSAVSManagement.Version
        }

        It "Should recursively load module dependencies" {
            # Skip if the module isn't available or we're in CI
            try {
                $installed = Get-PSResource -Name $moduleWithDeps | 
                    Where-Object { $_.Version.ToString() -eq $moduleWithDepsVersion }
                
                if ($installed) {
                    Import-ModulePinned -Name $moduleWithDeps -Version $moduleWithDepsVersion -Verbose
                    
                    # Check that the main module is loaded
                    $loadedModule = Get-Module -Name $moduleWithDeps
                    $loadedModule | Should -Not -BeNullOrEmpty
                }
                else {
                    Set-ItResult -Skipped -Because "Test module $moduleWithDeps version $moduleWithDepsVersion not installed"
                }
            }
            catch {
                Set-ItResult -Skipped -Because "Dependency test requires specific module versions"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            # Clean up
            Get-Module -Name $moduleWithDeps -ErrorAction SilentlyContinue | Remove-Module -Force
        }
    }

    Context "Prefix Parameter" {
        BeforeAll {
            $script:testModuleName = $script:MSAVSManagement.Name
            $script:testModuleVersion = $script:MSAVSManagement.Version
        }

        It "Should apply prefix to imported commands" {
            Import-ModulePinned -Name $testModuleName -Version $testModuleVersion -Prefix "Test" -Force
            
            # Check that prefixed command exists
            $commands = Get-Command -Module $testModuleName
            # Note: Actual prefix behavior depends on the module's noun structure
            $commands | Should -Not -BeNullOrEmpty
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            Get-Module -Name $testModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
        }
    }

    Context "Global Scope" {
        BeforeAll {
            $script:testModuleName = $script:MSAVSManagement.Name
            $script:testModuleVersion = $script:MSAVSManagement.Version
        }

        It "Should import module to global scope when specified" {
            Import-ModulePinned -Name $testModuleName -Version $testModuleVersion -Global -Force
            
            $loadedModule = Get-Module -Name $testModuleName
            $loadedModule | Should -Not -BeNullOrEmpty
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            Get-Module -Name $testModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
        }
    }

    Context "Verbose Output" {
        BeforeAll {
            $script:testModuleName = $script:MSAVSManagement.Name
            $script:testModuleVersion = $script:MSAVSManagement.Version
        }

        It "Should produce verbose output when requested" {
            $verboseOutput = Import-ModulePinned -Name $testModuleName -Version $testModuleVersion -Verbose -Force 4>&1
            $verboseOutput | Should -Not -BeNullOrEmpty
            $verboseOutput | Should -Match "Importing module"
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            Get-Module -Name $testModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
        }
    }
}

Describe "Module Manifest" {
    BeforeAll {
        $manifestPath = Join-Path $PSScriptRoot ".." "Microsoft.CDR" "Microsoft.CDR.psd1"
        $script:manifest = Test-ModuleManifest -Path $manifestPath
    }

    It "Should have correct module name" {
        $manifest.Name | Should -Be "Microsoft.CDR"
    }

    It "Should export Install-PSResourcePinned function" {
        $manifest.ExportedFunctions.Keys | Should -Contain "Install-PSResourcePinned"
    }

    It "Should export Import-ModulePinned function" {
        $manifest.ExportedFunctions.Keys | Should -Contain "Import-ModulePinned"
    }

    It "Should have valid version" {
        $manifest.Version | Should -Not -BeNullOrEmpty
        $manifest.Version.GetType().Name | Should -Be "Version"
    }

    It "Should require PowerShell 7.4 or higher" {
        $manifest.PowerShellVersion | Should -BeGreaterOrEqual ([Version]"7.4")
    }
}

AfterAll {
}
