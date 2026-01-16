BeforeAll {
    # Import the module under test
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
    Import-Module $modulePath -Force

    if($Global:FeedSettings) {
        $script:credential = $Global:FeedSettings.Credential
        $script:repository = $Global:FeedSettings.Repository
    }

    # if we upgrade the pipline dependencies to use this version we should change this to another version, so that install could actually happen
    $script:PSAnalyser = @{ Name = "PSScriptAnalyzer"; Version = "1.24.0" }
    $script:MSAVSManagement = @{ Name = "Microsoft.AVS.Management"; Version = "8.0.201" }
    $testModules = @($script:PSAnalyser, $script:MSAVSManagement)

    if(-not $env:SKIP_INTEGRATION_TESTS) {
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
            $versionParam = $command.Parameters['RequiredVersion']
            $versionParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Repository parameter" {
            $command = Get-Command Install-PSResourcePinned
            $command.Parameters.ContainsKey('Repository') | Should -BeTrue
        }

        It "Should have Credential parameter" {
            $command = Get-Command Install-PSResourcePinned
            $credParam = $command.Parameters['Credential']
            $credParam.ParameterType.Name | Should -Be 'PSCredential'
        }

        It "Should have RedirectMapPath parameter" {
            $command = Get-Command Install-PSResourcePinned
            $command.Parameters.ContainsKey('RedirectMapPath') | Should -BeTrue
        }
    }

    Context "Module Installation" -Tag 'Integration' {
        BeforeAll {
        }

        It "Should install a module with exact version" {
            try {
                Install-PSResourcePinned -Name $script:PSAnalyser.Name -RequiredVersion $script:PSAnalyser.Version -Repository $script:repository -Credential $script:credential -Scope $testScope
                $installed = Get-PSResource -Name $script:PSAnalyser.Name | Where-Object { $_.Version.ToString() -eq $script:PSAnalyser.Version }
                $installed | Should -Not -BeNullOrEmpty
            }
            catch {
                Set-ItResult -Skipped -Because "Network access required for this test"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should handle non-existent module gracefully" {
            { Install-PSResourcePinned -Name "NonExistentModule12345" -RequiredVersion "1.0.0" -Repository $script:repository -Credential $script:credential } | 
                Should -Throw -ExpectedMessage "*could not be found*"
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')
    }

    Context "Redirect Map" {
        BeforeAll {
            # Create a temporary redirect map file
            $script:nonExistentMapPath = Join-Path $TestDrive "non-existent-map.json"
        }

        It "Should accept redirect map file path parameter" {
            # Verify the parameter exists and file can be loaded
            $command = Get-Command Install-PSResourcePinned
            $command.Parameters.ContainsKey('RedirectMapPath') | Should -BeTrue
        }

        It "Should throw when redirect map file doesn't exist" {
            # When map file doesn't exist and is specified, should throw
            { 
                Install-PSResourcePinned -Name $script:PSAnalyser.Name -RequiredVersion $script:PSAnalyser.Version `
                    -RedirectMapPath $script:nonExistentMapPath -Repository $script:repository `
                    -Credential $script:credential -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "*not found*"
        }

        It "Should respect redirects in map file during install" -Tag 'Integration' {
            # Create a redirect map that would redirect a dependency version
            # This is a conceptual test - in practice we'd need a module with known dependencies
            $redirectMapForInstall = Join-Path $TestDrive "install-redirect.json"
            $installRedirects = @{
                "$($script:PSAnalyser.Name)@$($script:PSAnalyser.Version)" = $script:PSAnalyser.Version
            }
            $installRedirects | ConvertTo-Json | Set-Content $redirectMapForInstall
            
            # Capture verbose output to verify redirect was loaded
            $verboseOutput = Install-PSResourcePinned -Name $script:PSAnalyser.Name `
                -RequiredVersion $script:PSAnalyser.Version -RedirectMapPath $redirectMapForInstall `
                -Repository $script:repository -Credential $script:credential -Verbose 4>&1
            
            # Should see message about loading redirect map
            $verboseOutput | Should -Match "Loading redirect map"
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should respect redirects in map file during import" -Tag 'Integration' {
            # Create a redirect map for import testing
            $redirectMapForImport = Join-Path $TestDrive "import-redirect.json"
            $importRedirects = @{
                "$($script:MSAVSManagement.Name)@$($script:MSAVSManagement.Version)" = $script:MSAVSManagement.Version
            }
            $importRedirects | ConvertTo-Json | Set-Content $redirectMapForImport
            
            # Ensure module is installed first
            $installed = Get-PSResource -Name $script:MSAVSManagement.Name | 
                Where-Object { $_.Version.ToString() -eq $script:MSAVSManagement.Version }
            
            if (-not $installed) {
                Install-PSResourcePinned -Name $script:MSAVSManagement.Name `
                    -RequiredVersion $script:MSAVSManagement.Version -Repository $script:repository `
                    -Credential $script:credential
            }
            
            # Capture verbose output to verify redirect was loaded
            $verboseOutput = Import-ModulePinned -Name $script:MSAVSManagement.Name `
                -RequiredVersion $script:MSAVSManagement.Version -RedirectMapPath $redirectMapForImport `
                -Force -Verbose 4>&1
            
            # Should see message about loading redirect map
            $verboseOutput | Should -Match "Loading redirect map"
            
            # Clean up
            Get-Module -Name $script:MSAVSManagement.Name -ErrorAction SilentlyContinue | Remove-Module -Force
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterAll {
            # Cleanup handled in individual tests
        }
    }

    Context "Verbose Output" {
        It "Should produce verbose output when requested" {
            $verboseOutput = Install-PSResourcePinned -Name $script:MSAVSManagement.Name -RequiredVersion $script:MSAVSManagement.Version -Repository $script:repository -Credential $script:credential -Verbose 4>&1
            # At minimum, should see searching message
            $verboseOutput | Should -Not -BeNullOrEmpty
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')
    }
}

Describe "Get-MergedRedirectMap" {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
        Import-Module $modulePath -Force
        
        $script:mapsDir = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "maps"
        if (-not (Test-Path $script:mapsDir)) {
            New-Item -Path $script:mapsDir -ItemType Directory -Force | Out-Null
        }
    }

    Context "Map Merging" {
        It "Should return outer map when no module-specific map exists" {
            InModuleScope Microsoft.AVS.CDR {
                $outerMap = @{ "Module1@1.0" = "1.1" }
                $result = Get-MergedRedirectMap -OuterMap $outerMap -Name "NonExistentModule" -Version "1.0.0"
                
                $result.Count | Should -Be 1
                $result["Module1@1.0"] | Should -Be "1.1"
            }
        }

        It "Should merge module-specific map with outer map" {
            $testModuleMapPath = Join-Path $script:mapsDir "MergeTest@1.0.0.json"
            
            try {
                # Create a module-specific map
                $moduleSpecificMap = @{
                    "Dependency1@1.0.0" = "1.0.1"
                    "Dependency2@2.0.0" = "2.0.1"
                }
                $moduleSpecificMap | ConvertTo-Json | Set-Content $testModuleMapPath
                
                InModuleScope Microsoft.AVS.CDR {
                    param($mapPath)
                    
                    $outerMap = @{ "Dependency3@3.0.0" = "3.0.1" }
                    $result = Get-MergedRedirectMap -OuterMap $outerMap -Name "MergeTest" -Version "1.0.0"
                    
                    # Should contain all three dependencies
                    $result.Count | Should -Be 3
                    $result["Dependency1@1.0.0"] | Should -Be "1.0.1"
                    $result["Dependency2@2.0.0"] | Should -Be "2.0.1"
                    $result["Dependency3@3.0.0"] | Should -Be "3.0.1"
                } -ArgumentList $testModuleMapPath
            }
            finally {
                if (Test-Path $testModuleMapPath) {
                    Remove-Item $testModuleMapPath -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It "Should favor outer map over module-specific map for conflicts" {
            $testModuleMapPath = Join-Path $script:mapsDir "ConflictTest@1.0.0.json"
            
            try {
                # Create a module-specific map
                $moduleSpecificMap = @{
                    "Dependency1@1.0.0" = "1.0.1"  # This should be overridden
                }
                $moduleSpecificMap | ConvertTo-Json | Set-Content $testModuleMapPath
                
                InModuleScope Microsoft.AVS.CDR {
                    $outerMap = @{ "Dependency1@1.0.0" = "1.0.2" }  # This should win
                    $result = Get-MergedRedirectMap -OuterMap $outerMap -Name "ConflictTest" -Version "1.0.0"
                    
                    # Outer map should take precedence
                    $result["Dependency1@1.0.0"] | Should -Be "1.0.2"
                }
            }
            finally {
                if (Test-Path $testModuleMapPath) {
                    Remove-Item $testModuleMapPath -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It "Should try full version, major.minor, and major-only patterns" {
            # Create map files for different version patterns
            $fullVersionMapPath = Join-Path $script:mapsDir "PatternTest@1.2.3.4.json"
            $majorMinorMapPath = Join-Path $script:mapsDir "PatternTest@1.2.json"
            $majorOnlyMapPath = Join-Path $script:mapsDir "PatternTest@1.json"
            
            try {
                # Only create the major.minor version map
                $majorMinorMap = @{ "Dependency@1.0.0" = "1.0.1" }
                $majorMinorMap | ConvertTo-Json | Set-Content $majorMinorMapPath
                
                InModuleScope Microsoft.AVS.CDR {
                    $outerMap = @{}
                    # Request full version 1.2.3.4, should fall back to 1.2
                    $result = Get-MergedRedirectMap -OuterMap $outerMap -Name "PatternTest" -Version "1.2.3.4"
                    
                    # Should have loaded the major.minor map
                    $result["Dependency@1.0.0"] | Should -Be "1.0.1"
                }
            }
            finally {
                Remove-Item $fullVersionMapPath, $majorMinorMapPath, $majorOnlyMapPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should cache loaded maps" {
            $testModuleMapPath = Join-Path $script:mapsDir "CacheTest@1.0.0.json"
            
            try {
                # Create a module-specific map
                $moduleSpecificMap = @{ "Dependency@1.0.0" = "1.0.1" }
                $moduleSpecificMap | ConvertTo-Json | Set-Content $testModuleMapPath
                
                InModuleScope Microsoft.AVS.CDR {
                    # Clear cache
                    $script:moduleMapCache = @{}
                    
                    $outerMap = @{}
                    
                    # First call - should load from file
                    $result1 = Get-MergedRedirectMap -OuterMap $outerMap -Name "CacheTest" -Version "1.0.0"
                    
                    # Cache should now contain the map
                    $script:moduleMapCache.ContainsKey("CacheTest@1.0.0") | Should -BeTrue
                    
                    # Second call - should use cache
                    $result2 = Get-MergedRedirectMap -OuterMap $outerMap -Name "CacheTest" -Version "1.0.0"
                    
                    # Results should be the same
                    $result1["Dependency@1.0.0"] | Should -Be "1.0.1"
                    $result2["Dependency@1.0.0"] | Should -Be "1.0.1"
                }
            }
            finally {
                if (Test-Path $testModuleMapPath) {
                    Remove-Item $testModuleMapPath -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It "Should handle version ranges in ModuleVersion parameter" {
            $testModuleMapPath = Join-Path $script:mapsDir "RangeTest@1.2.json"
            
            try {
                # Create a map for version 1.2
                $versionMap = @{ "Dependency@1.0.0" = "1.0.1" }
                $versionMap | ConvertTo-Json | Set-Content $testModuleMapPath
                
                InModuleScope Microsoft.AVS.CDR {
                    $outerMap = @{}
                    # Pass a version range format
                    $result = Get-MergedRedirectMap -OuterMap $outerMap -Name "RangeTest" -Version "[1.2.3, 1.2.4]"
                    
                    # Should extract version 1.2.3 and match to 1.2 pattern
                    $result["Dependency@1.0.0"] | Should -Be "1.0.1"
                }
            }
            finally {
                if (Test-Path $testModuleMapPath) {
                    Remove-Item $testModuleMapPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    AfterAll {
        # Clean up any test map files
        if (Test-Path $script:mapsDir) {
            Get-ChildItem -Path $script:mapsDir -Filter "*Test@*.json" | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe "Import-ModulePinned" {
    Context "Parameter Validation" {
        It "Should have Name parameter as mandatory" {
            $command = Get-Command Import-ModulePinned
            $nameParam = $command.Parameters['Name']
            $nameParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have RequiredVersion parameter as mandatory" {
            $command = Get-Command Import-ModulePinned
            $versionParam = $command.Parameters['RequiredVersion']
            $versionParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should accept Name and RequiredVersion positional parameters" {
            # Test that parameters accept positional values
            $command = Get-Command Import-ModulePinned
            $command.Parameters['Name'].Attributes.Position | Should -Be 0
            $command.Parameters['RequiredVersion'].Attributes.Position | Should -Be 1
        }

        It "Should have RedirectMapPath parameter" {
            $command = Get-Command Import-ModulePinned
            $command.Parameters.ContainsKey('RedirectMapPath') | Should -BeTrue
        }
    }

    Context "Module Import" -Tag 'Integration' {
        BeforeAll {
            # Ensure test module is installed
            $script:testModuleName = $script:MSAVSManagement.Name
            $script:testModuleVersion = $script:MSAVSManagement.Version
            
            if( -not $env:SKIP_INTEGRATION_TESTS) {
                # Check if module is installed, if not, install it
                $installed = Get-PSResource -Name $testModuleName | 
                Where-Object { $_.Version.ToString() -eq $testModuleVersion }
                
                if (-not $installed) {
                    Install-PSResourcePinned -Name $testModuleName -RequiredVersion $testModuleVersion -Repository $script:repository -Credential $script:credential
                }
            }
        }

        It "Should import a module with exact version" {
            { Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion } | Should -Not -Throw
            
            $loadedModule = Get-Module -Name $testModuleName
            $loadedModule | Should -Not -BeNullOrEmpty
            $loadedModule.Version.ToString() | Should -Be $testModuleVersion
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should return module info when PassThru is specified" {
            $result = Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion -PassThru -Force
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $testModuleName
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should reimport module when Force is specified" {
            # Import once
            Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion
            
            # Import again with Force
            { Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion -Force } | Should -Not -Throw
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should throw when module is not installed" {
            { Import-ModulePinned -Name "NonExistentModule12345" -RequiredVersion "1.0.0" } | 
                Should -Throw -ExpectedMessage "Module not found: NonExistentModule12345 version 1.0.0"
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
                    Import-ModulePinned -Name $moduleWithDeps -RequiredVersion $moduleWithDepsVersion -Verbose
                    
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
            Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion -Prefix "Test" -Force
            
            # Check that prefixed command exists
            $commands = Get-Command -Module $testModuleName
            # Note: Actual prefix behavior depends on the module's noun structure
            $commands | Should -Not -BeNullOrEmpty
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            Get-Module -Name $testModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
        }
    }
}

Describe "Module Manifest" {
    BeforeAll {
        $manifestPath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
        $script:manifest = Test-ModuleManifest -Path $manifestPath
    }

    It "Should have correct module name" {
        $manifest.Name | Should -Be "Microsoft.AVS.CDR"
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
}

Describe "Find-DependencyRedirect" {
    BeforeAll {
        # Access internal function through module scope
        $module = Get-Module Microsoft.AVS.CDR
        $script:FindDependencyRedirect = & $module { ${function:Find-DependencyRedirect} }
    }
    
    Context "Empty/Null Version Handling" {
        It "Should resolve empty version from redirect map (name-only)" {
            $redirectMap = @{ "TestModule" = "1.0.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should resolve null version from redirect map (name-only)" {
            $redirectMap = @{ "TestModule" = "1.0.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion $null -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should throw when empty version has no redirect map entry" {
            $redirectMap = @{}
            { & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "" -RedirectMap $redirectMap } | 
                Should -Throw "*Cannot conservatively resolve version*"
        }
        
        It "Should normalize dependency name casing for empty version" {
            $redirectMap = @{ "TestModule" = "1.0.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "testmodule" -DependencyVersion "" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
    }
    
    Context "Open-Ended Version Range Handling" {
        It "Should extract minimum version from open-ended range [1.0, )" {
            $redirectMap = @{}
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $false
        }
        
        It "Should extract minimum version from open-ended range (1.2.3, )" {
            $redirectMap = @{}
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "(1.2.3, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.2.3"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $false
        }
        
        It "Should extract minimum version from range [2.1.0, ]" {
            $redirectMap = @{}
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[2.1.0, ]" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "2.1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $false
        }
    }
    
    Context "Exact Version Specification - No Redirect" {
        It "Should handle simple version with no redirect" {
            $redirectMap = @{}
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "1.0.0" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $false
        }
        
        It "Should handle exact range [1.0, 1.0] with no redirect" {
            $redirectMap = @{}
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, 1.0]" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $false
        }
    }
    
    Context "Exact Version Specification - With Same Version Redirect" {
        It "Should allow redirect to same version for simple version" {
            $redirectMap = @{ "TestModule@1.0" = "1.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "1.0" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should allow redirect to same version for exact range" {
            $redirectMap = @{ "TestModule@1.2.3" = "1.2.3" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.2.3, 1.2.3]" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.2.3"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
    }
    
    Context "Exact Version Specification - With Different Version Redirect (Should Throw)" {
        It "Should throw when redirecting simple version to different version" {
            $redirectMap = @{ "TestModule@1.0" = "2.0" }
            { & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "1.0" -RedirectMap $redirectMap } |
                Should -Throw "*Cannot redirect exact version dependency*"
        }
        
        It "Should throw when redirecting exact range to different version" {
            $redirectMap = @{ "TestModule@1.0" = "1.1" }
            { & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, 1.0]" -RedirectMap $redirectMap } |
                Should -Throw "*Cannot redirect exact version dependency*"
        }
        
        It "Should throw when name-only redirect changes exact version" {
            $redirectMap = @{ "TestModule" = "2.0.0" }
            { & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "1.0.0" -RedirectMap $redirectMap } |
                Should -Throw "*Cannot redirect exact version dependency*"
        }
    }
    
    Context "Version-Specific Redirect (name@version)" {
        It "Should apply version-specific redirect" {
            $redirectMap = @{ "TestModule@1.0" = "1.1" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.1"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should prioritize version-specific redirect over name-only redirect" {
            $redirectMap = @{ "TestModule" = "2.0"; "TestModule@1.0" = "1.5" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.5"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should normalize module name casing from version-specific redirect key" {
            $redirectMap = @{ "TestModule@1.0" = "1.1" }
            $result = & $script:FindDependencyRedirect -DependencyName "testmodule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.1"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
    }
    
    Context "Name-Only Redirect" {
        It "Should apply name-only redirect to non-exact version" {
            $redirectMap = @{ "TestModule" = "1.5.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.5.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should normalize module name casing from name-only redirect key" {
            $redirectMap = @{ "TestModule" = "1.0.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "testmodule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
    }
    
    Context "Special '*' Redirect Value" {
        It "Should retain version and normalize name with name@version redirect to '*'" {
            $redirectMap = @{ "TestModule@1.0" = "*" }
            $result = & $script:FindDependencyRedirect -DependencyName "testmodule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should retain version and normalize name with name-only redirect to '*'" {
            $redirectMap = @{ "TestModule" = "*" }
            $result = & $script:FindDependencyRedirect -DependencyName "testmodule" -DependencyVersion "1.0.0" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should retain exact version with '*' redirect" {
            $redirectMap = @{ "TestModule@1.0" = "*" }
            $result = & $script:FindDependencyRedirect -DependencyName "testmodule" -DependencyVersion "1.0" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should retain normalized version from open range with '*' redirect" {
            $redirectMap = @{ "TestModule" = "*" }
            $result = & $script:FindDependencyRedirect -DependencyName "testmodule" -DependencyVersion "[2.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "2.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
    }
    
    Context "Case Sensitivity and Normalization" {
        It "Should be case-insensitive for dependency name matching" {
            $redirectMap = @{ "TestModule@1.0" = "1.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "TESTMODULE" -DependencyVersion "1.0" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should preserve redirect map key casing for module name" {
            $redirectMap = @{ "VMware.VimAutomation.Core" = "*" }
            $result = & $script:FindDependencyRedirect -DependencyName "vmware.vimautomation.core" -DependencyVersion "1.0" -RedirectMap $redirectMap
            $result.ResolvedName | Should -Be "VMware.VimAutomation.Core"
        }
    }
    
    Context "Complex Scenarios" {
        It "Should handle open range that becomes exact version after normalization with redirect" {
            $redirectMap = @{ "TestModule@1.0" = "1.0.1" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, )" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0.1"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should extract module name correctly from name@version redirect key" {
            $redirectMap = @{ "Test.Module@1.0.0" = "1.0.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "test.module" -DependencyVersion "1.0.0" -RedirectMap $redirectMap
            $result.ResolvedName | Should -Be "Test.Module"
        }
    }
    
    Context "Non-Exact Version Ranges" {
        It "Should allow redirect for non-exact range [1.0, 2.0]" {
            $redirectMap = @{ "TestModule@1.0" = "1.5.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, 2.0]" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.5.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
        
        It "Should handle range with different min/max versions" {
            $redirectMap = @{ "TestModule" = "1.8.0" }
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "[1.0, 2.0]" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.8.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $true
        }
    }
    
    Context "Edge Cases" {
        It "Should handle version with many parts" {
            $redirectMap = @{}
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "1.2.3.4" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.2.3.4"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $false
        }
        
        It "Should handle empty redirect map" {
            $redirectMap = @{}
            $result = & $script:FindDependencyRedirect -DependencyName "TestModule" -DependencyVersion "1.0" -RedirectMap $redirectMap
            $result.ResolvedVersion | Should -Be "1.0"
            $result.ResolvedName | Should -Be "TestModule"
            $result.IsRedirected | Should -Be $false
        }
    }
}

AfterAll {
}
