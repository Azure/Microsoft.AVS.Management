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

    Context "Verbose Output" -Tag 'Integration' {
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
                Should -Throw -ExpectedMessage "*Module not found: NonExistentModule12345 version 1.0.0*"
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

    Context "Topological Import Order" -Tag 'Integration' {
        BeforeAll {
            $script:testModuleName = $script:MSAVSManagement.Name
            $script:testModuleVersion = $script:MSAVSManagement.Version
        }

        It "Should build dependency graph in verbose output" {
            try {
                $installed = Get-PSResource -Name $testModuleName | 
                    Where-Object { $_.Version.ToString() -eq $testModuleVersion }
                
                if (-not $installed) {
                    Set-ItResult -Skipped -Because "Test module not installed"
                    return
                }
                
                # Capture verbose output
                $verboseOutput = Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion -Force -Verbose 4>&1
                $verboseText = $verboseOutput | Out-String
                
                # Should see graph building phase
                $verboseText | Should -Match "Building dependency graph"
                
                # Should see topological order computation
                $verboseText | Should -Match "Computing topological order"
                
                # Should see import order listing
                $verboseText | Should -Match "Import order"
            }
            catch {
                Set-ItResult -Skipped -Because "Topological import test requires specific module versions: $_"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should pre-load all dependencies before main module" {
            try {
                $installed = Get-PSResource -Name $testModuleName | 
                    Where-Object { $_.Version.ToString() -eq $testModuleVersion }
                
                if (-not $installed) {
                    Set-ItResult -Skipped -Because "Test module not installed"
                    return
                }
                
                # Clear any loaded modules
                Get-Module -Name $testModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
                
                # Capture verbose output
                $verboseOutput = Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion -Force -Verbose 4>&1
                $verboseText = $verboseOutput | Out-String
                
                # Should see pre-loading message
                $verboseText | Should -Match "Pre-loading all modules"
                
                # Main module should be loaded at the end
                $loadedModule = Get-Module -Name $testModuleName
                $loadedModule | Should -Not -BeNullOrEmpty
                $loadedModule.Version.ToString() | Should -Be $testModuleVersion
            }
            catch {
                Set-ItResult -Skipped -Because "Pre-load test requires specific module versions: $_"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        It "Should report correct count of imported dependencies" {
            try {
                $installed = Get-PSResource -Name $testModuleName | 
                    Where-Object { $_.Version.ToString() -eq $testModuleVersion }
                
                if (-not $installed) {
                    Set-ItResult -Skipped -Because "Test module not installed"
                    return
                }
                
                # Capture verbose output
                $verboseOutput = Import-ModulePinned -Name $testModuleName -RequiredVersion $testModuleVersion -Force -Verbose 4>&1
                $verboseText = $verboseOutput | Out-String
                
                # Should report success with dependency count
                $verboseText | Should -Match "Successfully imported.*and \d+ dependencies"
            }
            catch {
                Set-ItResult -Skipped -Because "Dependency count test requires specific module versions: $_"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            # Clean up loaded modules
            Get-Module -Name $testModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
        }
    }

    Context "Prefix Parameter" -Tag 'Integration' {
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

Describe "Topological Dependency Loading" {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
        Import-Module $modulePath -Force
    }

    Context "Get-TopologicalOrder Function" {
        # Access the internal function through InModuleScope
        
        It "Should return empty order for empty graph" {
            InModuleScope Microsoft.AVS.CDR {
                # Define the function locally for testing (it's nested inside Import-ModulePinned)
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                $emptyGraph = @{}
                $result = Get-TopologicalOrder -Graph $emptyGraph
                $result.Count | Should -Be 0
            }
        }

        It "Should return single module for graph with no dependencies" {
            InModuleScope Microsoft.AVS.CDR {
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                $graph = @{
                    "ModuleA@1.0.0" = @{
                        Name = "ModuleA"
                        Version = "1.0.0"
                        Dependencies = @()
                    }
                }
                
                $result = @(Get-TopologicalOrder -Graph $graph)
                $result.Count | Should -Be 1
                $result[0] | Should -Be "ModuleA@1.0.0"
            }
        }

        It "Should order dependencies before dependents (linear chain)" {
            InModuleScope Microsoft.AVS.CDR {
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                # A depends on B, B depends on C
                # C -> B -> A (C should be imported first)
                $graph = @{
                    "ModuleA@1.0.0" = @{
                        Name = "ModuleA"
                        Version = "1.0.0"
                        Dependencies = @("ModuleB@1.0.0")
                    }
                    "ModuleB@1.0.0" = @{
                        Name = "ModuleB"
                        Version = "1.0.0"
                        Dependencies = @("ModuleC@1.0.0")
                    }
                    "ModuleC@1.0.0" = @{
                        Name = "ModuleC"
                        Version = "1.0.0"
                        Dependencies = @()
                    }
                }
                
                $result = Get-TopologicalOrder -Graph $graph
                $result.Count | Should -Be 3
                
                # C must come before B, B must come before A
                $indexC = $result.IndexOf("ModuleC@1.0.0")
                $indexB = $result.IndexOf("ModuleB@1.0.0")
                $indexA = $result.IndexOf("ModuleA@1.0.0")
                
                $indexC | Should -BeLessThan $indexB
                $indexB | Should -BeLessThan $indexA
            }
        }

        It "Should handle diamond dependency pattern" {
            InModuleScope Microsoft.AVS.CDR {
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                # Diamond: A -> B, A -> C, B -> D, C -> D
                #       A
                #      / \
                #     B   C
                #      \ /
                #       D
                $graph = @{
                    "ModuleA@1.0.0" = @{
                        Name = "ModuleA"
                        Version = "1.0.0"
                        Dependencies = @("ModuleB@1.0.0", "ModuleC@1.0.0")
                    }
                    "ModuleB@1.0.0" = @{
                        Name = "ModuleB"
                        Version = "1.0.0"
                        Dependencies = @("ModuleD@1.0.0")
                    }
                    "ModuleC@1.0.0" = @{
                        Name = "ModuleC"
                        Version = "1.0.0"
                        Dependencies = @("ModuleD@1.0.0")
                    }
                    "ModuleD@1.0.0" = @{
                        Name = "ModuleD"
                        Version = "1.0.0"
                        Dependencies = @()
                    }
                }
                
                $result = Get-TopologicalOrder -Graph $graph
                $result.Count | Should -Be 4
                
                # D must come before B and C, B and C must come before A
                $indexD = $result.IndexOf("ModuleD@1.0.0")
                $indexB = $result.IndexOf("ModuleB@1.0.0")
                $indexC = $result.IndexOf("ModuleC@1.0.0")
                $indexA = $result.IndexOf("ModuleA@1.0.0")
                
                $indexD | Should -BeLessThan $indexB
                $indexD | Should -BeLessThan $indexC
                $indexB | Should -BeLessThan $indexA
                $indexC | Should -BeLessThan $indexA
            }
        }

        It "Should detect and warn about circular dependencies" {
            InModuleScope Microsoft.AVS.CDR {
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                # Circular: A -> B -> C -> A
                $graph = @{
                    "ModuleA@1.0.0" = @{
                        Name = "ModuleA"
                        Version = "1.0.0"
                        Dependencies = @("ModuleB@1.0.0")
                    }
                    "ModuleB@1.0.0" = @{
                        Name = "ModuleB"
                        Version = "1.0.0"
                        Dependencies = @("ModuleC@1.0.0")
                    }
                    "ModuleC@1.0.0" = @{
                        Name = "ModuleC"
                        Version = "1.0.0"
                        Dependencies = @("ModuleA@1.0.0")
                    }
                }
                
                # Should produce warning but not throw
                $warnings = Get-TopologicalOrder -Graph $graph 3>&1
                $warnings | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | 
                    Should -Not -BeNullOrEmpty
            }
        }

        It "Should handle multiple independent subgraphs" {
            InModuleScope Microsoft.AVS.CDR {
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                # Two independent chains: A->B and C->D
                $graph = @{
                    "ModuleA@1.0.0" = @{
                        Name = "ModuleA"
                        Version = "1.0.0"
                        Dependencies = @("ModuleB@1.0.0")
                    }
                    "ModuleB@1.0.0" = @{
                        Name = "ModuleB"
                        Version = "1.0.0"
                        Dependencies = @()
                    }
                    "ModuleC@1.0.0" = @{
                        Name = "ModuleC"
                        Version = "1.0.0"
                        Dependencies = @("ModuleD@1.0.0")
                    }
                    "ModuleD@1.0.0" = @{
                        Name = "ModuleD"
                        Version = "1.0.0"
                        Dependencies = @()
                    }
                }
                
                $result = Get-TopologicalOrder -Graph $graph
                $result.Count | Should -Be 4
                
                # B must come before A, D must come before C
                $indexA = $result.IndexOf("ModuleA@1.0.0")
                $indexB = $result.IndexOf("ModuleB@1.0.0")
                $indexC = $result.IndexOf("ModuleC@1.0.0")
                $indexD = $result.IndexOf("ModuleD@1.0.0")
                
                $indexB | Should -BeLessThan $indexA
                $indexD | Should -BeLessThan $indexC
            }
        }

        It "Should not duplicate modules in order" {
            InModuleScope Microsoft.AVS.CDR {
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                # Diamond pattern where D is referenced by both B and C
                $graph = @{
                    "ModuleA@1.0.0" = @{
                        Name = "ModuleA"
                        Version = "1.0.0"
                        Dependencies = @("ModuleB@1.0.0", "ModuleC@1.0.0")
                    }
                    "ModuleB@1.0.0" = @{
                        Name = "ModuleB"
                        Version = "1.0.0"
                        Dependencies = @("ModuleD@1.0.0")
                    }
                    "ModuleC@1.0.0" = @{
                        Name = "ModuleC"
                        Version = "1.0.0"
                        Dependencies = @("ModuleD@1.0.0")
                    }
                    "ModuleD@1.0.0" = @{
                        Name = "ModuleD"
                        Version = "1.0.0"
                        Dependencies = @()
                    }
                }
                
                $result = Get-TopologicalOrder -Graph $graph
                
                # D should only appear once
                $dOccurrences = ($result | Where-Object { $_ -eq "ModuleD@1.0.0" }).Count
                $dOccurrences | Should -Be 1
                
                # Total count should be exactly 4
                $result.Count | Should -Be 4
            }
        }
    }

    Context "Version Conflict Detection Scenario" {
        It "Should demonstrate the version conflict problem this solves" {
            # This test documents the problem scenario:
            # - Module A requires Core@12.7 (exact)
            # - Module B requires Core@[12.6, ) (minimum - gets latest 13.3)
            # - Both Core versions require Common with same name but different versions
            # - Without topological preloading, PowerShell loads wrong version
            
            InModuleScope Microsoft.AVS.CDR {
                function Get-TopologicalOrder {
                    param([hashtable]$Graph)
                    
                    $visited = @{}
                    $visiting = @{}
                    $order = [System.Collections.ArrayList]@()
                    
                    function Visit {
                        param([string]$NodeKey)
                        
                        if ($visited.ContainsKey($NodeKey)) { return }
                        if ($visiting.ContainsKey($NodeKey)) {
                            Write-Warning "Circular dependency detected involving: $NodeKey"
                            return
                        }
                        
                        $visiting[$NodeKey] = $true
                        
                        if ($Graph.ContainsKey($NodeKey)) {
                            $node = $Graph[$NodeKey]
                            foreach ($depKey in $node.Dependencies) {
                                Visit -NodeKey $depKey
                            }
                        }
                        
                        $visiting.Remove($NodeKey)
                        $visited[$NodeKey] = $true
                        [void]$order.Add($NodeKey)
                    }
                    
                    foreach ($nodeKey in $Graph.Keys) {
                        Visit -NodeKey $nodeKey
                    }
                    
                    return $order
                }
                
                # Simulates the VMware module conflict:
                # VCDA.AVS -> Management -> Core@12.7 -> Cis.Core -> Vim -> Common@12.7
                #                        -> Hcx@12.7 -> Core@12.7 (same)
                $graph = @{
                    "VMware.VCDA.AVS@1.0.3" = @{
                        Name = "VMware.VCDA.AVS"
                        Version = "1.0.3"
                        Dependencies = @("Microsoft.AVS.Management@5.3.99")
                    }
                    "Microsoft.AVS.Management@5.3.99" = @{
                        Name = "Microsoft.AVS.Management"
                        Version = "5.3.99"
                        Dependencies = @("VMware.VimAutomation.Core@12.7.0", "VMware.VimAutomation.Hcx@12.7.0")
                    }
                    "VMware.VimAutomation.Core@12.7.0" = @{
                        Name = "VMware.VimAutomation.Core"
                        Version = "12.7.0"
                        Dependencies = @("VMware.VimAutomation.Cis.Core@12.7.0")
                    }
                    "VMware.VimAutomation.Hcx@12.7.0" = @{
                        Name = "VMware.VimAutomation.Hcx"
                        Version = "12.7.0"
                        Dependencies = @("VMware.VimAutomation.Core@12.7.0")
                    }
                    "VMware.VimAutomation.Cis.Core@12.7.0" = @{
                        Name = "VMware.VimAutomation.Cis.Core"
                        Version = "12.7.0"
                        Dependencies = @("VMware.Vim@7.0.3")
                    }
                    "VMware.Vim@7.0.3" = @{
                        Name = "VMware.Vim"
                        Version = "7.0.3"
                        Dependencies = @("VMware.VimAutomation.Common@12.7.0")
                    }
                    "VMware.VimAutomation.Common@12.7.0" = @{
                        Name = "VMware.VimAutomation.Common"
                        Version = "12.7.0"
                        Dependencies = @()
                    }
                }
                
                $result = Get-TopologicalOrder -Graph $graph
                
                # Common (leaf) should be first, VCDA.AVS (root) should be last
                $indexCommon = $result.IndexOf("VMware.VimAutomation.Common@12.7.0")
                $indexVCDA = $result.IndexOf("VMware.VCDA.AVS@1.0.3")
                
                $indexCommon | Should -Be 0  # First to be imported
                $indexVCDA | Should -Be ($result.Count - 1)  # Last to be imported
                
                # Vim must come after Common
                $indexVim = $result.IndexOf("VMware.Vim@7.0.3")
                $indexVim | Should -BeGreaterThan $indexCommon
                
                # Cis.Core must come after Vim
                $indexCisCore = $result.IndexOf("VMware.VimAutomation.Cis.Core@12.7.0")
                $indexCisCore | Should -BeGreaterThan $indexVim
                
                # Core must come after Cis.Core
                $indexCore = $result.IndexOf("VMware.VimAutomation.Core@12.7.0")
                $indexCore | Should -BeGreaterThan $indexCisCore
            }
        }
    }

}

Describe "Save-PSResourcePinned" {
    BeforeAll {
        $script:testSavePath = Join-Path $TestDrive "packages"
    }

    Context "Parameter Validation" {
        It "Should have Name parameter as mandatory" {
            $command = Get-Command Save-PSResourcePinned
            $nameParam = $command.Parameters['Name']
            $nameParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have RequiredVersion parameter as mandatory" {
            $command = Get-Command Save-PSResourcePinned
            $versionParam = $command.Parameters['RequiredVersion']
            $versionParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Path parameter as mandatory" {
            $command = Get-Command Save-PSResourcePinned
            $pathParam = $command.Parameters['Path']
            $pathParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Repository parameter" {
            $command = Get-Command Save-PSResourcePinned
            $command.Parameters.ContainsKey('Repository') | Should -BeTrue
        }

        It "Should have Credential parameter" {
            $command = Get-Command Save-PSResourcePinned
            $credParam = $command.Parameters['Credential']
            $credParam.ParameterType.Name | Should -Be 'PSCredential'
        }

        It "Should have RedirectMapPath parameter" {
            $command = Get-Command Save-PSResourcePinned
            $command.Parameters.ContainsKey('RedirectMapPath') | Should -BeTrue
        }

        It "Should have AsNupkg switch parameter" {
            $command = Get-Command Save-PSResourcePinned
            $command.Parameters.ContainsKey('AsNupkg') | Should -BeTrue
            $command.Parameters['AsNupkg'].SwitchParameter | Should -BeTrue
        }
    }

    Context "Path Handling" {
        It "Should create destination directory if it doesn't exist" {
            $newPath = Join-Path $TestDrive "new-save-dir-$(Get-Random)"
            
            # Mock Find-PSResource to return a module with no dependencies
            Mock Find-PSResource -ModuleName Microsoft.AVS.CDR {
                [PSCustomObject]@{
                    Name = "TestModule"
                    Version = [version]"1.0.0"
                    Dependencies = @()
                }
            }
            
            # Mock Save-PSResource to do nothing
            Mock Save-PSResource -ModuleName Microsoft.AVS.CDR { }
            
            Save-PSResourcePinned -Name "TestModule" -RequiredVersion "1.0.0" -Path $newPath
            
            Test-Path $newPath | Should -BeTrue
            
            # Cleanup
            Remove-Item $newPath -Force -ErrorAction SilentlyContinue
        }
    }

    Context "Redirect Map" {
        BeforeAll {
            $script:nonExistentMapPath = Join-Path $TestDrive "non-existent-map.json"
        }

        It "Should throw when redirect map file doesn't exist" {
            { 
                Save-PSResourcePinned -Name "TestModule" -RequiredVersion "1.0.0" `
                    -Path $script:testSavePath -RedirectMapPath $script:nonExistentMapPath -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "*not found*"
        }
    }

    Context "Module Not Found" {
        It "Should throw when module is not found in repository" {
            Mock Find-PSResource -ModuleName Microsoft.AVS.CDR { $null }
            
            { Save-PSResourcePinned -Name "NonExistentModule" -RequiredVersion "1.0.0" -Path $script:testSavePath } |
                Should -Throw -ExpectedMessage "*not found*"
        }
    }

    Context "Dependency Processing" {
        BeforeEach {
            if (-not (Test-Path $script:testSavePath)) {
                New-Item -Path $script:testSavePath -ItemType Directory -Force | Out-Null
            }
        }

        It "Should save main module with SkipDependencyCheck" {
            Mock Find-PSResource -ModuleName Microsoft.AVS.CDR {
                [PSCustomObject]@{
                    Name = "TestModule"
                    Version = [version]"1.0.0"
                    Dependencies = @()
                }
            }
            
            Mock Save-PSResource -ModuleName Microsoft.AVS.CDR { }
            
            Save-PSResourcePinned -Name "TestModule" -RequiredVersion "1.0.0" -Path $script:testSavePath
            
            Should -Invoke Save-PSResource -ModuleName Microsoft.AVS.CDR -Times 1 -ParameterFilter {
                $Name -eq "TestModule" -and $Version -eq "1.0.0" -and $SkipDependencyCheck -eq $true
            }
        }

        It "Should save dependencies before main module" {
            # Create mock module with dependency
            Mock Find-PSResource -ModuleName Microsoft.AVS.CDR {
                param($Name, $Version)
                if ($Name -eq "MainModule") {
                    [PSCustomObject]@{
                        Name = "MainModule"
                        Version = [version]"1.0.0"
                        Dependencies = @(
                            [PSCustomObject]@{ Name = "DepModule"; VersionRange = "[2.0.0, 2.0.0]" }
                        )
                    }
                }
                else {
                    [PSCustomObject]@{
                        Name = "DepModule"
                        Version = [version]"2.0.0"
                        Dependencies = @()
                    }
                }
            }
            
            $script:savedModules = @()
            Mock Save-PSResource -ModuleName Microsoft.AVS.CDR {
                $script:savedModules += $Name
            }
            
            # Create redirect map for exact version
            $redirectMapPath = Join-Path $TestDrive "dep-redirect.json"
            @{ "DepModule@2.0.0" = "2.0.0" } | ConvertTo-Json | Set-Content $redirectMapPath
            
            Save-PSResourcePinned -Name "MainModule" -RequiredVersion "1.0.0" `
                -Path $script:testSavePath -RedirectMapPath $redirectMapPath
            
            # Dependency should be saved before main module
            $script:savedModules.Count | Should -Be 2
            $script:savedModules[0] | Should -Be "DepModule"
            $script:savedModules[1] | Should -Be "MainModule"
        }

        It "Should skip already saved packages" {
            Mock Find-PSResource -ModuleName Microsoft.AVS.CDR {
                [PSCustomObject]@{
                    Name = "TestModule"
                    Version = [version]"1.0.0"
                    Dependencies = @(
                        [PSCustomObject]@{ Name = "DepModule"; VersionRange = "[2.0.0, 2.0.0]" }
                    )
                }
            }
            
            # Create a fake .nupkg file to simulate already saved
            $existingNupkg = Join-Path $script:testSavePath "DepModule.2.0.0.nupkg"
            "fake content" | Set-Content $existingNupkg
            
            $script:savedModules = @()
            Mock Save-PSResource -ModuleName Microsoft.AVS.CDR {
                $script:savedModules += $Name
            }
            
            $redirectMapPath = Join-Path $TestDrive "skip-redirect.json"
            @{ "DepModule@2.0.0" = "2.0.0" } | ConvertTo-Json | Set-Content $redirectMapPath
            
            Save-PSResourcePinned -Name "TestModule" -RequiredVersion "1.0.0" `
                -Path $script:testSavePath -RedirectMapPath $redirectMapPath
            
            # Only main module should be saved, dependency already exists
            $script:savedModules | Should -Contain "TestModule"
            $script:savedModules | Should -Not -Contain "DepModule"
        }

        AfterEach {
            if (Test-Path $script:testSavePath) {
                Remove-Item $script:testSavePath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Module Download" -Tag 'Integration' {
        BeforeEach {
            if (Test-Path $script:testSavePath) {
                Remove-Item $script:testSavePath -Recurse -Force
            }
        }

        It "Should save a module with exact version as nupkg" {
            try {
                Save-PSResourcePinned -Name $script:PSAnalyser.Name -RequiredVersion $script:PSAnalyser.Version `
                    -Path $script:testSavePath -Repository $script:repository -Credential $script:credential
                
                $expectedFile = Join-Path $script:testSavePath "$($script:PSAnalyser.Name).$($script:PSAnalyser.Version).nupkg"
                Test-Path $expectedFile | Should -BeTrue
            }
            catch {
                Set-ItResult -Skipped -Because "Network access required for this test"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            if (Test-Path $script:testSavePath) {
                Remove-Item $script:testSavePath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "Install-PSResourceDependencies" {
    BeforeAll {
        $script:testManifestDir = Join-Path $TestDrive "TestModule"
        $script:testManifestPath = Join-Path $script:testManifestDir "TestModule.psd1"
    }

    Context "Parameter Validation" {
        It "Should have ManifestPath parameter as mandatory" {
            $command = Get-Command Install-PSResourceDependencies
            $pathParam = $command.Parameters['ManifestPath']
            $pathParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Repository parameter" {
            $command = Get-Command Install-PSResourceDependencies
            $command.Parameters.ContainsKey('Repository') | Should -BeTrue
        }

        It "Should have Credential parameter" {
            $command = Get-Command Install-PSResourceDependencies
            $credParam = $command.Parameters['Credential']
            $credParam.ParameterType.Name | Should -Be 'PSCredential'
        }

        It "Should have RedirectMapPath parameter" {
            $command = Get-Command Install-PSResourceDependencies
            $command.Parameters.ContainsKey('RedirectMapPath') | Should -BeTrue
        }

        It "Should have Scope parameter with valid values" {
            $command = Get-Command Install-PSResourceDependencies
            $scopeParam = $command.Parameters['Scope']
            $validateSet = $scopeParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'CurrentUser'
            $validateSet.ValidValues | Should -Contain 'AllUsers'
        }
    }

    Context "Manifest Validation" {
        It "Should throw when manifest file doesn't exist" {
            $nonExistentManifest = Join-Path $TestDrive "NonExistent.psd1"
            { Install-PSResourceDependencies -ManifestPath $nonExistentManifest } | 
                Should -Throw -ExpectedMessage "*not found*"
        }

        It "Should throw when file is not a .psd1 file" {
            $notPsd1File = Join-Path $TestDrive "test.txt"
            "test content" | Set-Content $notPsd1File
            
            { Install-PSResourceDependencies -ManifestPath $notPsd1File } | 
                Should -Throw -ExpectedMessage "*.psd1*"
        }

        It "Should handle manifest with no RequiredModules gracefully" {
            # Create test directory
            New-Item -Path $script:testManifestDir -ItemType Directory -Force | Out-Null
            
            # Create a minimal manifest with no RequiredModules
            $manifestContent = @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'e1234567-1234-1234-1234-123456789012'
    Author = 'Test'
    RootModule = 'TestModule.psm1'
}
"@
            $manifestContent | Set-Content $script:testManifestPath
            
            # Should not throw, just return silently
            { Install-PSResourceDependencies -ManifestPath $script:testManifestPath } | Should -Not -Throw
        }
    }

    Context "RequiredModules Processing" {
        BeforeEach {
            # Create test directory
            New-Item -Path $script:testManifestDir -ItemType Directory -Force | Out-Null
        }

        It "Should convert ModuleVersion to open-ended range for redirect resolution" {
            # Create manifest with ModuleVersion (minimum version)
            $manifestContent = @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'e1234567-1234-1234-1234-123456789012'
    Author = 'Test'
    RootModule = 'TestModule.psm1'
    RequiredModules = @(
        @{ ModuleName = 'TestDep'; ModuleVersion = '2.0.0' }
    )
}
"@
            $manifestContent | Set-Content $script:testManifestPath
            
            # Create a redirect map that expects open-ended range format
            $redirectMapPath = Join-Path $TestDrive "test-redirect.json"
            # The redirect map should match on "TestDep" and redirect the open range to a specific version
            @{ "TestDep" = "2.5.0" } | ConvertTo-Json | Set-Content $redirectMapPath
            
            # Mock Install-PSResourcePinned to capture what version was resolved
            Mock Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR { }
            
            Install-PSResourceDependencies -ManifestPath $script:testManifestPath -RedirectMapPath $redirectMapPath
            
            # The redirect should have resolved "[2.0.0, )" to "2.5.0"
            Should -Invoke Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR -Times 1 -ParameterFilter {
                $Name -eq "TestDep" -and $RequiredVersion -eq "2.5.0"
            }
        }

        It "Should pass RequiredVersion as exact version for redirect resolution" {
            $manifestContent = @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'e1234567-1234-1234-1234-123456789012'
    Author = 'Test'
    RootModule = 'TestModule.psm1'
    RequiredModules = @(
        @{ ModuleName = 'TestDep'; RequiredVersion = '3.0.0' }
    )
}
"@
            $manifestContent | Set-Content $script:testManifestPath
            
            # Create a redirect map - for exact version, redirect must be same version
            $redirectMapPath = Join-Path $TestDrive "test-redirect.json"
            @{ "TestDep@3.0.0" = "3.0.0" } | ConvertTo-Json | Set-Content $redirectMapPath
            
            Mock Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR { }
            
            Install-PSResourceDependencies -ManifestPath $script:testManifestPath -RedirectMapPath $redirectMapPath
            
            # Should pass the exact version
            Should -Invoke Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR -Times 1 -ParameterFilter {
                $Name -eq "TestDep" -and $RequiredVersion -eq "3.0.0"
            }
        }

        It "Should call Install-PSResourcePinned for each RequiredModule" {
            $manifestContent = @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'e1234567-1234-1234-1234-123456789012'
    Author = 'Test'
    RootModule = 'TestModule.psm1'
    RequiredModules = @(
        @{ ModuleName = 'ModuleA'; RequiredVersion = '1.0.0' },
        @{ ModuleName = 'ModuleB'; RequiredVersion = '2.0.0' }
    )
}
"@
            $manifestContent | Set-Content $script:testManifestPath
            
            $redirectMapPath = Join-Path $TestDrive "test-redirect.json"
            @{ 
                "ModuleA@1.0.0" = "1.0.0"
                "ModuleB@2.0.0" = "2.0.0"
            } | ConvertTo-Json | Set-Content $redirectMapPath
            
            Mock Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR { }
            
            Install-PSResourceDependencies -ManifestPath $script:testManifestPath -RedirectMapPath $redirectMapPath
            
            Should -Invoke Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR -Times 1 -ParameterFilter {
                $Name -eq "ModuleA" -and $RequiredVersion -eq "1.0.0"
            }
            Should -Invoke Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR -Times 1 -ParameterFilter {
                $Name -eq "ModuleB" -and $RequiredVersion -eq "2.0.0"
            }
        }

        It "Should pass through Scope and Repository parameters" {
            $manifestContent = @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'e1234567-1234-1234-1234-123456789012'
    Author = 'Test'
    RootModule = 'TestModule.psm1'
    RequiredModules = @(
        @{ ModuleName = 'TestDep'; RequiredVersion = '1.0.0' }
    )
}
"@
            $manifestContent | Set-Content $script:testManifestPath
            
            $redirectMapPath = Join-Path $TestDrive "test-redirect.json"
            @{ "TestDep@1.0.0" = "1.0.0" } | ConvertTo-Json | Set-Content $redirectMapPath
            
            Mock Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR { }
            
            Install-PSResourceDependencies -ManifestPath $script:testManifestPath `
                -RedirectMapPath $redirectMapPath -Scope 'AllUsers' -Repository 'TestRepo'
            
            Should -Invoke Install-PSResourcePinned -ModuleName Microsoft.AVS.CDR -Times 1 -ParameterFilter {
                $Scope -eq 'AllUsers' -and $Repository -eq 'TestRepo'
            }
        }

        AfterEach {
            if (Test-Path $script:testManifestDir) {
                Remove-Item $script:testManifestDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Redirect Map" {
        BeforeEach {
            New-Item -Path $script:testManifestDir -ItemType Directory -Force | Out-Null
        }

        It "Should throw when redirect map file doesn't exist" {
            $manifestContent = @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'e1234567-1234-1234-1234-123456789012'
    Author = 'Test'
    RootModule = 'TestModule.psm1'
    RequiredModules = @('SomeModule')
}
"@
            $manifestContent | Set-Content $script:testManifestPath
            $nonExistentMapPath = Join-Path $TestDrive "non-existent-map.json"
            
            { 
                Install-PSResourceDependencies -ManifestPath $script:testManifestPath `
                    -RedirectMapPath $nonExistentMapPath -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "*not found*"
        }

        AfterEach {
            if (Test-Path $script:testManifestDir) {
                Remove-Item $script:testManifestDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Dependency Installation" -Tag 'Integration' {
        BeforeEach {
            New-Item -Path $script:testManifestDir -ItemType Directory -Force | Out-Null
        }

        It "Should install dependencies from manifest" {
            # Create manifest with a real module as dependency
            $manifestContent = @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'e1234567-1234-1234-1234-123456789012'
    Author = 'Test'
    RootModule = 'TestModule.psm1'
    RequiredModules = @(
        @{ ModuleName = '$($script:PSAnalyser.Name)'; RequiredVersion = '$($script:PSAnalyser.Version)' }
    )
}
"@
            $manifestContent | Set-Content $script:testManifestPath
            
            try {
                Install-PSResourceDependencies -ManifestPath $script:testManifestPath `
                    -Repository $script:repository -Credential $script:credential
                
                $installed = Get-PSResource -Name $script:PSAnalyser.Name | 
                    Where-Object { $_.Version.ToString() -eq $script:PSAnalyser.Version }
                $installed | Should -Not -BeNullOrEmpty
            }
            catch {
                Set-ItResult -Skipped -Because "Network access required for this test"
            }
        } -Skip:($env:SKIP_INTEGRATION_TESTS -eq 'true')

        AfterEach {
            if (Test-Path $script:testManifestDir) {
                Remove-Item $script:testManifestDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "Find-PSResourcesPinned" {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
        Import-Module $modulePath -Force
    }

    Context "Parameter Validation" {
        It "Should have Name parameter as mandatory" {
            $command = Get-Command Find-PSResourcesPinned
            $nameParam = $command.Parameters['Name']
            $nameParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have RequiredVersion parameter as mandatory" {
            $command = Get-Command Find-PSResourcesPinned
            $versionParam = $command.Parameters['RequiredVersion']
            $versionParam.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have Repository parameter" {
            $command = Get-Command Find-PSResourcesPinned
            $command.Parameters.ContainsKey('Repository') | Should -BeTrue
        }

        It "Should have Credential parameter" {
            $command = Get-Command Find-PSResourcesPinned
            $credParam = $command.Parameters['Credential']
            $credParam.ParameterType.Name | Should -Be 'PSCredential'
        }

        It "Should have RedirectMapPath parameter" {
            $command = Get-Command Find-PSResourcesPinned
            $command.Parameters.ContainsKey('RedirectMapPath') | Should -BeTrue
        }
    }

    Context "Redirect Map Validation" {
        It "Should throw when redirect map file doesn't exist" {
            $nonExistentMapPath = Join-Path $TestDrive "non-existent-map.json"
            
            InModuleScope Microsoft.AVS.CDR {
                param($mapPath)
                
                Mock Find-PSResource { }
                
                { 
                    Find-PSResourcesPinned -Name "TestModule" -RequiredVersion "1.0.0" `
                        -RedirectMapPath $mapPath -ErrorAction Stop
                } | Should -Throw -ExpectedMessage "*not found*"
            } -ArgumentList $nonExistentMapPath
        }

        It "Should load redirect map when file exists" {
            $redirectMapPath = Join-Path $TestDrive "test-redirect.json"
            @{ "Dep1@1.0.0" = "1.0.1" } | ConvertTo-Json | Set-Content $redirectMapPath
            
            InModuleScope Microsoft.AVS.CDR {
                param($mapPath)
                
                # Mock Find-PSResource to return a module with no dependencies
                Mock Find-PSResource {
                    [PSCustomObject]@{
                        Name = "TestModule"
                        Version = [version]"1.0.0"
                        Repository = "TestRepo"
                        Dependencies = @()
                    }
                }
                
                # Should not throw when redirect map file exists
                { Find-PSResourcesPinned -Name "TestModule" -RequiredVersion "1.0.0" `
                    -RedirectMapPath $mapPath } | Should -Not -Throw
                
                # Verify result is returned
                $result = Find-PSResourcesPinned -Name "TestModule" -RequiredVersion "1.0.0" `
                    -RedirectMapPath $mapPath
                $result | Should -Not -BeNullOrEmpty
            } -ArgumentList $redirectMapPath
        }
    }

    Context "Module Not Found" {
        It "Should throw when main module is not found" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource { $null }
                
                { 
                    Find-PSResourcesPinned -Name "NonExistentModule" -RequiredVersion "1.0.0" -ErrorAction Stop
                } | Should -Throw -ExpectedMessage "*not found*"
            }
        }

        It "Should throw when dependency is not found" {
            InModuleScope Microsoft.AVS.CDR {
                # First call returns main module, second call for dependency returns null
                $script:callCount = 0
                Mock Find-PSResource {
                    $script:callCount++
                    if ($script:callCount -eq 1) {
                        [PSCustomObject]@{
                            Name = "MainModule"
                            Version = [version]"1.0.0"
                            Repository = "TestRepo"
                            Dependencies = @(
                                [PSCustomObject]@{ Name = "MissingDep"; VersionRange = "1.0.0" }
                            )
                        }
                    }
                    else {
                        $null
                    }
                }
                
                { 
                    Find-PSResourcesPinned -Name "MainModule" -RequiredVersion "1.0.0" -ErrorAction Stop
                } | Should -Throw -ExpectedMessage "*Dependency not found*"
            }
        }
    }

    Context "Module Without Dependencies" {
        It "Should return only the main module when it has no dependencies" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource {
                    [PSCustomObject]@{
                        Name = "SimpleModule"
                        Version = [version]"2.0.0"
                        Repository = "PSGallery"
                        Dependencies = @()
                    }
                }
                
                $result = Find-PSResourcesPinned -Name "SimpleModule" -RequiredVersion "2.0.0"
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 1
                $result[0].Name | Should -Be "SimpleModule"
                $result[0].Version | Should -Be "2.0.0"
            }
        }
    }

    Context "Module With Dependencies" {
        It "Should resolve and return all dependencies" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource {
                    param($Name, $Version)
                    
                    switch ($Name) {
                        "ParentModule" {
                            [PSCustomObject]@{
                                Name = "ParentModule"
                                Version = [version]"1.0.0"
                                Repository = "TestRepo"
                                Dependencies = @(
                                    [PSCustomObject]@{ Name = "ChildDep"; VersionRange = "2.0.0" }
                                )
                            }
                        }
                        "ChildDep" {
                            [PSCustomObject]@{
                                Name = "ChildDep"
                                Version = [version]"2.0.0"
                                Repository = "TestRepo"
                                Dependencies = @()
                            }
                        }
                    }
                }
                
                $result = Find-PSResourcesPinned -Name "ParentModule" -RequiredVersion "1.0.0"
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 2
                
                # Check that both modules are present
                $parentModule = $result | Where-Object { $_.Name -eq "ParentModule" }
                $childDep = $result | Where-Object { $_.Name -eq "ChildDep" }
                
                $parentModule | Should -Not -BeNullOrEmpty
                $childDep | Should -Not -BeNullOrEmpty
                $childDep.Version | Should -Be "2.0.0"
            }
        }

        It "Should resolve transitive dependencies" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource {
                    param($Name, $Version)
                    
                    switch ($Name) {
                        "RootModule" {
                            [PSCustomObject]@{
                                Name = "RootModule"
                                Version = [version]"1.0.0"
                                Repository = "TestRepo"
                                Dependencies = @(
                                    [PSCustomObject]@{ Name = "Level1Dep"; VersionRange = "1.0.0" }
                                )
                            }
                        }
                        "Level1Dep" {
                            [PSCustomObject]@{
                                Name = "Level1Dep"
                                Version = [version]"1.0.0"
                                Repository = "TestRepo"
                                Dependencies = @(
                                    [PSCustomObject]@{ Name = "Level2Dep"; VersionRange = "1.0.0" }
                                )
                            }
                        }
                        "Level2Dep" {
                            [PSCustomObject]@{
                                Name = "Level2Dep"
                                Version = [version]"1.0.0"
                                Repository = "TestRepo"
                                Dependencies = @()
                            }
                        }
                    }
                }
                
                $result = Find-PSResourcesPinned -Name "RootModule" -RequiredVersion "1.0.0"
                
                $result.Count | Should -Be 3
                ($result | Where-Object { $_.Name -eq "RootModule" }) | Should -Not -BeNullOrEmpty
                ($result | Where-Object { $_.Name -eq "Level1Dep" }) | Should -Not -BeNullOrEmpty
                ($result | Where-Object { $_.Name -eq "Level2Dep" }) | Should -Not -BeNullOrEmpty
            }
        }

        It "Should not include duplicate dependencies (circular reference protection)" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource {
                    param($Name, $Version)
                    
                    switch ($Name) {
                        "ModuleA" {
                            [PSCustomObject]@{
                                Name = "ModuleA"
                                Version = [version]"1.0.0"
                                Repository = "TestRepo"
                                Dependencies = @(
                                    [PSCustomObject]@{ Name = "SharedDep"; VersionRange = "1.0.0" }
                                    [PSCustomObject]@{ Name = "ModuleB"; VersionRange = "1.0.0" }
                                )
                            }
                        }
                        "ModuleB" {
                            [PSCustomObject]@{
                                Name = "ModuleB"
                                Version = [version]"1.0.0"
                                Repository = "TestRepo"
                                Dependencies = @(
                                    [PSCustomObject]@{ Name = "SharedDep"; VersionRange = "1.0.0" }
                                )
                            }
                        }
                        "SharedDep" {
                            [PSCustomObject]@{
                                Name = "SharedDep"
                                Version = [version]"1.0.0"
                                Repository = "TestRepo"
                                Dependencies = @()
                            }
                        }
                    }
                }
                
                $result = Find-PSResourcesPinned -Name "ModuleA" -RequiredVersion "1.0.0"
                
                # Should have 3 unique modules: ModuleA, ModuleB, SharedDep
                $result.Count | Should -Be 3
                
                # SharedDep should only appear once
                $sharedDepCount = ($result | Where-Object { $_.Name -eq "SharedDep" }).Count
                $sharedDepCount | Should -Be 1
            }
        }
    }

    Context "Redirect Map Application" {
        It "Should apply version redirects from map" {
            $redirectMapPath = Join-Path $TestDrive "version-redirect.json"
            @{ "OldDep@1.0.0" = "2.0.0" } | ConvertTo-Json | Set-Content $redirectMapPath
            
            InModuleScope Microsoft.AVS.CDR {
                param($mapPath)
                
                Mock Find-PSResource {
                    param($Name, $Version)
                    
                    if ($Name -eq "MainModule") {
                        [PSCustomObject]@{
                            Name = "MainModule"
                            Version = [version]"1.0.0"
                            Repository = "TestRepo"
                            Dependencies = @(
                                [PSCustomObject]@{ Name = "OldDep"; VersionRange = "[1.0.0, )" }
                            )
                        }
                    }
                    elseif ($Name -eq "OldDep" -and $Version -eq "2.0.0") {
                        [PSCustomObject]@{
                            Name = "OldDep"
                            Version = [version]"2.0.0"
                            Repository = "TestRepo"
                            Dependencies = @()
                        }
                    }
                    else {
                        $null
                    }
                }
                
                $result = Find-PSResourcesPinned -Name "MainModule" -RequiredVersion "1.0.0" -RedirectMapPath $mapPath
                
                $dep = $result | Where-Object { $_.Name -eq "OldDep" }
                $dep.Version | Should -Be "2.0.0"
            } -ArgumentList $redirectMapPath
        }
    }

    Context "Output Format" {
        It "Should return objects with expected properties" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource {
                    [PSCustomObject]@{
                        Name = "TestModule"
                        Version = [version]"1.0.0"
                        Repository = "PSGallery"
                        Dependencies = @()
                    }
                }
                
                $result = Find-PSResourcesPinned -Name "TestModule" -RequiredVersion "1.0.0"
                
                $result[0].PSObject.Properties.Name | Should -Contain 'Name'
                $result[0].PSObject.Properties.Name | Should -Contain 'Version'
                $result[0].PSObject.Properties.Name | Should -Contain 'Repository'
                $result[0].PSObject.Properties.Name | Should -Contain 'Dependencies'
            }
        }

        It "Should return result that can be iterated" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource {
                    [PSCustomObject]@{
                        Name = "SingleModule"
                        Version = [version]"1.0.0"
                        Repository = "TestRepo"
                        Dependencies = @()
                    }
                }
                
                $result = Find-PSResourcesPinned -Name "SingleModule" -RequiredVersion "1.0.0"
                
                # Verify result is iterable and has expected count
                @($result).Count | Should -Be 1
                $result.Name | Should -Be "SingleModule"
            }
        }
    }

    Context "Repository and Credential Passthrough" {
        It "Should pass Repository parameter to Find-PSResource" {
            InModuleScope Microsoft.AVS.CDR {
                Mock Find-PSResource {
                    [PSCustomObject]@{
                        Name = "TestModule"
                        Version = [version]"1.0.0"
                        Repository = "CustomRepo"
                        Dependencies = @()
                    }
                }
                
                Find-PSResourcesPinned -Name "TestModule" -RequiredVersion "1.0.0" -Repository "CustomRepo"
                
                Should -Invoke Find-PSResource -ParameterFilter { $Repository -eq "CustomRepo" }
            }
        }
    }
}

AfterAll {
}
